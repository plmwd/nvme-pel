mod events;
mod headers;

use self::headers::{parse_event_header, parse_log_header};
use nom::{
    bits,
    bytes::complete::take,
    sequence::{preceded, tuple},
    IResult,
};
use std::time::Duration;

pub use self::events::*;
pub use self::headers::{EventHeader, LogHeader};

pub fn parse_pel(input: &[u8]) -> IResult<&[u8], Pel> {
    todo!()
}

pub struct Pel {
    header: LogHeader,
    events: Vec<Event>,
}

pub enum Event {
    SmartHealth(EventHeader, Box<SmartHealthInfo>),
    FwCommit(EventHeader, Box<FwCommitInfo>),
    TimestampChange(EventHeader, Box<TimestampChangeInfo>),
    Por(EventHeader, Box<PorInfo>),
    NvmHwError(EventHeader, Box<NvmHwErrorInfo>),
    ChangeNamespace(EventHeader, Box<ChangeNamespaceInfo>),
    FormatNvmStart(EventHeader, Box<FormatNvmStartInfo>),
    FormatNvmComplete(EventHeader, Box<FormatNvmCompleteInfo>),
    SanitizeStart(EventHeader, Box<SanitizeStartInfo>),
    SanitizeComplete(EventHeader, Box<SanitizeCompleteInfo>),
    SetFeature(EventHeader, Box<SetFeatureInfo>),
    TelementryLogCreated(EventHeader, Box<TelementryLogCreatedInfo>),
    ThermalExcursion(EventHeader, Box<ThermalExcursionInfo>),
    VendorSpecifc(EventHeader, Box<VendorSpecifcInfo>),
    TcgDefined(EventHeader, Box<TcgDefinedInfo>),
    Unsupported(EventHeader, Box<UnsupportedInfo>),
}

// TODO: use a set or something else
pub struct SuppEventsBitmap([u8; 32]);
impl SuppEventsBitmap {
    pub fn is_supported(&self, event_type: EventType) -> bool {
        let event_type: u8 = event_type as u8;
        self.0[(event_type / 32) as usize] & (0x1 << (event_type % 32)) > 0
    }
}

pub enum EventType {
    SmartHealth = 0x1,
    FwCommit,
    TimestampChange,
    Por,
    NvmHwError,
    ChangeNamespace,
    FormatNvmStart,
    FormatNvmComplete,
    SanitizeStart,
    SanitizeComplete,
    SetFeature,
    TelementryLogCreated,
    ThermalExcursion,
    VendorSpecifc = 0xde,
    TcgDefined = 0xdf,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Timestamp {
    ms: Duration,
    origin: Result<TimestampOrigin, u8>,
    synch: Result<TimestampSynch, u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TimestampOrigin {
    Reset,
    SetFeature,
}

impl TryFrom<usize> for TimestampOrigin {
    type Error = u8;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Reset),
            1 => Ok(Self::SetFeature),
            _ => Err(value as u8),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TimestampSynch {
    Continuous,
    Skipped,
}

impl TryFrom<usize> for TimestampSynch {
    type Error = u8;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Continuous),
            1 => Ok(Self::Skipped),
            _ => Err(value as u8),
        }
    }
}

impl TryFrom<u8> for EventType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::SmartHealth),
            0x02 => Ok(Self::FwCommit),
            0x03 => Ok(Self::TimestampChange),
            0x04 => Ok(Self::Por),
            0x05 => Ok(Self::NvmHwError),
            0x06 => Ok(Self::ChangeNamespace),
            0x07 => Ok(Self::FormatNvmStart),
            0x08 => Ok(Self::FormatNvmComplete),
            0x09 => Ok(Self::SanitizeStart),
            0x0a => Ok(Self::SanitizeComplete),
            0x0b => Ok(Self::SetFeature),
            0x0c => Ok(Self::TelementryLogCreated),
            0x0d => Ok(Self::ThermalExcursion),
            0xde => Ok(Self::VendorSpecifc),
            0xdf => Ok(Self::TcgDefined),
            _ => Err(value),
        }
    }
}

fn parse_ms(input: &[u8]) -> IResult<&[u8], u64> {
    let (input, ms) = take(6u8)(input)?;
    let ms = [ms[0], ms[1], ms[2], ms[3], ms[4], ms[5], 0, 0];
    IResult::Ok((input, u64::from_le_bytes(ms)))
}

fn parse_timestamp(input: &[u8]) -> IResult<&[u8], Timestamp> {
    // 05:00 - timestamp milliseconds
    let (input, ms) = parse_ms(input)?;
    // 06 - attributes
    let (input, (origin, synch)): (&[u8], (usize, usize)) =
        bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
            preceded::<_, usize, usize, _, _, _>(
                bits::complete::take(4usize), // bits 07:04 - reserved
                bits::complete::take(3usize), // bits 01:03 - timestamp origin
            ),
            bits::complete::take(1usize), // bit 00 - synch
        )))(input)?;
    // 07 - reserved
    let (input, _) = take(1usize)(input)?;

    IResult::Ok((
        input,
        Timestamp {
            ms: Duration::from_millis(ms),
            synch: TimestampSynch::try_from(synch),
            origin: TimestampOrigin::try_from(origin),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ms() {
        let ms_le_bytes = [0u8; 6];
        let (remainder, parsed_ms) = parse_ms(&ms_le_bytes).unwrap();
        assert_eq!(remainder, &[]);
        assert_eq!(parsed_ms, 0u64);

        let ms_le_bytes = [0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];
        let (remainder, parsed_ms) = parse_ms(&ms_le_bytes).unwrap();
        assert_eq!(remainder, &[0xf]);
        assert_eq!(parsed_ms, 0x0e0d0c0b0a00);

        let mut ms_le_bytes = [0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf];
        ms_le_bytes.reverse();
        let (remainder, parsed_ms) = parse_ms(&ms_le_bytes).unwrap();
        assert_eq!(remainder, &[0x0]);
        assert_eq!(parsed_ms, 0x000a0b0c0d0e0f);
    }

    #[test]
    fn test_parse_timestamp() {
        let (remainder, parsed_timestamp) = parse_timestamp(&[0u8; 8]).unwrap();
        assert_eq!(remainder.len(), 0);
        assert_eq!(
            parsed_timestamp,
            Timestamp {
                ms: Duration::from_millis(0),
                synch: Ok(TimestampSynch::Continuous),
                origin: Ok(TimestampOrigin::Reset),
            }
        );

        let (remainder, parsed_timestamp) =
            parse_timestamp(&[0x0, 0x11, 0x22, 0x33, 0x44, 0x55, 0b00000011, 0xff]).unwrap();
        assert_eq!(remainder.len(), 0);
        assert_eq!(
            parsed_timestamp,
            Timestamp {
                ms: Duration::from_millis(0x554433221100),
                synch: Ok(TimestampSynch::Skipped),
                origin: Ok(TimestampOrigin::SetFeature),
            }
        );

        let (remainder, parsed_timestamp) =
            parse_timestamp(&[0x0, 0x11, 0x22, 0x33, 0x44, 0x55, 0b00000101, 0xff]).unwrap();
        assert_eq!(remainder.len(), 0);
        assert_eq!(
            parsed_timestamp,
            Timestamp {
                ms: Duration::from_millis(0x554433221100),
                synch: Ok(TimestampSynch::Skipped),
                origin: Err(2u8),
            }
        );
    }
}


