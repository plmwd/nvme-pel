use std::time::Duration;

use nom::{
    bits,
    bytes::complete::take,
    number::complete::{le_u128, le_u16, le_u32, le_u64, le_u8},
    sequence::{preceded, terminated, tuple},
    IResult,
};

pub struct LogHeader {
    pub log_id: u8,
    pub num_events: u32,
    pub log_len: u64,
    pub log_rev: u8,
    pub header_len: u16,
    pub timestamp: Timestamp,
    pub power_on_hours: u128,
    pub power_cycle_count: u64,
    pub vid: u16,
    pub ssvid: u16,
    pub serial_num: String,
    pub model_num: String,
    pub name: String,
    pub supp_events: SuppEventsBitmap,
}

// TODO: use a set or something
pub struct SuppEventsBitmap([u8; 32]);

impl SuppEventsBitmap {
    pub fn is_supported(&self, event_type: EventType) -> bool {
        let event_type: u8 = event_type as u8;
        self.0[(event_type / 32) as usize] & (0x1 << (event_type % 32)) > 0
    }
}

pub struct EventHeader {
    pub event_type: Result<EventType, u8>,
    pub event_rev: u8,
    pub header_len: u8,
    pub ctrl_id: u16,
    pub timestamp: Timestamp,
    pub vendor_info_len: u16,
    pub event_len: u16,
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

fn parse_log_header(input: &[u8]) -> IResult<&[u8], LogHeader> {
    // 00 - log id
    // 03:01 - reserved
    let (input, log_id) = terminated(le_u8, take(3usize))(input)?;
    // 07:04 - total number of events (TNEV)
    let (input, num_events) = le_u32(input)?;
    // 15:08 - total log length (TTL)
    let (input, log_len) = le_u64(input)?;
    // 16 - log revision
    // 17 - reserved
    let (input, log_rev) = terminated(le_u8, take(1usize))(input)?;
    // 19:18: log header length
    let (input, header_len) = le_u16(input)?;
    // 27:20 - timestamp
    let (input, timestamp) = parse_timestamp(input)?;
    // 43:28 - power on hours (POH)
    let (input, power_on_hours) = le_u128(input)?;
    // 51:44 - power cycle count
    let (input, power_cycle_count) = le_u64(input)?;
    // 53:52 - serial number (SN)
    let (input, vid) = le_u16(input)?;
    // 55:54 - model number (MN)
    let (input, ssvid) = le_u16(input)?;
    // 75:56 - pci vendor id (VID)
    let (input, serial_num) = take(20usize)(input)?;
    // 115:76 - pci subsystem vendor id (SSVID)
    let (input, model_num) = take(40usize)(input)?;
    // 371:116 - nvm subsystem nvme qualified name (SUBNQN)
    // 479:372 - reserved
    let (input, name) = terminated(take(256usize), take(108usize))(input)?;
    // 511:480 - supported events bitmap
    let (input, supp_events) = take(32usize)(input)?;

    let clean_str = |s: &[u8]| String::from_utf8_lossy(s).trim().replace('\0', "");
    IResult::Ok((
        input,
        LogHeader {
            log_id,
            num_events,
            log_len,
            log_rev,
            header_len,
            timestamp,
            power_on_hours,
            power_cycle_count,
            vid,
            ssvid,
            serial_num: clean_str(serial_num),
            model_num: clean_str(model_num),
            name: clean_str(name),
            supp_events: SuppEventsBitmap(supp_events.try_into().unwrap()),
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

    #[test]
    fn test_log_header() {
        todo!()
    }
}
