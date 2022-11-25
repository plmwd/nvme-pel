mod events;
mod parser;

use self::parser::{parse_event_header, parse_log_header};
use nom::{
    bits,
    bytes::complete::take,
    sequence::{preceded, tuple},
    IResult,
};
use std::{default, time::Duration};

pub use self::events::*;

pub fn parse_pel(input: &[u8]) -> IResult<&[u8], Pel> {
    todo!()
}

#[derive(Debug, Default)]
pub struct Pel {
    pub num_events: u32,
    pub len: u64,
    pub revision: u8,
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
    pub events: Option<Vec<Event>>,
    // Added in 2
    pub generation: Option<u16>,
    pub reporting_context: Option<ReportingContext>,
}

#[derive(Debug)]
pub enum ReportingContext {
    DoesNotExist,
    NVMPort(u16),
    MiPort(u16),
}

#[derive(Debug)]
pub struct EventRecord<T> {
    pub revision: u8,
    pub header_len: u8, // The total event header length (EHL+ 3)
    pub ctrl_id: u16,
    pub timestamp: Timestamp,
    pub vendor_info_len: u16,
    pub len: u16, // The total event length (EL + EHL +3)
    pub info: Box<T>,
}

pub type SmartHealthEvent = EventRecord<SmartHealthInfo>;
pub type FwCommitEvent = EventRecord<FwCommitInfo>;
pub type TimestampChangeEvent = EventRecord<TimestampChangeInfo>;
pub type PorEvent = EventRecord<PorInfo>;
pub type NvmHwErrorEvent = EventRecord<NvmHwErrorInfo>;
pub type ChangeNamespaceEvent = EventRecord<ChangeNamespaceInfo>;
pub type FormatNvmStartEvent = EventRecord<FormatNvmStartInfo>;
pub type FormatNvmCompleteEvent = EventRecord<FormatNvmCompleteInfo>;
pub type SanitizeStartEvent = EventRecord<SanitizeStartInfo>;
pub type SanitizeCompleteEvent = EventRecord<SanitizeCompleteInfo>;
pub type SetFeatureEvent = EventRecord<SetFeatureInfo>;
pub type TelementryLogCreatedEvent = EventRecord<TelementryLogCreatedInfo>;
pub type ThermalExcursionEvent = EventRecord<ThermalExcursionInfo>;
pub type VendorSpecifcEvent = EventRecord<VendorSpecifcInfo>;
pub type TcgDefinedEvent = EventRecord<TcgDefinedInfo>;
pub type UnknownEvent = EventRecord<UnknownInfo>;

#[derive(Debug)]
pub enum Event {
    SmartHealth(SmartHealthEvent),
    FwCommit(FwCommitEvent),
    TimestampChange(TimestampChangeEvent),
    Por(PorEvent),
    NvmHwError(NvmHwErrorEvent),
    ChangeNamespace(ChangeNamespaceEvent),
    FormatNvmStart(FormatNvmStartEvent),
    FormatNvmComplete(FormatNvmCompleteEvent),
    SanitizeStart(SanitizeStartEvent),
    SanitizeComplete(SanitizeCompleteEvent),
    SetFeature(SetFeatureEvent),
    TelementryLogCreated(TelementryLogCreatedEvent),
    ThermalExcursion(ThermalExcursionEvent),
    VendorSpecifc(VendorSpecifcEvent),
    TcgDefined(TcgDefinedEvent),
    Unknown(UnknownEvent),
}

// TODO: use a set or something else
#[derive(Debug, Default)]
pub struct SuppEventsBitmap([u8; 32]);

pub const SMART_HEALTH: u8 = 0x01;
pub const FW_COMMIT: u8 = 0x02;
pub const TIMESTAMP_CHANGE: u8 = 0x02;
pub const POR: u8 = 0x03;
pub const NVM_HW_ERROR: u8 = 0x04;
pub const CHANGE_NAMESPACE: u8 = 0x05;
pub const FORMAT_NVM_START: u8 = 0x07;
pub const FORMAT_NVM_COMPLETE: u8 = 0x08;
pub const SANITIZE_START: u8 = 0x09;
pub const SANITIZE_COMPLETE: u8 = 0x0a;
pub const SET_FEATURE: u8 = 0x0b;
pub const TELEMENTRY_LOG_CREATED: u8 = 0x0c;
pub const THERMAL_EXCURSION: u8 = 0x0d;
pub const VENDOR_SPECIFC: u8 = 0xde;
pub const TCG_DEFINED: u8 = 0xdf;

#[derive(Debug, PartialEq, Eq, Default)]
pub struct Timestamp {
    ms: Duration,
    origin: TimestampOrigin,
    synch: TimestampSynch,
}

#[derive(Debug, PartialEq, Eq, Default)]
pub enum TimestampOrigin {
    #[default]
    Reset,
    SetFeature,
    Unknown(u8),
}

impl From<u8> for TimestampOrigin {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Reset,
            1 => Self::SetFeature,
            _ => Self::Unknown(value),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Default)]
pub enum TimestampSynch {
    #[default]
    Continuous,
    Skipped,
    Unknown(u8),
}

impl From<u8> for TimestampSynch {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Continuous,
            1 => Self::Skipped,
            _ => Self::Unknown(value),
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
            synch: TimestampSynch::from(synch as u8),
            origin: TimestampOrigin::from(origin as u8),
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
                synch: TimestampSynch::Continuous,
                origin: TimestampOrigin::Reset,
            }
        );

        let (remainder, parsed_timestamp) =
            parse_timestamp(&[0x0, 0x11, 0x22, 0x33, 0x44, 0x55, 0b00000011, 0xff]).unwrap();
        assert_eq!(remainder.len(), 0);
        assert_eq!(
            parsed_timestamp,
            Timestamp {
                ms: Duration::from_millis(0x554433221100),
                synch: TimestampSynch::Skipped,
                origin: TimestampOrigin::SetFeature,
            }
        );

        let (remainder, parsed_timestamp) =
            parse_timestamp(&[0x0, 0x11, 0x22, 0x33, 0x44, 0x55, 0b00000101, 0xff]).unwrap();
        assert_eq!(remainder.len(), 0);
        assert_eq!(
            parsed_timestamp,
            Timestamp {
                ms: Duration::from_millis(0x554433221100),
                synch: TimestampSynch::Skipped,
                origin: TimestampOrigin::Unknown(2u8),
            }
        );
    }
}


