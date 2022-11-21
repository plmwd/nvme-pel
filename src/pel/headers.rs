use nom::{
    bits,
    bytes::complete::take,
    combinator::{map, peek},
    number::complete::{le_u128, le_u16, le_u32, le_u64, le_u8},
    sequence::{preceded, terminated, tuple},
    IResult,
};

use super::{parse_timestamp, EventType, SuppEventsBitmap, Timestamp};

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

pub struct EventHeader {
    pub event_type: Result<EventType, u8>,
    pub event_rev: u8,
    pub header_len: u8, // The total event header length (EHL+ 3)
    pub ctrl_id: u16,
    pub timestamp: Timestamp,
    pub vendor_info_len: u16,
    pub event_len: u16, // The total event length (EL + EHL +3)
}

pub fn parse_log_header(input: &[u8]) -> IResult<&[u8], LogHeader> {
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

pub fn parse_event_header(input: &[u8]) -> IResult<&[u8], EventHeader> {
    // 00 - event type
    let (input, event_type) = map(le_u8, EventType::try_from)(input)?;
    // 01 - event type revision
    let (input, event_rev) = le_u8(input)?;
    // 02 - event header length (EHL)
    // 03 - reserved
    let (input, header_len) = terminated(le_u8, le_u8)(input)?;
    // 05:04 - controller id
    let (input, ctrl_id) = le_u16(input)?;
    // 13:06 - event timestamp
    // 19:14 - reserved
    let (input, timestamp) = terminated(parse_timestamp, take(6usize))(input)?;
    // 21:20 - vendor specific information length (VSIL)
    let (input, vendor_info_len) = le_u16(input)?;
    // 23:22 - event length (EL)
    let (input, event_len) = le_u16(input)?;

    IResult::Ok((
        input,
        EventHeader {
            event_type,
            event_rev,
            // Figure 216: total header length is this field + 3
            header_len: header_len + 3,
            ctrl_id,
            timestamp,
            vendor_info_len,
            // Figure 216: total event length is this field + EHL + 3
            event_len: event_len + header_len as u16 + 3,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_header() {
        todo!()
    }

    #[test]
    fn test_log_event_header() {
        todo!()
    }
}
