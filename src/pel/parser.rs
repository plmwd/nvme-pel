use nom::{
    bits,
    bytes::complete::take,
    combinator::{map, peek},
    number::complete::{le_u128, le_u16, le_u32, le_u64, le_u8},
    sequence::{preceded, terminated, tuple},
    IResult,
};

use super::{parse_timestamp, Event, EventType, Pel, SuppEventsBitmap, Timestamp};

pub fn parse_log_header(input: &[u8]) -> IResult<&[u8], Pel> {
    // 00 - log id (always going to be 0Dh)
    // 03:01 - reserved
    let (input, _) = take(4usize)(input)?;
    // 07:04 - total number of events (TNEV)
    let (input, num_events) = le_u32(input)?;
    // 15:08 - total log length (TTL)
    let (input, len) = le_u64(input)?;
    // 16 - log revision
    let (input, revision) = terminated(le_u8, take(1usize))(input)?;
    // 17 - reserved
    let _ = take(1usize)(input)?;
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
        Pel {
            num_events,
            len,
            revision,
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
            ..Default::default()
        },
    ))
}

pub fn parse_event(input: &[u8], headers_only: bool) -> IResult<&[u8], Event> {
    // 00 - event type
    let (input, event_type) = le_u8(input)?;
    // 01 - event type revision
    let (input, revision) = le_u8(input)?;
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

    let (input, vendor_info) = parse_vendor_info(input, event_type, revision, vendor_info_len)?;

    let length = event_len - header_len as u16;

    let (input, event) = match event_type {
        SMART_HEALTH => parse_smart_event(input, revision, length)?,
        FW_COMMIT => parse_fw_commit_event(input, revision, length)?,
        TIMESTAMP_CHANGE => parse_timestamp_change_event(input, revision, length)?,
        POR => parse_por_event(input, revision, length)?,
        NVM_HW_ERROR => parse_nvm_hw_error_event(input, revision, length)?,
        CHANGE_NAMESPACE => parse_change_namespace_event(input, revision, length)?,
        FORMAT_NVM_START => parse_format_nvm_start_event(input, revision, length)?,
        FORMAT_NVM_COMPLETE => parse_format_nvm_complete_event(input, revision, length)?,
        SANITIZE_START => parse_sanitize_start_event(input, revision, length)?,
        SANITIZE_COMPLETE => parse_sanitize_complete_event(input, revision, length)?,
        SET_FEATURE => parse_set_feature_event(input, revision, length)?,
        TELEMENTRY_LOG_CREATED => parse_telementry_log_created_event(input, revision, length)?,
        THERMAL_EXCURSION => parse_thermal_excursion_event(input, revision, length)?,
        VENDOR_SPECIFC => parse_vendor_specific_event(input, revision, length)?,
        TCG_DEFINED => parse_tcg_event(input, revision, length)?,
        _ => parse_unknown_event(input, revision, length)?,
    };

    IResult::Ok((input, event))
}

fn parse_vendor_info(
    input: &[u8],
    event_type: u8,
    revision: u8,
    length: u16,
) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_unknown_event(input: &[u8], revision: u8, length: u16) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_tcg_event(input: &[u8], revision: u8, length: u16) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_vendor_specific_event(input: &[u8], revision: u8, length: u16) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_thermal_excursion_event(input: &[u8], revision: u8, length: u16) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_telementry_log_created_event(
    input: &[u8],
    revision: u8,
    length: u16,
) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_set_feature_event(input: &[u8], revision: u8, length: u16) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_sanitize_complete_event(input: &[u8], revision: u8, length: u16) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_sanitize_start_event(input: &[u8], revision: u8, length: u16) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_format_nvm_complete_event(
    input: &[u8],
    revision: u8,
    length: u16,
) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_format_nvm_start_event(input: &[u8], revision: u8, length: u16) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_change_namespace_event(input: &[u8], revision: u8, length: u16) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_nvm_hw_error_event(input: &[u8], revision: u8, length: u16) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_por_event(input: &[u8], revision: u8, length: u16) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_timestamp_change_event(input: &[u8], revision: u8, length: u16) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_fw_commit_event(input: &[u8], revision: u8, length: u16) -> IResult<&[u8], Event> {
    todo!()
}

fn parse_smart_event(input: &[u8], revision: u8, length: u16) -> IResult<&[u8], Event> {
    todo!()
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
