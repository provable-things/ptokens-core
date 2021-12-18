use std::{
    convert::TryFrom,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::{prelude::DateTime, Utc};
use serde_json::Value as JsonValue;
use tiny_keccak::{Hasher, Keccak};

use crate::{
    constants::{CORE_VERSION, DB_KEY_PREFIX, DEBUG_OUTPUT_MARKER, U64_NUM_BYTES},
    types::{Byte, Bytes, Result},
};

pub fn add_key_and_value_to_json(key: &str, value: JsonValue, json: JsonValue) -> Result<JsonValue> {
    match json {
        JsonValue::Object(mut map) => {
            map.insert(key.to_string(), value);
            Ok(JsonValue::Object(map))
        },
        _ => Err("Error adding field to json!".into()),
    }
}

pub fn get_unix_timestamp() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub fn get_unix_timestamp_as_u32() -> Result<u32> {
    Ok(u32::try_from(get_unix_timestamp()?)?)
}

pub fn convert_unix_timestamp_to_human_readable(timestamp: u64) -> String {
    DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(timestamp))
        .format("%d/%m/%Y,%H:%M:%S")
        .to_string()
}

pub fn right_pad_or_truncate(s: &str, width: usize) -> String {
    if s.len() >= width {
        truncate_str(s, width).to_string()
    } else {
        right_pad_with_zeroes(s, width)
    }
}

pub fn truncate_str(s: &str, num_chars: usize) -> &str {
    match s.char_indices().nth(num_chars) {
        None => s,
        Some((i, _)) => &s[..i],
    }
}

pub fn get_prefixed_db_key(suffix: &str) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    let mut hashed = [0u8; 32];
    keccak.update(format!("{}{}", DB_KEY_PREFIX.to_string(), suffix).as_bytes());
    keccak.finalize(&mut hashed);
    hashed
}

pub fn convert_bytes_to_u64(bytes: &[Byte]) -> Result<u64> {
    match bytes.len() {
        0..=7 => Err("✘ Not enough bytes to convert to u64!".into()),
        U64_NUM_BYTES => {
            let mut arr = [0u8; U64_NUM_BYTES];
            let bytes = &bytes[..U64_NUM_BYTES];
            arr.copy_from_slice(bytes);
            Ok(u64::from_le_bytes(arr))
        },
        _ => Err("✘ Too many bytes to convert to u64 without overflowing!".into()),
    }
}

pub fn convert_bytes_to_u8(bytes: &[Byte]) -> Result<u8> {
    match bytes.len() {
        0 => Err("✘ Not enough bytes to convert to u8!".into()),
        1 => {
            let mut arr = [0u8; 1];
            let bytes = &bytes[..1];
            arr.copy_from_slice(bytes);
            Ok(u8::from_le_bytes(arr))
        },
        _ => Err("✘ Too many bytes to convert to u8 without overflowing!".into()),
    }
}

pub fn right_pad_with_zeroes(s: &str, width: usize) -> String {
    format!("{:0<width$}", s, width = width)
}

pub fn left_pad_with_zeroes(s: &str, width: usize) -> String {
    format!("{:0>width$}", s, width = width)
}

fn left_pad_with_zero(string: &str) -> String {
    format!("0{}", string)
}

pub fn strip_hex_prefix(hex: &str) -> String {
    const LOWERCASE_HEX_PREFIX: &str = "0x";
    const UPPERCASE_HEX_PREFIX: &str = "0X";
    let hex_no_prefix = if hex.starts_with(LOWERCASE_HEX_PREFIX) || hex.starts_with(UPPERCASE_HEX_PREFIX) {
        hex.trim_start_matches(LOWERCASE_HEX_PREFIX)
            .trim_start_matches(UPPERCASE_HEX_PREFIX)
    } else {
        hex
    };
    match hex_no_prefix.len() % 2 {
        0 => hex_no_prefix.to_string(),
        _ => left_pad_with_zero(hex_no_prefix),
    }
}

pub fn decode_hex_with_err_msg(hex: &str, err_msg: &str) -> Result<Bytes> {
    match hex::decode(strip_hex_prefix(hex)) {
        Ok(bytes) => Ok(bytes),
        Err(err) => Err(format!("{} {}", err_msg, err).into()),
    }
}

pub fn decode_hex_with_no_padding_with_err_msg(hex: &str, err_msg: &str) -> Result<Bytes> {
    match hex::decode(strip_hex_prefix(hex)) {
        Ok(bytes) => Ok(bytes),
        Err(err) => Err(format!("{} {}", err_msg, err).into()),
    }
}

pub fn convert_u64_to_bytes(u_64: u64) -> Bytes {
    u_64.to_le_bytes().to_vec()
}

pub fn prepend_debug_output_marker_to_string(string_to_prepend: String) -> String {
    format!("{}_{}", DEBUG_OUTPUT_MARKER, &string_to_prepend)
}

pub fn get_not_in_state_err(substring: &str) -> String {
    format!("✘ No {} in state!", substring)
}

pub fn get_no_overwrite_state_err(substring: &str) -> String {
    format!("✘ Cannot overwrite {} in state!", substring)
}

pub fn get_core_version() -> String {
    CORE_VERSION.unwrap_or("Unknown").to_string()
}

pub fn is_hex(string: &str) -> bool {
    hex::decode(strip_hex_prefix(string)).is_ok()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::errors::AppError;

    #[test]
    fn should_maybe_initialize_simple_logger() {
        if option_env!("ENABLE_LOGGING").is_some() {
            simple_logger::SimpleLogger::new().init().unwrap();
        };
        debug!("Test logging enabled!");
    }

    #[test]
    fn should_convert_u64_to_bytes() {
        let u_64 = u64::max_value();
        let expected_result = [255, 255, 255, 255, 255, 255, 255, 255];
        let result = convert_u64_to_bytes(u_64);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_bytes_to_u64() {
        let bytes = vec![255, 255, 255, 255, 255, 255, 255, 255];
        let expected_result = u64::max_value();
        let result = convert_bytes_to_u64(&bytes).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_not_strip_missing_hex_prefix_correctly() {
        let dummy_hex = "c0ffee";
        let expected_result = "c0ffee".to_string();
        let result = strip_hex_prefix(dummy_hex);
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_left_pad_string_with_zero_correctly() {
        let dummy_hex = "0xc0ffee";
        let expected_result = "00xc0ffee".to_string();
        let result = left_pad_with_zero(dummy_hex);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_strip_lower_hex_prefix_correctly() {
        let dummy_hex = "0xc0ffee";
        let expected_result = "c0ffee".to_string();
        let result = strip_hex_prefix(dummy_hex);
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_strip_upper_case_hex_prefix_correctly() {
        let dummy_hex = "0Xc0ffee";
        let expected_result = "c0ffee".to_string();
        let result = strip_hex_prefix(dummy_hex);
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_decode_hex_with_err_msg() {
        let hex = "0xcoffee";
        let err_msg = "Could not decode test hex:";
        let expected_error = format!("{} Invalid character \'o\' at position 1", err_msg);
        match decode_hex_with_err_msg(hex, err_msg) {
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            Err(e) => panic!("Wrong error recieved: {}", e),
            Ok(_) => panic!("Should not have succeeded!"),
        }
    }

    #[test]
    fn should_prepend_debug_marker_to_string() {
        let string = "some string".to_string();
        let expected_result = format!("{}_{}", DEBUG_OUTPUT_MARKER, &string);
        let result = prepend_debug_output_marker_to_string(string);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_no_state_err_string() {
        let thing = "thing".to_string();
        let expected_result = "✘ No thing in state!";
        let result = get_not_in_state_err(&thing);
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_get_no_overwrite_err_string() {
        let thing = "thing".to_string();
        let expected_result = "✘ Cannot overwrite thing in state!";
        let result = get_no_overwrite_state_err(&thing);
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_truncate_str() {
        let s = "some string";
        let len = 3;
        let result = truncate_str(s, len);
        assert_eq!(result, "som");
    }

    #[test]
    fn should_not_truncate_str_if_i_gt_len() {
        let s = "some string";
        let len = s.len() + 1;
        let result = truncate_str(s, len);
        assert_eq!(result, s);
    }

    #[test]
    fn should_truncate_str_correctly_if_i_0() {
        let s = "some string";
        let len = 0;
        let result = truncate_str(s, len);
        assert_eq!(result, "");
    }

    #[test]
    fn should_right_pad_with_zeroes() {
        let s = "some string";
        let width = s.len() + 3;
        let result = right_pad_with_zeroes(s, width);
        assert_eq!(result, "some string000")
    }

    #[test]
    fn should_left_pad_with_zeroes() {
        let s = "some string";
        let width = s.len() + 3;
        let result = left_pad_with_zeroes(s, width);
        assert_eq!(result, "000some string")
    }

    #[test]
    fn right_pad_or_truncate_should_truncate_correctly() {
        let s = "some string";
        let width = s.len() - 3;
        let result = right_pad_or_truncate(s, width);
        assert_eq!(result, "some str");
    }

    #[test]
    fn right_pad_or_truncate_should_pad_correctly() {
        let s = "some string";
        let width = s.len() + 3;
        let result = right_pad_or_truncate(s, width);
        assert_eq!(result, "some string000");
    }

    #[test]
    fn should_get_unix_timestamp() {
        let result = get_unix_timestamp();
        assert!(result.is_ok());
    }

    #[test]
    fn should_get_unix_timestamp_as_u32() {
        let result = get_unix_timestamp_as_u32();
        assert!(result.is_ok());
    }

    #[test]
    fn should_check_if_string_is_hex() {
        let hex = "0x5A0b54D5dc17e0AadC383d2db43B0a0D3E029c4c";
        let hex_no_prefix = "4d261b7d3101e9ff7e37f63449be8a9a1affef87e4952900dbb84ee3c29f45f3";
        let string_no_hex = "Arbitrary string";
        let string_containing_hex = "the address is 0x82a59eA2B64B2A6FF0B8A778D0B3f3A1945d36Dd";
        assert_eq!(is_hex(hex), true);
        assert_eq!(is_hex(hex_no_prefix), true);
        assert_eq!(is_hex(string_no_hex), false);
        assert_eq!(is_hex(string_containing_hex), false);
    }

    #[test]
    fn should_convert_unix_timestamp_to_human_readable() {
        let timestamp = 1618406537;
        let result = convert_unix_timestamp_to_human_readable(timestamp);
        let expected_result = "14/04/2021,13:22:17";
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_add_key_and_value_to_json() {
        let key = "c";
        let value = json!("d");
        let json = json!({"a":"b"});
        let expected_result = json!({
            "a": "b",
            "c": "d",
        });
        let result = add_key_and_value_to_json(key, value, json).unwrap();
        assert_eq!(result, expected_result);
    }
}
