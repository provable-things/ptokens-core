use tiny_keccak::keccak256;
use crate::{
    constants::DEBUG_OUTPUT_MARKER,
    types::{Byte, Bytes, Result},
    constants::{
        U64_NUM_BYTES,
        DB_KEY_PREFIX,
    },
};

pub fn get_prefixed_db_key(suffix: &str) -> [u8; 32] {
    keccak256(format!("{}{}", DB_KEY_PREFIX.to_string(), suffix).as_bytes())
}

pub fn convert_bytes_to_u64(bytes: &[Byte]) -> Result<u64> {
    match bytes.len() {
        0..=7 => Err("✘ Not enough bytes to convert to u64!".into()),
        U64_NUM_BYTES => {
            let mut arr = [0u8; U64_NUM_BYTES];
            let bytes = &bytes[..U64_NUM_BYTES];
            arr.copy_from_slice(bytes);
            Ok(u64::from_le_bytes(arr))
        }
        _ => Err("✘ Too many bytes to convert to u64 without overflowing!".into()),
    }
}

fn left_pad_with_zero(string: &str) -> Result<String> {
    Ok(format!("0{}", string))
}

fn maybe_strip_hex_prefix(hex: &str) -> Result<&str> {
    let lowercase_hex_prefix = "0x";
    let uppercase_hex_prefix = "0X";
    match hex.starts_with(lowercase_hex_prefix) || hex.starts_with(uppercase_hex_prefix) {
        true => Ok(hex.trim_start_matches(lowercase_hex_prefix).trim_start_matches(uppercase_hex_prefix)),
        false => Ok(hex),
    }
}

pub fn strip_hex_prefix(hex : &str) -> Result<String> {
    maybe_strip_hex_prefix(hex)
        .and_then(|hex_no_prefix| match hex_no_prefix.len() % 2 {
            0 => Ok(hex_no_prefix.to_string()),
            _ => left_pad_with_zero(&hex_no_prefix),
        })
}

pub fn decode_hex_with_err_msg(hex: &str, err_msg: &str) -> Result<Bytes> {
    match hex::decode(strip_hex_prefix(hex)?) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::AppError;

    #[test]
    fn should_maybe_initialize_simple_logger() {
        if option_env!("ENABLE_LOGGING").is_some() { simple_logger::init().unwrap() };
        debug!("Test logging enabled!");
    }

    #[test]
    fn should_convert_u64_to_bytes() {
        let u_64 = u64::max_value();
        let expected_result = [255,255,255,255,255,255,255,255];
        let result = convert_u64_to_bytes(u_64);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_bytes_to_u64() {
        let bytes = vec![255,255,255,255,255,255,255,255];
        let expected_result = u64::max_value();
        let result = convert_bytes_to_u64(&bytes)
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_not_strip_missing_hex_prefix_correctly() {
        let dummy_hex = "c0ffee";
        let expected_result = "c0ffee".to_string();
        let result = strip_hex_prefix(dummy_hex)
            .unwrap();
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_left_pad_string_with_zero_correctly() {
        let dummy_hex = "0xc0ffee";
        let expected_result = "00xc0ffee".to_string();
        let result = left_pad_with_zero(dummy_hex)
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_strip_lower_hex_prefix_correctly() {
        let dummy_hex = "0xc0ffee";
        let expected_result = "c0ffee".to_string();
        let result = strip_hex_prefix(dummy_hex)
            .unwrap();
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_strip_upper_case_hex_prefix_correctly() {
        let dummy_hex = "0Xc0ffee";
        let expected_result = "c0ffee".to_string();
        let result = strip_hex_prefix(dummy_hex)
            .unwrap();
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
}
