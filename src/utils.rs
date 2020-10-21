use tiny_keccak::keccak256;
use crate::{
    constants::DEBUG_OUTPUT_MARKER,
    types::{Byte, Bytes, Result},
    constants::{
        U64_NUM_BYTES,
        DB_KEY_PREFIX,
    },
};

pub fn right_pad_or_truncate(s: &str, width: usize) -> String {
    if s.len() >= width { truncate_str(&s, width).to_string() } else { right_pad_with_zeroes(&s, width) }
}

pub fn truncate_str(s: &str, num_chars: usize) -> &str {
    match s.char_indices().nth(num_chars) {
        None => s,
        Some((i, _)) => &s[..i],
    }
}

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

pub fn right_pad_with_zeroes(s: &str, width: usize) -> String {
    format!("{:0<width$}", s, width = width)
}

pub fn left_pad_with_zeroes(s: &str, width: usize) -> String {
    format!("{:0>width$}", s, width = width)
}

fn left_pad_with_zero(string: &str) -> Result<String> {
    Ok(format!("0{}", string))
}

pub fn maybe_strip_hex_prefix(hex: &str) -> Result<&str> {
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

pub fn decode_hex_with_no_padding_with_err_msg(hex: &str, err_msg: &str) -> Result<Bytes> {
    match hex::decode(maybe_strip_hex_prefix(hex)?) {
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
    format!("✘ No {} in state!" , substring)
}

pub fn get_no_overwrite_state_err(substring: &str) -> String {
    format!("✘ Cannot overwrite {} in state!" , substring)
}

#[cfg(test)]
mod tests {
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
}
