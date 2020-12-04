use crate::{
    chains::eth::{
        eth_constants::{EXTENSION_NODE_STRING, LEAF_NODE_STRING},
        nibble_utils::{
            convert_nibble_to_bytes,
            get_length_in_nibbles,
            get_nibble_at_index,
            get_nibbles_from_bytes,
            get_nibbles_from_offset_bytes,
            get_zero_nibble,
            prefix_nibbles_with_byte,
            replace_nibble_in_nibbles_at_nibble_index,
            set_nibble_offset_to_one,
            set_nibble_offset_to_zero,
            slice_nibbles_at_nibble_index,
            Nibbles,
        },
    },
    types::{Bytes, Result},
};

const ODD_LENGTH_LEAF_PREFIX_NIBBLE: u8 = 3u8; // [00000011]
const EVEN_LENGTH_LEAF_PREFIX_BYTE: u8 = 32u8; // [00100000]
const EVEN_LENGTH_LEAF_PREFIX_NIBBLE: u8 = 2u8; // [00000010]
const EVEN_LENGTH_EXTENSION_PREFIX_BYTE: u8 = 0u8; // [00000000]
const ODD_LENGTH_EXTENSION_PREFIX_NIBBLE: u8 = 1u8; // [00000001]
const EVEN_LENGTH_EXTENSION_PREFIX_NIBBLE: u8 = 0u8; // [00000000]

fn get_leaf_prefix_nibble() -> Nibbles {
    get_nibbles_from_offset_bytes(vec![ODD_LENGTH_LEAF_PREFIX_NIBBLE])
}

fn get_extension_prefix_nibble() -> Nibbles {
    get_nibbles_from_offset_bytes(vec![ODD_LENGTH_EXTENSION_PREFIX_NIBBLE])
}

fn encode_even_length_extension_path_from_nibbles(nibbles: Nibbles) -> Result<Bytes> {
    prefix_nibbles_with_byte(nibbles, vec![EVEN_LENGTH_EXTENSION_PREFIX_BYTE])
}

fn encode_even_length_leaf_path_from_nibbles(nibbles: Nibbles) -> Result<Bytes> {
    prefix_nibbles_with_byte(nibbles, vec![EVEN_LENGTH_LEAF_PREFIX_BYTE])
}

fn encode_odd_length_path_from_nibbles(nibbles: Nibbles, prefix_nibble: Nibbles) -> Result<Bytes> {
    replace_nibble_in_nibbles_at_nibble_index(set_nibble_offset_to_zero(nibbles), prefix_nibble, 0)
        .and_then(convert_nibble_to_bytes)
}

fn encode_odd_length_extension_path_from_nibbles(nibbles: Nibbles) -> Result<Bytes> {
    encode_odd_length_path_from_nibbles(nibbles, get_extension_prefix_nibble())
}

fn encode_odd_length_leaf_path_from_nibbles(nibbles: Nibbles) -> Result<Bytes> {
    encode_odd_length_path_from_nibbles(nibbles, get_leaf_prefix_nibble())
}

fn decode_odd_length_nibbles(nibbles: Nibbles) -> Result<Nibbles> {
    replace_nibble_in_nibbles_at_nibble_index(nibbles, get_zero_nibble(), 0).map(set_nibble_offset_to_one)
}

pub fn decode_path_to_nibbles_and_node_type(path: Bytes) -> Result<(Nibbles, &'static str)> {
    let nibbles = get_nibbles_from_bytes(path);
    match get_nibble_at_index(&nibbles, 0)? {
        EVEN_LENGTH_LEAF_PREFIX_NIBBLE => Ok((slice_nibbles_at_nibble_index(nibbles, 2)?, LEAF_NODE_STRING)),
        EVEN_LENGTH_EXTENSION_PREFIX_NIBBLE => Ok((slice_nibbles_at_nibble_index(nibbles, 2)?, EXTENSION_NODE_STRING)),
        ODD_LENGTH_LEAF_PREFIX_NIBBLE => Ok((decode_odd_length_nibbles(nibbles)?, LEAF_NODE_STRING)),
        ODD_LENGTH_EXTENSION_PREFIX_NIBBLE => Ok((decode_odd_length_nibbles(nibbles)?, EXTENSION_NODE_STRING)),
        _ => Err("✘ Malformed path - cannot determine node type!".into()),
    }
}

pub fn encode_extension_path_from_nibbles(nibbles: Nibbles) -> Result<Bytes> {
    match get_length_in_nibbles(&nibbles) % 2 == 0 {
        true => encode_even_length_extension_path_from_nibbles(nibbles),
        false => encode_odd_length_extension_path_from_nibbles(nibbles),
    }
}

pub fn encode_leaf_path_from_nibbles(nibbles: Nibbles) -> Result<Bytes> {
    match get_length_in_nibbles(&nibbles) % 2 == 0 {
        true => encode_even_length_leaf_path_from_nibbles(nibbles),
        false => encode_odd_length_leaf_path_from_nibbles(nibbles),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::eth::nibble_utils::{get_nibbles_from_bytes, get_nibbles_from_offset_bytes},
        errors::AppError,
    };

    // Test vectors are from the spec @:
    // https://github.com/ethereum/wiki/wiki/Patricia-Tree
    //
    // > [ 1, 2, 3, 4, 5, ...]
    // '11 23 45'
    // > [ 0, 1, 2, 3, 4, 5, ...]
    // '00 01 23 45'
    // > [ 0, f, 1, c, b, 8, 10]
    // '20 0f 1c b8'
    // > [ f, 1, c, b, 8, 10]
    // '3f 1c b8'
    //

    fn get_odd_extension_path_sample() -> (Nibbles, Bytes) {
        let nibbles = get_nibbles_from_offset_bytes(vec![0x01u8, 0x23, 0x45]);
        let bytes = hex::decode("112345".to_string()).unwrap();
        (nibbles, bytes)
    }

    fn get_even_extension_path_sample() -> (Nibbles, Bytes) {
        let nibbles = get_nibbles_from_bytes(vec![0x01, 0x23, 0x45]);
        let bytes = hex::decode("00012345".to_string()).unwrap();
        (nibbles, bytes)
    }

    fn get_even_leaf_path_sample() -> (Nibbles, Bytes) {
        let nibbles = get_nibbles_from_bytes(vec![0x0f, 0x1c, 0xb8]);
        let bytes = hex::decode("200f1cb8".to_string()).unwrap();
        (nibbles, bytes)
    }

    fn get_odd_leaf_path_sample() -> (Nibbles, Bytes) {
        let nibbles = get_nibbles_from_offset_bytes(vec![0x0fu8, 0x1c, 0xb8]);
        let bytes = hex::decode("3f1cb8".to_string()).unwrap();
        (nibbles, bytes)
    }

    #[test]
    fn should_encode_odd_length_extension_path_correctly() {
        let (sample, expected_result) = get_odd_extension_path_sample();
        let result = encode_odd_length_extension_path_from_nibbles(sample).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_encode_even_length_extension_path_correctly() {
        let (sample, expected_result) = get_even_extension_path_sample();
        let result = encode_even_length_extension_path_from_nibbles(sample).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_encode_odd_length_leaf_path_correctly() {
        let (sample, expected_result) = get_odd_leaf_path_sample();
        let result = encode_odd_length_leaf_path_from_nibbles(sample).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_encode_even_length_leaf_path_correctly() {
        let (sample, expected_result) = get_even_leaf_path_sample();
        let result = encode_even_length_leaf_path_from_nibbles(sample).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_encode_extension_path_from_offset_nibbles_correctly() {
        let (sample, expected_result) = get_odd_extension_path_sample();
        let result = encode_extension_path_from_nibbles(sample).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_encode_extension_path_from_nibbles_correctly() {
        let (sample, expected_result) = get_even_extension_path_sample();
        let result = encode_extension_path_from_nibbles(sample).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_encode_leaf_path_from_offset_nibbles_correctly() {
        let (sample, expected_result) = get_odd_leaf_path_sample();
        let result = encode_leaf_path_from_nibbles(sample).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_encode_leaf_path_from_nibbles_correctly() {
        let (sample, expected_result) = get_even_leaf_path_sample();
        let result = encode_leaf_path_from_nibbles(sample).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_decode_even_path_to_nibbles_and_leaf_node_type_correctly() {
        let (expected_nibbles, path) = get_even_leaf_path_sample();
        let (result_nibbles, result_type) = decode_path_to_nibbles_and_node_type(path).unwrap();
        assert_eq!(result_type, "leaf");
        assert_eq!(expected_nibbles.data, result_nibbles.data);
    }

    #[test]
    fn should_decode_odd_path_to_nibbles_and_leaf_node_type_correctly() {
        let (expected_nibbles, path) = get_odd_leaf_path_sample();
        let (result_nibbles, result_type) = decode_path_to_nibbles_and_node_type(path).unwrap();
        assert_eq!(result_type, "leaf");
        assert_eq!(expected_nibbles.data, result_nibbles.data);
    }

    #[test]
    fn should_decode_odd_path_to_nibbles_and_extension_node_type_correctly() {
        let (expected_nibbles, path) = get_odd_extension_path_sample();
        let (result_nibbles, result_type) = decode_path_to_nibbles_and_node_type(path).unwrap();
        assert_eq!(result_type, "extension");
        assert_eq!(expected_nibbles.data, result_nibbles.data);
    }

    #[test]
    fn should_decode_even_path_to_nibbles_and_extension_node_type_correctly() {
        let (expected_nibbles, path) = get_even_extension_path_sample();
        let (result_nibbles, result_type) = decode_path_to_nibbles_and_node_type(path).unwrap();
        assert_eq!(result_type, "extension");
        assert_eq!(expected_nibbles.data, result_nibbles.data);
    }

    #[test]
    fn should_error_when_decoding_a_wrongly_encoded_path() {
        // NOTE: 1st nibble > 3 == a wrong encoding
        let wrong_path = hex::decode("c0ffee".to_string()).unwrap();
        let expected_error = "✘ Malformed path - cannot determine node type!".to_string();
        match decode_path_to_nibbles_and_node_type(wrong_path) {
            Ok(_) => panic!("Should not decode a bad encoding!"),
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            _ => panic!("Didn't get correct decoding error!"),
        }
    }

    #[test]
    fn should_decode_odd_length_leaf_path_to_nibbles_correctly() {
        let (expected_nibbles, path) = get_odd_leaf_path_sample();
        let encoded_nibbles = get_nibbles_from_bytes(path);
        let result = decode_odd_length_nibbles(encoded_nibbles).unwrap();
        assert_eq!(result.data, expected_nibbles.data);
    }

    #[test]
    fn should_decode_odd_length_extension_path_to_nibbles_correctly() {
        let (expected_nibbles, path) = get_odd_extension_path_sample();
        let encoded_nibbles = get_nibbles_from_bytes(path);
        let result = decode_odd_length_nibbles(encoded_nibbles).unwrap();
        assert_eq!(result.data, expected_nibbles.data);
    }
}
