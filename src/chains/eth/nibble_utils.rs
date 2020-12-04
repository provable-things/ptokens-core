use crate::{
    chains::eth::eth_constants::{EMPTY_NIBBLES, HIGH_NIBBLE_MASK, NUM_BITS_IN_NIBBLE, NUM_NIBBLES_IN_BYTE, ZERO_BYTE},
    types::{Byte, Bytes, Result},
};
use std::fmt;

#[derive(Clone, Eq)]
pub struct Nibbles {
    pub data: Bytes,
    pub offset: usize,
}

impl PartialEq for Nibbles {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.offset == other.offset
    }
}

impl fmt::Debug for Nibbles {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self == &EMPTY_NIBBLES {
            true => write!(f, "Nibble array is empty!")?,
            false => {
                for i in 0..get_length_in_nibbles(&self) {
                    write!(f, "0x{:01x} ", match get_nibble_at_index(&self, i) {
                        Ok(nibble) => nibble,
                        Err(_) => 0u8,
                    })?;
                }
            },
        };
        Ok(())
    }
}

impl Nibbles {
    pub fn len(&self) -> usize {
        get_length_in_nibbles(&self)
    }

    pub fn is_empty(&self) -> bool {
        get_length_in_nibbles(&self) == 0
    }
}

pub fn get_common_prefix_nibbles(nibbles_a: Nibbles, nibbles_b: Nibbles) -> Result<(Nibbles, Nibbles, Nibbles)> {
    let a_is_shorter = get_length_in_nibbles(&nibbles_a) < get_length_in_nibbles(&nibbles_b);
    let (common_prefix, a, b) = match a_is_shorter {
        true => get_common_prefix_nibbles_recursively(nibbles_a, nibbles_b, EMPTY_NIBBLES)?,
        false => get_common_prefix_nibbles_recursively(nibbles_b, nibbles_a, EMPTY_NIBBLES)?,
    };
    match a_is_shorter {
        true => Ok((common_prefix, a, b)),
        false => Ok((common_prefix, b, a)),
    }
}

fn get_common_prefix_nibbles_recursively(
    shorter_nibbles: Nibbles,
    longer_nibbles: Nibbles,
    common_prefix: Nibbles,
) -> Result<(Nibbles, Nibbles, Nibbles)> {
    match get_length_in_nibbles(&shorter_nibbles) {
        0 => Ok((common_prefix, shorter_nibbles, longer_nibbles)),
        _ => {
            let first_nibble = get_nibbles_from_bytes(vec![get_nibble_at_index(&shorter_nibbles, 0)?]);
            match get_nibble_at_index(&shorter_nibbles, 0)? == get_nibble_at_index(&longer_nibbles, 0)? {
                false => Ok((common_prefix, shorter_nibbles, longer_nibbles)),
                true => get_common_prefix_nibbles_recursively(
                    remove_first_nibble(shorter_nibbles)?,
                    remove_first_nibble(longer_nibbles)?,
                    push_nibble_into_nibbles(first_nibble, common_prefix)?,
                ),
            }
        },
    }
}

fn get_appending_byte_from_nibble(nibble: Nibbles) -> Result<u8> {
    Ok(nibble.data[0] << NUM_BITS_IN_NIBBLE)
}

fn append_byte_to_nibble_data(nibbles: Nibbles, byte: Bytes) -> Result<Bytes> {
    match nibbles == EMPTY_NIBBLES {
        true => Ok(byte),
        false => {
            let mut nibble_data = nibbles.data;
            nibble_data.push(byte[0]);
            Ok(nibble_data)
        },
    }
}

fn push_nibble_into_nibbles(nibble_to_append: Nibbles, nibbles: Nibbles) -> Result<Nibbles> {
    if nibbles == EMPTY_NIBBLES {
        return Ok(set_nibble_offset_to_one(nibble_to_append));
    };
    if nibble_to_append == EMPTY_NIBBLES {
        return Ok(nibbles);
    }
    match nibbles.offset {
        0 => get_appending_byte_from_nibble(nibble_to_append)
            .and_then(|byte| append_byte_to_nibble_data(nibbles, vec![byte]))
            .map(shift_bits_in_vec_right_one_nibble)
            .map(get_nibbles_from_offset_bytes)
            .map(remove_last_byte_from_nibbles),
        _ => get_appending_byte_from_nibble(nibble_to_append)
            .and_then(|byte| append_byte_to_nibble_data(nibbles, vec![byte]))
            .map(shift_bits_in_vec_left_one_nibble)
            .map(get_nibbles_from_bytes)
            .map(remove_last_byte_from_nibbles),
    }
}

fn shift_bits_in_vec_right_one_nibble(bytes: Bytes) -> Bytes {
    match bytes.len() {
        0 => vec![ZERO_BYTE],
        1 => vec![bytes[0] >> NUM_BITS_IN_NIBBLE],
        _ => {
            let mut new_bytes: Bytes = Vec::new();
            for i in 0..bytes.len() {
                let high_nibble_byte = match i {
                    x if (x == 0 || x == bytes.len()) => ZERO_BYTE,
                    _ => bytes[i - 1] << NUM_BITS_IN_NIBBLE,
                };
                let low_nibble_byte = bytes[i] >> NUM_BITS_IN_NIBBLE;
                let byte = merge_nibbles_from_bytes(low_nibble_byte, high_nibble_byte);
                new_bytes.push(byte);
            }

            let final_byte = merge_nibbles_from_bytes(ZERO_BYTE, bytes[bytes.len() - 1] << NUM_BITS_IN_NIBBLE);
            new_bytes.push(final_byte);
            new_bytes
        },
    }
}

fn shift_bits_in_vec_left_one_nibble(bytes: Bytes) -> Bytes {
    match bytes.len() {
        0 => vec![ZERO_BYTE],
        1 => vec![bytes[0] << NUM_BITS_IN_NIBBLE],
        _ => {
            let mut new_bytes: Bytes = Vec::new();
            for i in 0..bytes.len() {
                let high_nibble_byte = bytes[i] << NUM_BITS_IN_NIBBLE;
                let low_nibble_byte = match i {
                    x if (x == bytes.len() - 1 || x == bytes.len()) => ZERO_BYTE,
                    _ => bytes[i + 1] >> NUM_BITS_IN_NIBBLE,
                };
                let byte = merge_nibbles_from_bytes(low_nibble_byte, high_nibble_byte);
                new_bytes.push(byte);
            }
            new_bytes
        },
    }
}

fn remove_first_nibble(nibbles: Nibbles) -> Result<Nibbles> {
    match get_length_in_nibbles(&nibbles) {
        0 => Ok(EMPTY_NIBBLES),
        1 => Ok(EMPTY_NIBBLES),
        _ => match nibbles.offset {
            1 => Ok(remove_first_byte_from_nibbles(nibbles)),
            _ => replace_nibble_in_nibbles_at_nibble_index(nibbles, get_zero_nibble(), 0).map(set_nibble_offset_to_one),
        },
    }
}

pub fn get_zero_nibble() -> Nibbles {
    Nibbles {
        data: vec![ZERO_BYTE],
        offset: 1,
    }
}

fn remove_first_byte_from_nibbles(nibbles: Nibbles) -> Nibbles {
    match nibbles.data.len() > 1 {
        false => EMPTY_NIBBLES,
        true => Nibbles {
            offset: 0,
            data: nibbles.data[1..].to_vec(),
        },
    }
}

fn remove_last_byte_from_nibbles(nibbles: Nibbles) -> Nibbles {
    match nibbles.data.len() > 1 {
        false => EMPTY_NIBBLES,
        true => Nibbles {
            offset: nibbles.offset,
            data: nibbles.data[..nibbles.data.len() - 1].to_vec(),
        },
    }
}

pub fn set_nibble_offset_to_zero(nibbles: Nibbles) -> Nibbles {
    Nibbles {
        data: nibbles.data,
        offset: 0,
    }
}

pub fn set_nibble_offset_to_one(nibbles: Nibbles) -> Nibbles {
    Nibbles {
        data: nibbles.data,
        offset: 1,
    }
}

pub fn get_nibbles_from_bytes(nibbles: Bytes) -> Nibbles {
    Nibbles {
        data: nibbles,
        offset: 0,
    }
}

pub fn get_nibbles_from_offset_bytes(nibbles: Bytes) -> Nibbles {
    Nibbles {
        data: nibbles,
        offset: 1,
    }
}

pub fn replace_nibble_in_nibbles_at_nibble_index(
    nibbles: Nibbles,
    replacement_nibble: Nibbles,
    nibble_index: usize,
) -> Result<Nibbles> {
    get_byte_containing_nibble_at_nibble_index(&nibbles, nibble_index)
        .map(|byte| match (nibble_index + nibbles.offset) % 2 {
            0 => replace_high_nibble_in_byte(byte, replacement_nibble),
            _ => replace_low_nibble_in_byte(byte, replacement_nibble),
        })
        .map(|byte| {
            replace_byte_in_nibbles_at_byte_index(
                convert_nibble_index_to_byte_index(&nibbles, nibble_index),
                nibbles,
                byte,
            )
        })
}

fn convert_nibble_index_to_byte_index(nibbles: &Nibbles, nibble_index: usize) -> usize {
    (nibbles.offset + nibble_index) / NUM_NIBBLES_IN_BYTE
}

fn replace_byte_in_nibbles_at_byte_index(index: usize, nibbles: Nibbles, byte: Byte) -> Nibbles {
    let mut nibbles_data = nibbles.data.clone();
    if index < nibbles_data.len() {
        nibbles_data[index] = byte;
    }
    match nibbles.offset {
        0 => get_nibbles_from_bytes(nibbles_data),
        _ => get_nibbles_from_offset_bytes(nibbles_data),
    }
}

pub fn replace_high_nibble_in_byte(byte: Byte, replacement_nibble: Nibbles) -> Byte {
    match replacement_nibble.offset {
        0 => merge_nibbles_from_bytes(byte, replacement_nibble.data[0]),
        _ => merge_nibbles_from_bytes(byte, shift_nibble_left(replacement_nibble.data[0])),
    }
}

pub fn replace_low_nibble_in_byte(byte: Byte, replacement_nibble: Nibbles) -> Byte {
    match replacement_nibble.offset {
        1 => merge_nibbles_from_bytes(replacement_nibble.data[0], byte),
        _ => merge_nibbles_from_bytes(shift_nibble_right(replacement_nibble.data[0]), byte),
    }
}

fn merge_nibbles_from_bytes(low_nibble_byte: Byte, high_nibble_byte: Byte) -> Byte {
    high_nibble_byte ^ ((high_nibble_byte ^ low_nibble_byte) & HIGH_NIBBLE_MASK)
}

pub fn get_length_in_nibbles(nibbles: &Nibbles) -> usize {
    nibbles.data.len() * 2 - nibbles.offset
}

pub fn split_at_first_nibble(nibbles: &Nibbles) -> Result<(Nibbles, Nibbles)> {
    match get_length_in_nibbles(&nibbles) > 0 {
        false => Ok((EMPTY_NIBBLES, EMPTY_NIBBLES)),
        true => get_nibble_at_index(&nibbles, 0).and_then(|first_nibble| {
            Ok((
                get_nibbles_from_offset_bytes(vec![first_nibble]),
                slice_nibbles_at_nibble_index(nibbles.clone(), 1)?,
            ))
        }),
    }
}

pub fn get_nibble_at_index(nibbles: &Nibbles, nibble_index: usize) -> Result<Byte> {
    match nibble_index > get_length_in_nibbles(&nibbles) {
        true => Err(format!("✘ Index {} is out-of-bounds in nibble vector!", nibble_index).into()),
        _ => match nibbles.offset {
            0 => match nibble_index % 2 {
                0 => get_high_nibble_from_byte(&nibbles, nibble_index),
                _ => get_low_nibble_from_byte(&nibbles, nibble_index),
            },
            _ => match nibble_index % 2 {
                0 => get_low_nibble_from_byte(&nibbles, nibble_index),
                _ => get_high_nibble_from_byte(&nibbles, nibble_index + 1),
            },
        },
    }
}

fn get_byte_containing_nibble_at_nibble_index(nibbles: &Nibbles, nibble_index: usize) -> Result<Byte> {
    Ok(nibbles.data[convert_nibble_index_to_byte_index(nibbles, nibble_index)])
}

fn mask_higher_nibble(byte: Byte) -> Byte {
    byte & HIGH_NIBBLE_MASK
}

fn shift_nibble_right(byte: Byte) -> Byte {
    byte >> NUM_BITS_IN_NIBBLE
}

fn shift_nibble_left(byte: Byte) -> Byte {
    byte << NUM_BITS_IN_NIBBLE
}

fn get_low_nibble_from_byte(nibbles: &Nibbles, nibble_index: usize) -> Result<Byte> {
    get_byte_containing_nibble_at_nibble_index(nibbles, nibble_index).map(mask_higher_nibble)
}

fn get_high_nibble_from_byte(nibbles: &Nibbles, nibble_index: usize) -> Result<Byte> {
    get_byte_containing_nibble_at_nibble_index(nibbles, nibble_index).map(shift_nibble_right)
}

pub fn prefix_nibbles_with_byte(nibbles: Nibbles, mut vec_including_prefix_byte: Vec<u8>) -> Result<Bytes> {
    convert_nibble_to_bytes(nibbles).map(|mut bytes| {
        vec_including_prefix_byte.append(&mut bytes);
        vec_including_prefix_byte
    })
}

pub fn convert_nibble_to_bytes(nibbles: Nibbles) -> Result<Bytes> {
    Ok(nibbles.data)
}

fn slice_nibbles_at_byte_index(nibbles: Nibbles, byte_index: usize) -> Result<Nibbles> {
    Ok(get_nibbles_from_bytes(nibbles.data[byte_index..].to_vec()))
}

pub fn slice_nibbles_at_nibble_index(nibbles: Nibbles, nibble_index: usize) -> Result<Nibbles> {
    match nibble_index {
        // NOTE: The following pattern guard is ∵ we compare to a runtime var!
        x if (x >= get_length_in_nibbles(&nibbles)) => Ok(EMPTY_NIBBLES),
        0 => Ok(nibbles),
        1 => remove_first_nibble(nibbles),
        _ => {
            let offset = nibbles.offset;
            let byte_index = convert_nibble_index_to_byte_index(&nibbles, nibble_index);
            let sliced_nibbles = slice_nibbles_at_byte_index(nibbles, byte_index)?;
            match (nibble_index + offset) % 2 == 0 {
                true => Ok(sliced_nibbles),
                false => replace_nibble_in_nibbles_at_nibble_index(sliced_nibbles, get_zero_nibble(), 0)
                    .map(set_nibble_offset_to_one),
            }
        },
    }
}

pub fn convert_nibble_to_usize(nibbles: Nibbles) -> usize {
    match nibbles.is_empty() {
        true => 0,
        false => nibbles.data[0] as usize,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::needless_range_loop)]

    use super::*;
    use crate::errors::AppError;

    const EXPECTED_NIBBLES: [u8; 14] = [
        0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, 0x07u8, 0x08u8, 0x09u8, 0x0au8, 0x0bu8, 0x0cu8, 0x0du8, 0x0eu8,
    ];

    fn get_bytes_with_nibbles_from_index_zero() -> Bytes {
        vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde]
    }

    fn get_bytes_with_nibbles_from_index_one() -> Bytes {
        vec![0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd]
    }

    fn get_sample_nibbles() -> Nibbles {
        get_nibbles_from_bytes(get_bytes_with_nibbles_from_index_zero())
    }

    fn get_sample_offset_nibbles() -> Nibbles {
        get_nibbles_from_offset_bytes(get_bytes_with_nibbles_from_index_one())
    }

    #[test]
    fn should_convert_nibble_to_usize() {
        let nibble = get_nibbles_from_bytes(vec![0xfu8]);
        let result = convert_nibble_to_usize(nibble);
        assert_eq!(result, 15);
    }

    #[test]
    fn should_convert_zero_nibble_to_usize() {
        let result = convert_nibble_to_usize(EMPTY_NIBBLES);
        assert_eq!(result, 0);
    }

    #[test]
    fn should_convert_slice_with_nibble_at_index_zero_correctly() {
        let expected_length = get_bytes_with_nibbles_from_index_zero().len() * 2;
        let bytes = get_bytes_with_nibbles_from_index_zero();
        let result = get_nibbles_from_bytes(bytes);
        assert_eq!(get_length_in_nibbles(&result), expected_length)
    }

    #[test]
    fn should_convert_slice_with_nibble_at_index_one_correctly() {
        let expected_length = get_bytes_with_nibbles_from_index_one().len() * 2 - 1;
        let bytes = get_bytes_with_nibbles_from_index_one();
        let result = get_nibbles_from_offset_bytes(bytes);
        assert_eq!(get_length_in_nibbles(&result), expected_length)
    }

    #[test]
    fn should_get_all_nibbles_with_first_nibble_at_index_zero_correctly() {
        let bytes = get_bytes_with_nibbles_from_index_zero();
        let nibbles = get_nibbles_from_bytes(bytes);
        for i in 0..get_length_in_nibbles(&nibbles) {
            let nibble = get_nibble_at_index(&nibbles, i).unwrap();
            assert_eq!(nibble, EXPECTED_NIBBLES[i]);
        }
    }

    #[test]
    fn should_get_all_nibbles_with_first_nibble_at_index_one_correctly() {
        let bytes = get_bytes_with_nibbles_from_index_one();
        let nibbles = get_nibbles_from_offset_bytes(bytes);
        for i in 0..get_length_in_nibbles(&nibbles) {
            let nibble = get_nibble_at_index(&nibbles, i).unwrap();
            assert_eq!(nibble, EXPECTED_NIBBLES[i]);
        }
    }

    #[test]
    fn should_err_if_attempting_to_get_out_of_bounds_nibble() {
        let bytes = get_bytes_with_nibbles_from_index_zero();
        let nibbles = get_nibbles_from_bytes(bytes);
        let num_nibbles = get_length_in_nibbles(&nibbles);
        let out_of_bounds_index = num_nibbles + 1;
        assert!(out_of_bounds_index > num_nibbles);
        let expected_error = &format!("✘ Index {} is out-of-bounds in nibble vector!", out_of_bounds_index);
        match get_nibble_at_index(&nibbles, out_of_bounds_index) {
            Err(AppError::Custom(e)) => assert!(e.contains(expected_error)),
            _ => panic!("Expected error not receieved!"),
        }
    }

    #[test]
    fn should_display_nibble_starting_at_index_zero_string_correctly() {
        let bytes = get_bytes_with_nibbles_from_index_zero();
        let nibbles = get_nibbles_from_bytes(bytes);
        println!("{:?}", nibbles);
    }

    #[test]
    fn should_display_nibble_starting_at_index_one_string_correctly() {
        let bytes = get_bytes_with_nibbles_from_index_one();
        let nibbles = get_nibbles_from_offset_bytes(bytes);
        println!("{:?}", nibbles);
    }

    #[test]
    fn should_merge_nibbles_from_bytes_correctly() {
        let low_nibble_byte = 14u8; // [00001110]
        let high_nibble_byte = 160u8; // [10100000]
        let expected_result = 174u8; // [10101110]
        let result = merge_nibbles_from_bytes(low_nibble_byte, high_nibble_byte);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_shift_nibble_right_correctly() {
        let test_byte = 160u8; // [10100000]
        let expected_result = 10u8; // [00001010]
        let result = shift_nibble_right(test_byte);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_shift_nibble_left_correctly() {
        let test_byte = 10u8; // [00001010]
        let expected_result = 160u8; // [10100000]
        let result = shift_nibble_left(test_byte);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_mask_higher_nibble_correctly() {
        let test_byte = 174u8; // [10101110]
        let expected_result = 14u8; // [00001110]
        let result = mask_higher_nibble(test_byte);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_low_nibble_from_byte_correctly() {
        let index_of_byte = 0;
        let nibbles = get_nibbles_from_bytes(vec![174u8]); // [10101110]
        let expected_result = 14u8; // [00001110]
        let result = get_low_nibble_from_byte(&nibbles, index_of_byte).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_high_nibble_from_byte_correctly() {
        let index_of_byte = 0;
        let nibbles = get_nibbles_from_bytes(vec![174u8]); // [10101110]
        let expected_result = 10u8; // [00001010]
        let result = get_high_nibble_from_byte(&nibbles, index_of_byte).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_byte_containing_nibble_at_i_correctly() {
        let index_of_nibble = 2;
        let nibbles = get_nibbles_from_bytes(vec![0u8, 1u8, 2u8, 3u8, 4u8, 5u8]);
        let expected_result = 1u8;
        let result = get_byte_containing_nibble_at_nibble_index(&nibbles, index_of_nibble).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_replace_high_nibble_in_byte_correctly() {
        let test_byte = 170u8; // [10101010]
        let replacement_nibble = 240u8; // [11110000]
        let expected_result = 250u8; // [11111010]
        let result = replace_high_nibble_in_byte(test_byte, get_nibbles_from_bytes(vec![replacement_nibble]));
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_replace_high_offset_nibble_in_byte_correctly() {
        let test_byte = 170u8; // [10101010]
        let replacement_nibble = 15u8; // [00001111]
        let expected_result = 250u8; // [11111010]
        let result = replace_high_nibble_in_byte(test_byte, get_nibbles_from_offset_bytes(vec![replacement_nibble]));
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_replace_low_nibble_in_byte_correctly() {
        let test_byte = 170u8; // [10101010]
        let replacement_nibble = 240u8; // [11110000]
        let expected_result = 175u8; // [10101111]
        let result = replace_low_nibble_in_byte(test_byte, get_nibbles_from_bytes(vec![replacement_nibble]));
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_replace_low_offset_nibble_in_byte_correctly() {
        let test_byte = 170u8; // [10101010]
        let replacement_nibble = 15u8; // [00001111]
        let expected_result = 175u8; // [10101111]
        let result = replace_low_nibble_in_byte(test_byte, get_nibbles_from_offset_bytes(vec![replacement_nibble]));
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_replace_byte_in_nibbles_correctly() {
        let byte_index = 3;
        let replacement_byte = 170u8;
        let original_bytes = get_bytes_with_nibbles_from_index_zero();
        let original_byte = original_bytes[byte_index];
        let nibbles = get_sample_nibbles();
        assert!(original_byte != replacement_byte);
        let updated_nibbles = replace_byte_in_nibbles_at_byte_index(byte_index, nibbles, replacement_byte);
        let result = updated_nibbles.data[byte_index];
        assert!(result != original_byte);
        assert_eq!(result, replacement_byte);
        updated_nibbles
            .data
            .iter()
            .enumerate()
            .for_each(|(i, byte)| match i == byte_index {
                true => assert_eq!(byte, &replacement_byte),
                false => assert_eq!(byte, &original_bytes[i]),
            });
    }

    #[test]
    fn should_replace_byte_in_offset_nibbles_correctly() {
        let byte_index = 3;
        let replacement_byte = 170u8;
        let original_bytes = get_bytes_with_nibbles_from_index_one();
        let original_byte = original_bytes[byte_index];
        let nibbles = get_sample_offset_nibbles();
        assert!(original_byte != replacement_byte);
        let updated_nibbles = replace_byte_in_nibbles_at_byte_index(byte_index, nibbles, replacement_byte);
        let result = updated_nibbles.data[byte_index];
        assert!(result != original_byte);
        assert_eq!(result, replacement_byte);
        updated_nibbles
            .data
            .iter()
            .enumerate()
            .for_each(|(i, byte)| match i == byte_index {
                true => assert_eq!(byte, &replacement_byte),
                false => assert_eq!(byte, &original_bytes[i]),
            });
    }

    #[test]
    fn should_convert_nibble_i_to_byte_i_in_nibbles_correctly() {
        let nibble_index = 3;
        let expected_result = 1;
        let nibbles = get_sample_nibbles();
        let result = convert_nibble_index_to_byte_index(&nibbles, nibble_index);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_nibble_i_to_byte_i_in_offset_nibbles_correctly() {
        let nibble_index = 3;
        let expected_result = 2;
        let nibbles = get_sample_offset_nibbles();
        let result = convert_nibble_index_to_byte_index(&nibbles, nibble_index);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_replace_offset_nibble_at_nibble_index_in_nibbles_correctly() {
        for nibble_index in 0..get_length_in_nibbles(&get_sample_nibbles()) {
            let nibbles_before = get_sample_nibbles();
            let byte_index = convert_nibble_index_to_byte_index(&nibbles_before, nibble_index);
            let byte_before = get_byte_containing_nibble_at_nibble_index(&nibbles_before, nibble_index).unwrap();
            let replacement_nibble = get_nibbles_from_offset_bytes(vec![15u8] /* [00001111] */);
            let expected_byte = match nibble_index % 2 {
                0 => replace_high_nibble_in_byte(byte_before, replacement_nibble.clone()),
                _ => replace_low_nibble_in_byte(byte_before, replacement_nibble.clone()),
            };
            let nibbles_after = replace_nibble_in_nibbles_at_nibble_index(
                nibbles_before.clone(),
                replacement_nibble.clone(),
                nibble_index,
            )
            .unwrap();
            let target_nibble_after = get_nibble_at_index(&nibbles_after, nibble_index).unwrap();
            let byte_after = get_byte_containing_nibble_at_nibble_index(&nibbles_after, nibble_index).unwrap();
            assert!(byte_before != byte_after);
            assert_eq!(target_nibble_after, replacement_nibble.data[0]);
            assert_eq!(nibbles_before.data.len(), nibbles_after.data.len());
            assert_eq!(byte_after, expected_byte);
            for i in 0..nibbles_after.data.len() {
                match i == byte_index {
                    true => assert_eq!(nibbles_after.data[i], expected_byte),
                    _ => assert!(nibbles_after.data[i] == nibbles_before.data[i]),
                }
            }
        }
    }

    #[test]
    fn should_replace_offset_nibble_at_nibble_index_in_offset_nibbles() {
        for nibble_index in 0..get_length_in_nibbles(&get_sample_offset_nibbles()) {
            let nibbles_before = get_sample_offset_nibbles();
            let byte_index = convert_nibble_index_to_byte_index(&nibbles_before, nibble_index);
            let byte_before = get_byte_containing_nibble_at_nibble_index(&nibbles_before, nibble_index).unwrap();
            let replacement_nibble = get_nibbles_from_offset_bytes(vec![15u8] /* [00001111] */);
            let expected_byte = match nibble_index % 2 {
                0 => replace_low_nibble_in_byte(byte_before, replacement_nibble.clone()),
                _ => replace_high_nibble_in_byte(byte_before, replacement_nibble.clone()),
            };
            let nibbles_after = replace_nibble_in_nibbles_at_nibble_index(
                nibbles_before.clone(),
                replacement_nibble.clone(),
                nibble_index,
            )
            .unwrap();
            let target_nibble_after = get_nibble_at_index(&nibbles_after, nibble_index).unwrap();
            let byte_after = get_byte_containing_nibble_at_nibble_index(&nibbles_after, nibble_index).unwrap();
            assert!(byte_before != byte_after);
            assert_eq!(target_nibble_after, replacement_nibble.data[0]);
            assert_eq!(nibbles_before.data.len(), nibbles_after.data.len());
            assert_eq!(byte_after, expected_byte);
            for i in 0..nibbles_after.data.len() {
                match i == byte_index {
                    true => assert_eq!(nibbles_after.data[i], expected_byte),
                    _ => assert!(nibbles_after.data[i] == nibbles_before.data[i]),
                }
            }
        }
    }

    #[test]
    fn should_replace_nibble_at_nibble_index_in_offset_nibbles_correctly() {
        for nibble_index in 0..get_length_in_nibbles(&get_sample_offset_nibbles()) {
            let nibbles_before = get_sample_offset_nibbles();
            let byte_index = convert_nibble_index_to_byte_index(&nibbles_before, nibble_index);
            let byte_before = get_byte_containing_nibble_at_nibble_index(&nibbles_before, nibble_index).unwrap();
            let replacement_nibble = get_nibbles_from_bytes(vec![240u8] /* [11110000] */);
            let expected_byte = match nibble_index % 2 {
                0 => replace_low_nibble_in_byte(byte_before, replacement_nibble.clone()),
                _ => replace_high_nibble_in_byte(byte_before, replacement_nibble.clone()),
            };
            let nibbles_after = replace_nibble_in_nibbles_at_nibble_index(
                nibbles_before.clone(),
                replacement_nibble.clone(),
                nibble_index,
            )
            .unwrap();
            let target_nibble_after = get_nibble_at_index(&nibbles_after, nibble_index).unwrap();
            let byte_after = get_byte_containing_nibble_at_nibble_index(&nibbles_after, nibble_index).unwrap();
            assert!(byte_before != byte_after);
            // NOTE: Shift left ∵ we're replacing w/ a non-offset nibble!
            assert_eq!(shift_nibble_left(target_nibble_after), replacement_nibble.data[0]);
            assert_eq!(nibbles_before.data.len(), nibbles_after.data.len());
            assert_eq!(byte_after, expected_byte);
            for i in 0..nibbles_after.data.len() {
                match i == byte_index {
                    true => assert_eq!(nibbles_after.data[i], expected_byte),
                    _ => assert!(nibbles_after.data[i] == nibbles_before.data[i]),
                }
            }
        }
    }

    #[test]
    fn should_replace_nibble_at_nibble_index_in_nibbles_correctly() {
        for nibble_index in 0..get_length_in_nibbles(&get_sample_nibbles()) {
            let nibbles_before = get_sample_nibbles();
            let byte_index = convert_nibble_index_to_byte_index(&nibbles_before, nibble_index);
            let byte_before = get_byte_containing_nibble_at_nibble_index(&nibbles_before, nibble_index).unwrap();
            let replacement_nibble = get_nibbles_from_bytes(vec![240u8] /* [11110000] */);
            let expected_byte = match nibble_index % 2 {
                0 => replace_high_nibble_in_byte(byte_before, replacement_nibble.clone()),
                _ => replace_low_nibble_in_byte(byte_before, replacement_nibble.clone()),
            };
            let nibbles_after = replace_nibble_in_nibbles_at_nibble_index(
                nibbles_before.clone(),
                replacement_nibble.clone(),
                nibble_index,
            )
            .unwrap();
            let target_nibble_after = get_nibble_at_index(&nibbles_after, nibble_index).unwrap();
            let byte_after = get_byte_containing_nibble_at_nibble_index(&nibbles_after, nibble_index).unwrap();
            assert!(byte_before != byte_after);
            // NOTE: Shift left ∵ we're replacing w/ a non-offset nibble!
            assert_eq!(shift_nibble_left(target_nibble_after), replacement_nibble.data[0]);
            assert_eq!(nibbles_before.data.len(), nibbles_after.data.len());
            assert_eq!(byte_after, expected_byte);
            for i in 0..nibbles_after.data.len() {
                match i == byte_index {
                    true => assert_eq!(nibbles_after.data[i], expected_byte),
                    _ => assert!(nibbles_after.data[i] == nibbles_before.data[i]),
                }
            }
        }
    }

    #[test]
    fn should_set_first_nibble_flag_in_nibbles_to_zero_correctly() {
        let expected_result = 0;
        let nibbles = get_sample_offset_nibbles();
        let nibble_flag_before = nibbles.offset;
        assert!(nibble_flag_before != expected_result);
        let updated_nibbles = set_nibble_offset_to_zero(nibbles);
        let result = updated_nibbles.offset;
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_set_first_nibble_flag_in_nibbles_to_one_correctly() {
        let expected_result = 1;
        let nibbles = get_sample_nibbles();
        let nibble_flag_before = nibbles.offset;
        assert!(nibble_flag_before != expected_result);
        let updated_nibbles = set_nibble_offset_to_one(nibbles);
        let result = updated_nibbles.offset;
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_remove_first_byte_from_nibbles() {
        let nibbles_before = get_sample_nibbles();
        let number_of_nibbles_before = get_length_in_nibbles(&nibbles_before);
        let nibbles_after = remove_first_byte_from_nibbles(nibbles_before.clone());
        let number_of_nibbles_after = get_length_in_nibbles(&nibbles_after);
        assert_eq!(number_of_nibbles_after, number_of_nibbles_before - 2);
        assert_eq!(nibbles_after.data.len(), nibbles_before.data.len() - 1);
    }

    #[test]
    fn should_remove_first_byte_from_offest_nibbles() {
        let nibbles_before = get_sample_offset_nibbles();
        let number_of_nibbles_before = get_length_in_nibbles(&nibbles_before);
        let nibbles_after = remove_first_byte_from_nibbles(nibbles_before.clone());
        let number_of_nibbles_after = get_length_in_nibbles(&nibbles_after);
        assert_eq!(number_of_nibbles_after, number_of_nibbles_before - 1);
        assert_eq!(nibbles_after.data.len(), nibbles_before.data.len() - 1);
    }

    #[test]
    fn should_remove_first_byte_of_single_nibble_correctly() {
        let nibble = Nibbles {
            data: vec![0xfu8],
            offset: 1,
        };
        let result = remove_first_byte_from_nibbles(nibble);
        assert_eq!(result, EMPTY_NIBBLES);
    }

    #[test]
    fn should_get_zero_nibble() {
        let expected_byte = 0u8;
        let expected_length = 1;
        let expected_num_nibbles = 1;
        let expected_offset = 1;
        let result = get_zero_nibble();
        let num_nibbles = get_length_in_nibbles(&result);
        assert_eq!(result.data[0], expected_byte);
        assert_eq!(num_nibbles, expected_num_nibbles);
        assert_eq!(result.data.len(), expected_length);
        assert_eq!(result.offset, expected_offset);
    }

    #[test]
    fn should_remove_first_nibble_from_nibbles() {
        let nibbles = get_sample_nibbles();
        let first_nibble_before = get_nibble_at_index(&nibbles, 0).unwrap();
        let expected_first_nibble_after = get_nibble_at_index(&nibbles, 1).unwrap();
        let nibble_len_before = get_length_in_nibbles(&nibbles);
        let last_nibble_before = get_nibble_at_index(&nibbles, nibble_len_before - 1).unwrap();
        let result = remove_first_nibble(nibbles).unwrap();
        let nibble_len_after = get_length_in_nibbles(&result);
        let first_nibble_after = get_nibble_at_index(&result, 0).unwrap();
        let last_nibble_after = get_nibble_at_index(&result, nibble_len_after - 1).unwrap();
        let nibble_len_after = get_length_in_nibbles(&result);
        assert_eq!(last_nibble_before, last_nibble_after);
        assert_eq!(nibble_len_after, nibble_len_before - 1);
        assert!(first_nibble_before != first_nibble_after);
        assert_eq!(first_nibble_after, expected_first_nibble_after);
    }

    #[test]
    fn should_remove_first_nibble_from_offset_nibbles() {
        let nibbles = get_sample_offset_nibbles();
        let first_nibble_before = get_nibble_at_index(&nibbles, 0).unwrap();
        let expected_first_nibble_after = get_nibble_at_index(&nibbles, 1).unwrap();
        let nibble_len_before = get_length_in_nibbles(&nibbles);
        let last_nibble_before = get_nibble_at_index(&nibbles, nibble_len_before - 1).unwrap();
        let result = remove_first_nibble(nibbles).unwrap();
        let nibble_len_after = get_length_in_nibbles(&result);
        let first_nibble_after = get_nibble_at_index(&result, 0).unwrap();
        let last_nibble_after = get_nibble_at_index(&result, nibble_len_after - 1).unwrap();
        let nibble_len_after = get_length_in_nibbles(&result);
        assert_eq!(last_nibble_before, last_nibble_after);
        assert_eq!(nibble_len_after, nibble_len_before - 1);
        assert!(first_nibble_before != first_nibble_after);
        assert_eq!(first_nibble_after, expected_first_nibble_after);
    }

    #[test]
    fn should_remove_first_nibble_if_only_one_nibble() {
        let byte = 5u8;
        let nibble = get_nibbles_from_offset_bytes(vec![byte]);
        let result = remove_first_nibble(nibble).unwrap();
        assert_eq!(result, EMPTY_NIBBLES);
    }

    #[test]
    fn should_prefix_nibble_with_byte_correctly() {
        let nibbles = get_sample_nibbles();
        let prefix = vec![0xff];
        let mut expected_result = prefix.clone();
        let result = prefix_nibbles_with_byte(nibbles, prefix).unwrap();
        let mut bytes = get_bytes_with_nibbles_from_index_zero();
        expected_result.append(&mut bytes);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_prefix_offset_nibble_with_byte_correctly() {
        let nibbles = get_sample_offset_nibbles();
        let prefix = vec![0xff];
        let mut expected_result = prefix.clone();
        let result = prefix_nibbles_with_byte(nibbles, prefix).unwrap();
        let mut bytes = get_bytes_with_nibbles_from_index_one();
        expected_result.append(&mut bytes);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_nibbles_to_bytes_correctly() {
        let nibbles = get_sample_nibbles();
        let expected_result = get_bytes_with_nibbles_from_index_zero();
        let result = convert_nibble_to_bytes(nibbles).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_offset_nibbles_to_bytes_correctly() {
        let nibbles = get_sample_offset_nibbles();
        let expected_result = get_bytes_with_nibbles_from_index_one();
        let result = convert_nibble_to_bytes(nibbles).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_slice_nibbles_at_byte_index_correctly() {
        let byte_index = 2;
        let nibbles = get_sample_nibbles();
        let expected_result = get_nibbles_from_bytes(vec![0x56, 0x78, 0x9a, 0xbc, 0xde]);
        let result = slice_nibbles_at_byte_index(nibbles, byte_index).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_slice_offset_nibbles_at_byte_index_correctly() {
        let byte_index = 2;
        let nibbles = get_sample_offset_nibbles();
        let expected_result = get_nibbles_from_bytes(vec![0x45, 0x67, 0x89, 0xab, 0xcd]);
        let result = slice_nibbles_at_byte_index(nibbles, byte_index).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_slice_nibbles_at_even_nibble_index_correctly() {
        let nibble_index = 4;
        assert_eq!(nibble_index % 2, 0);
        let nibbles = get_sample_nibbles();
        let expected_result = get_nibbles_from_bytes(vec![0x56, 0x78, 0x9a, 0xbc, 0xde]);
        let result = slice_nibbles_at_nibble_index(nibbles, nibble_index).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_slice_nibbles_at_odd_nibble_index_correctly() {
        let nibble_index = 5;
        assert!(nibble_index % 2 != 0);
        let nibbles = get_sample_nibbles();
        let expected_result = get_nibbles_from_offset_bytes(vec![0x6u8, 0x78, 0x9a, 0xbc, 0xde]);
        let result = slice_nibbles_at_nibble_index(nibbles, nibble_index).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_slice_offset_nibbles_at_even_nibble_index_correctly() {
        let nibble_index = 4;
        assert_eq!(nibble_index % 2, 0);
        let nibbles = get_sample_offset_nibbles();
        let expected_result = get_nibbles_from_offset_bytes(vec![0x5u8, 0x67, 0x89, 0xab, 0xcd]);
        let result = slice_nibbles_at_nibble_index(nibbles, nibble_index).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_slice_ofset_nibbles_at_odd_nibble_index_correctly() {
        let nibble_index = 5;
        assert!(nibble_index % 2 != 0);
        let nibbles = get_sample_offset_nibbles();
        let expected_result = get_nibbles_from_bytes(vec![0x67, 0x89, 0xab, 0xcd]);
        let result = slice_nibbles_at_nibble_index(nibbles, nibble_index).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_return_empty_nibbles_when_slicing_with_i_greater_than_length() {
        let nibbles = get_sample_nibbles();
        let nibble_length = get_length_in_nibbles(&nibbles);
        let nibble_index = nibble_length + 1;
        assert!(nibble_length <= nibble_index);
        let result = slice_nibbles_at_nibble_index(nibbles, nibble_index).unwrap();
        assert_eq!(result, EMPTY_NIBBLES)
    }

    #[test]
    fn should_slice_nibbles_at_zero_nibble_index_correctly() {
        let nibble_index = 0;
        let nibbles = get_sample_nibbles();
        let result = slice_nibbles_at_nibble_index(nibbles.clone(), nibble_index).unwrap();
        assert_eq!(nibbles, result);
    }

    #[test]
    fn should_slice_offset_nibbles_at_zero_nibble_index_correctly() {
        let nibble_index = 0;
        let nibbles = get_sample_offset_nibbles();
        let result = slice_nibbles_at_nibble_index(nibbles.clone(), nibble_index).unwrap();
        assert_eq!(nibbles, result);
    }

    #[test]
    fn should_slice_nibbles_at_nibble_index_of_one_correctly() {
        let nibble_index = 1;
        let nibbles = get_sample_nibbles();
        let result = slice_nibbles_at_nibble_index(nibbles, nibble_index).unwrap();
        let expected_result = get_nibbles_from_offset_bytes(vec![0x2u8, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde]);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_slice_offset_nibbles_at_nibble_index_of_one_correctly() {
        let nibble_index = 1;
        let nibbles = get_sample_offset_nibbles();
        let result = slice_nibbles_at_nibble_index(nibbles, nibble_index).unwrap();
        let expected_result = get_nibbles_from_bytes(vec![0x23, 0x45, 0x67, 0x89, 0xab, 0xcd]);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn empty_nibbles_should_have_nibble_length_of_zero() {
        let length_in_nibbles = get_length_in_nibbles(&EMPTY_NIBBLES);
        assert_eq!(length_in_nibbles, 0)
    }

    #[test]
    fn should_shift_bytes_in_vec_right_one_nibble() {
        let bytes = get_bytes_with_nibbles_from_index_zero();
        let expected_result = vec![0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xe0];
        let result = shift_bits_in_vec_right_one_nibble(bytes);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_shift_one_byte_in_vec_right_one_nibble() {
        let byte = vec![0xab];
        let expected_result = vec![0xau8];
        let result = shift_bits_in_vec_right_one_nibble(byte);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_shift_no_bytes_in_vec_right_one_nibble() {
        let byte = Vec::new();
        let expected_result = vec![ZERO_BYTE];
        let result = shift_bits_in_vec_right_one_nibble(byte);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_shift_bytes_in_vec_left_one_nibble() {
        let bytes = get_bytes_with_nibbles_from_index_one();
        let expected_result = vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xd0];
        let result = shift_bits_in_vec_left_one_nibble(bytes);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_shift_one_byte_in_vec_left_one_nibble() {
        let byte = vec![0xab];
        let expected_result = vec![0xb0];
        let result = shift_bits_in_vec_left_one_nibble(byte);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_shift_no_bytes_in_vec_left_one_nibble() {
        let byte = Vec::new();
        let expected_result = vec![ZERO_BYTE];
        let result = shift_bits_in_vec_left_one_nibble(byte);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_appending_byte_from_nibble_correctly() {
        let nibble = Nibbles {
            data: vec![0xab],
            offset: 1,
        };
        let result = get_appending_byte_from_nibble(nibble).unwrap();
        let expected_result = 0xb0;
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_append_byte_to_nibble_data_correctly() {
        let byte = vec![0xff];
        let nibbles = get_sample_nibbles();
        let mut expected_result = nibbles.clone().data;
        expected_result.push(byte[0]);
        let result = append_byte_to_nibble_data(nibbles, byte).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_append_byte_to_empty_nibble_data_correctly() {
        let byte = vec![0xff];
        let nibbles = EMPTY_NIBBLES;
        let mut expected_result = nibbles.clone().data;
        expected_result.push(byte[0]);
        let result = append_byte_to_nibble_data(nibbles, byte).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_push_nibble_into_nibbles_correctly() {
        let nibbles = get_sample_nibbles();
        let nibble = Nibbles {
            data: vec![0xfu8],
            offset: 1,
        };
        let expected_result = Nibbles {
            data: vec![0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            offset: 1,
        };
        let result = push_nibble_into_nibbles(nibble, nibbles).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_push_nibble_into_nibbles_of_length_one_correctly() {
        let nibbles = Nibbles {
            data: vec![0xau8],
            offset: 1,
        };
        let nibble = Nibbles {
            data: vec![0xfu8],
            offset: 1,
        };
        let expected_result = Nibbles {
            data: vec![0xaf],
            offset: 0,
        };
        let result = push_nibble_into_nibbles(nibble, nibbles).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_push_nibble_into_offset_nibbles_correctly() {
        let nibbles = get_sample_offset_nibbles();
        let nibble = Nibbles {
            data: vec![0xfu8],
            offset: 1,
        };
        let expected_result = Nibbles {
            data: vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xdf],
            offset: 0,
        };
        let result = push_nibble_into_nibbles(nibble, nibbles).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_push_nibble_into_empty_nibbles_correctly() {
        let nibbles = EMPTY_NIBBLES;
        let nibble = Nibbles {
            data: vec![0xfu8],
            offset: 1,
        };
        let expected_result = Nibbles {
            data: vec![0xfu8],
            offset: 1,
        };
        let result = push_nibble_into_nibbles(nibble, nibbles).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_remove_last_byte_from_nibbles_correctly() {
        let nibbles = get_sample_nibbles();
        let expected_result = get_nibbles_from_bytes(vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
        let result = remove_last_byte_from_nibbles(nibbles);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_remove_last_byte_from_offset_nibbles_correctly() {
        let nibbles = get_sample_offset_nibbles();
        let expected_result = get_nibbles_from_offset_bytes(vec![0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab]);
        let result = remove_last_byte_from_nibbles(nibbles);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_remove_last_byte_from_single_nibble_correctly() {
        let nibble = Nibbles {
            data: vec![0xfu8],
            offset: 1,
        };
        let result = remove_last_byte_from_nibbles(nibble);
        assert_eq!(result, EMPTY_NIBBLES);
    }

    #[test]
    fn should_remove_last_byte_from_empty_nibble_correctly() {
        let result = remove_last_byte_from_nibbles(EMPTY_NIBBLES);
        assert_eq!(result, EMPTY_NIBBLES);
    }

    #[test]
    fn should_get_common_prefix_nibbles_recursively_when_both_not_offset() {
        let prefix_bytes = vec![0x12, 0x34];
        let shorter_bytes_suffix = vec![0x84, 0x9a];
        let longer_bytes_suffix = vec![0x56, 0x78, 0x9a];
        let shorter_bytes = vec![0x12, 0x34, 0x84, 0x9a];
        let longer_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a];
        let longer_nibbles = get_nibbles_from_bytes(longer_bytes);
        let shorter_nibbles = get_nibbles_from_bytes(shorter_bytes);
        let expected_common_prefix_result = get_nibbles_from_bytes(prefix_bytes);
        let expected_longer_result = get_nibbles_from_bytes(longer_bytes_suffix);
        let expected_shorter_result = get_nibbles_from_bytes(shorter_bytes_suffix);
        let (result_prefix, result_shorter, result_longer) =
            get_common_prefix_nibbles_recursively(shorter_nibbles, longer_nibbles, EMPTY_NIBBLES).unwrap();
        assert_eq!(result_longer, expected_longer_result);
        assert_eq!(result_shorter, expected_shorter_result);
        assert_eq!(result_prefix, expected_common_prefix_result);
    }

    #[test]
    fn should_get_common_prefix_nibbles_recursively_when_both_offset() {
        let prefix_bytes = vec![0x2u8, 0x34];
        let shorter_bytes_suffix = vec![0x84, 0x9a];
        let longer_bytes_suffix = vec![0x56, 0x78, 0x9a];
        let shorter_bytes = vec![0x2u8, 0x34, 0x84, 0x9a];
        let longer_bytes = vec![0x2u8, 0x34, 0x56, 0x78, 0x9a];
        let longer_nibbles = get_nibbles_from_offset_bytes(longer_bytes);
        let shorter_nibbles = get_nibbles_from_offset_bytes(shorter_bytes);
        let expected_common_prefix_result = get_nibbles_from_offset_bytes(prefix_bytes);
        let expected_longer_result = get_nibbles_from_bytes(longer_bytes_suffix);
        let expected_shorter_result = get_nibbles_from_bytes(shorter_bytes_suffix);
        let (result_prefix, result_shorter, result_longer) =
            get_common_prefix_nibbles_recursively(shorter_nibbles, longer_nibbles, EMPTY_NIBBLES).unwrap();
        assert_eq!(result_longer, expected_longer_result);
        assert_eq!(result_shorter, expected_shorter_result);
        assert_eq!(result_prefix, expected_common_prefix_result);
    }

    #[test]
    fn should_get_common_prefix_nibbles_recursively_when_same_and_offset() {
        let longer_bytes = vec![0x2u8, 0x34, 0x56, 0x78, 0x9a];
        let shorter_bytes = vec![0x2u8, 0x34, 0x56, 0x78, 0x9a];
        let longer_nibbles = get_nibbles_from_offset_bytes(longer_bytes.clone());
        let shorter_nibbles = get_nibbles_from_offset_bytes(shorter_bytes);
        let expected_common_prefix_result = get_nibbles_from_offset_bytes(longer_bytes);
        let (result_prefix, result_shorter, result_longer) =
            get_common_prefix_nibbles_recursively(shorter_nibbles, longer_nibbles, EMPTY_NIBBLES).unwrap();
        assert_eq!(result_longer, EMPTY_NIBBLES);
        assert_eq!(result_shorter, EMPTY_NIBBLES);
        assert_eq!(result_prefix, expected_common_prefix_result);
    }

    #[test]
    fn should_get_common_prefix_nibbles_recursively_when_same_and_not_offset() {
        let longer_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a];
        let shorter_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a];
        let longer_nibbles = get_nibbles_from_bytes(longer_bytes.clone());
        let shorter_nibbles = get_nibbles_from_bytes(shorter_bytes);
        let expected_common_prefix_result = get_nibbles_from_bytes(longer_bytes);
        let (result_prefix, result_shorter, result_longer) =
            get_common_prefix_nibbles_recursively(shorter_nibbles, longer_nibbles, EMPTY_NIBBLES).unwrap();
        assert_eq!(result_longer, EMPTY_NIBBLES);
        assert_eq!(result_shorter, EMPTY_NIBBLES);
        assert_eq!(result_prefix, expected_common_prefix_result);
    }

    #[test]
    fn should_get_common_prefix_nibbles_recursively_correctly_when_one_offset() {
        let prefix_bytes = vec![0x12, 0x34];
        let shorter_bytes_suffix = vec![0x84, 0x9a];
        let shorter_bytes = vec![0x12, 0x34, 0x84, 0x9a];
        let longer_bytes_suffix = vec![0x5u8, 0x67, 0x89];
        let longer_bytes = vec![0x1u8, 0x23, 0x45, 0x67, 0x89];
        let longer_nibbles = get_nibbles_from_offset_bytes(longer_bytes);
        let shorter_nibbles = get_nibbles_from_bytes(shorter_bytes);
        let expected_common_prefix_result = get_nibbles_from_bytes(prefix_bytes);
        let expected_longer_result = get_nibbles_from_offset_bytes(longer_bytes_suffix);
        let expected_shorter_result = get_nibbles_from_bytes(shorter_bytes_suffix);
        let (result_prefix, result_shorter, result_longer) =
            get_common_prefix_nibbles_recursively(shorter_nibbles, longer_nibbles, EMPTY_NIBBLES).unwrap();
        assert_eq!(result_longer, expected_longer_result);
        assert_eq!(result_shorter, expected_shorter_result);
        assert_eq!(result_prefix, expected_common_prefix_result);
    }

    #[test]
    fn should_get_common_prefix_correctly_when_one_is_substring_of_other() {
        let prefix_bytes = vec![0x12, 0x34, 0x56];
        let longer_bytes_suffix = vec![0x78, 0x9a];
        let shorter_bytes = vec![0x12, 0x34, 0x56];
        let longer_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a];
        let longer_nibbles = get_nibbles_from_bytes(longer_bytes);
        let shorter_nibbles = get_nibbles_from_bytes(shorter_bytes);
        let expected_common_prefix_result = get_nibbles_from_bytes(prefix_bytes);
        let expected_longer_result = get_nibbles_from_bytes(longer_bytes_suffix);
        let (result_prefix, result_shorter, result_longer) =
            get_common_prefix_nibbles_recursively(shorter_nibbles, longer_nibbles, EMPTY_NIBBLES).unwrap();
        assert_eq!(result_shorter, EMPTY_NIBBLES);
        assert_eq!(result_longer, expected_longer_result);
        assert_eq!(result_prefix, expected_common_prefix_result);
    }

    #[test]
    fn should_get_common_prefixy_when_one_is_substring_of_other_and_offset() {
        let prefix_bytes = vec![0x2u8, 0x34, 0x56];
        let longer_bytes_suffix = vec![0x78, 0x9a];
        let shorter_bytes = vec![0x2u8, 0x34, 0x56];
        let longer_bytes = vec![0x2u8, 0x34, 0x56, 0x78, 0x9a];
        let longer_nibbles = get_nibbles_from_offset_bytes(longer_bytes);
        let shorter_nibbles = get_nibbles_from_offset_bytes(shorter_bytes);
        let expected_common_prefix_result = get_nibbles_from_offset_bytes(prefix_bytes);
        let expected_longer_result = get_nibbles_from_bytes(longer_bytes_suffix);
        let (result_prefix, result_shorter, result_longer) =
            get_common_prefix_nibbles_recursively(shorter_nibbles, longer_nibbles, EMPTY_NIBBLES).unwrap();
        assert_eq!(result_shorter, EMPTY_NIBBLES);
        assert_eq!(result_longer, expected_longer_result);
        assert_eq!(result_prefix, expected_common_prefix_result);
    }

    #[test]
    fn should_get_common_prefix_when_no_common_prefix_and_neither_offset() {
        let bytes_1 = vec![0xf2, 0x34, 0x56, 0x78, 0x9a];
        let bytes_2 = vec![0xba, 0x34, 0x56, 0x78, 0x9a];
        let nibbles_1 = get_nibbles_from_bytes(bytes_1);
        let nibbles_2 = get_nibbles_from_bytes(bytes_2);
        let expected_res_1 = nibbles_1.clone();
        let expected_res_2 = nibbles_2.clone();
        let (result_prefix, result_1, result_2) =
            get_common_prefix_nibbles_recursively(nibbles_1, nibbles_2, EMPTY_NIBBLES).unwrap();
        assert_eq!(result_1, expected_res_1);
        assert_eq!(result_2, expected_res_2);
        assert_eq!(result_prefix, EMPTY_NIBBLES);
    }

    #[test]
    fn should_get_common_prefix_when_no_common_prefix_and_both_offset() {
        let bytes_1 = vec![0x2u8, 0x34, 0x56, 0x78, 0x9a];
        let bytes_2 = vec![0xau8, 0x34, 0x56, 0x78, 0x9a];
        let nibbles_1 = get_nibbles_from_offset_bytes(bytes_1);
        let nibbles_2 = get_nibbles_from_offset_bytes(bytes_2);
        let expected_res_1 = nibbles_1.clone();
        let expected_res_2 = nibbles_2.clone();
        let (result_prefix, result_1, result_2) =
            get_common_prefix_nibbles_recursively(nibbles_1, nibbles_2, EMPTY_NIBBLES).unwrap();
        assert_eq!(result_1, expected_res_1);
        assert_eq!(result_2, expected_res_2);
        assert_eq!(result_prefix, EMPTY_NIBBLES);
    }

    #[test]
    fn should_get_common_prefix_when_no_common_prefix_and_one_offset() {
        let bytes_1 = vec![0xa2, 0x34, 0x56, 0x78, 0x9a];
        let bytes_2 = vec![0xfu8, 0x34, 0x56, 0x78, 0x9a];
        let nibbles_1 = get_nibbles_from_bytes(bytes_1);
        let nibbles_2 = get_nibbles_from_offset_bytes(bytes_2);
        let expected_res_1 = nibbles_1.clone();
        let expected_res_2 = nibbles_2.clone();
        let (result_prefix, result_1, result_2) =
            get_common_prefix_nibbles_recursively(nibbles_1, nibbles_2, EMPTY_NIBBLES).unwrap();
        assert_eq!(result_1, expected_res_1);
        assert_eq!(result_2, expected_res_2);
        assert_eq!(result_prefix, EMPTY_NIBBLES);
    }

    #[test]
    fn get_common_prefix_nibbles_should_work_if_first_nibbles_are_shorter() {
        let prefix_bytes = vec![0x12, 0x34];
        let shorter_bytes_suffix = vec![0x84, 0x9a];
        let longer_bytes_suffix = vec![0x56, 0x78, 0x9a];
        let shorter_bytes = vec![0x12, 0x34, 0x84, 0x9a];
        let longer_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a];
        let longer_nibbles = get_nibbles_from_bytes(longer_bytes);
        let shorter_nibbles = get_nibbles_from_bytes(shorter_bytes);
        let expected_common_prefix_result = get_nibbles_from_bytes(prefix_bytes);
        let expected_longer_result = get_nibbles_from_bytes(longer_bytes_suffix);
        let expected_shorter_result = get_nibbles_from_bytes(shorter_bytes_suffix);
        let (result_prefix, result_1, result_2) = get_common_prefix_nibbles(shorter_nibbles, longer_nibbles).unwrap();
        assert_eq!(result_2, expected_longer_result);
        assert_eq!(result_1, expected_shorter_result);
        assert_eq!(result_prefix, expected_common_prefix_result);
    }

    #[test]
    fn get_common_prefix_nibbles_should_work_if_second_nibbles_are_shorter() {
        let prefix_bytes = vec![0x12, 0x34];
        let shorter_bytes_suffix = vec![0x84, 0x9a];
        let longer_bytes_suffix = vec![0x56, 0x78, 0x9a];
        let shorter_bytes = vec![0x12, 0x34, 0x84, 0x9a];
        let longer_bytes = vec![0x12, 0x34, 0x56, 0x78, 0x9a];
        let longer_nibbles = get_nibbles_from_bytes(longer_bytes);
        let shorter_nibbles = get_nibbles_from_bytes(shorter_bytes);
        let expected_common_prefix_result = get_nibbles_from_bytes(prefix_bytes);
        let expected_longer_result = get_nibbles_from_bytes(longer_bytes_suffix);
        let expected_shorter_result = get_nibbles_from_bytes(shorter_bytes_suffix);
        let (result_prefix, result_1, result_2) = get_common_prefix_nibbles(longer_nibbles, shorter_nibbles).unwrap();
        assert_eq!(result_1, expected_longer_result);
        assert_eq!(result_2, expected_shorter_result);
        assert_eq!(result_prefix, expected_common_prefix_result);
    }

    #[test]
    fn should_split_at_first_nibble_correctly() {
        let bytes = vec![0xdu8, 0xec, 0xaf];
        let nibbles = get_nibbles_from_offset_bytes(bytes);
        let expected_nibbles = get_nibbles_from_bytes(vec![0xec, 0xaf]);
        let expected_nibble = get_nibbles_from_offset_bytes(vec![0xdu8]);
        let (result_nibble, result_nibbles) = split_at_first_nibble(&nibbles).unwrap();
        assert_eq!(result_nibble, expected_nibble);
        assert_eq!(result_nibbles, expected_nibbles);
    }

    #[test]
    fn should_split_at_first_nibble_from_single_nibbles_correctly() {
        let bytes = vec![0xdu8];
        let nibbles = get_nibbles_from_offset_bytes(bytes);
        let expected_nibble = get_nibbles_from_offset_bytes(vec![0xdu8]);
        let (result_nibble, result_nibbles) = split_at_first_nibble(&nibbles).unwrap();
        assert_eq!(result_nibble, expected_nibble);
        assert_eq!(result_nibbles, EMPTY_NIBBLES);
    }

    #[test]
    fn should_split_at_first_nibble_from_empty_nibbles_correctly() {
        let (result_nibble, result_nibbles) = split_at_first_nibble(&EMPTY_NIBBLES).unwrap();
        assert_eq!(result_nibble, EMPTY_NIBBLES);
        assert_eq!(result_nibbles, EMPTY_NIBBLES);
    }
}
