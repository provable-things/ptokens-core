use serde_json::Value;
use ethereum_types::{
    U256,
    H256,
    Address as EthAddress
};
use crate::{
    types::{Byte, Bytes, NoneError, Result},
    btc_on_eth::constants::{
        HASH_LENGTH,
        U64_NUM_BYTES,
        BTC_NUM_DECIMALS,
        SAFE_ETH_ADDRESS,
        PTOKEN_ERC777_NUM_DECIMALS,
    },
};

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

pub fn convert_u64_to_bytes(u_64: u64) -> Bytes {
    u_64.to_le_bytes().to_vec()
}

pub fn strip_new_line_chars(string: String) -> String {
    string.replace("\n", "")
}

pub fn convert_dec_str_to_u256(dec_str: &str) -> Result<U256> {
    match U256::from_dec_str(dec_str) {
        Ok(u256) => Ok(u256),
        Err(err) => Err(format!("✘ Error converting decimal string to u256:\n{:?}", err).into())
    }
}

pub fn convert_h256_to_bytes(hash: H256) -> Bytes {
    hash.as_bytes().to_vec()
}

pub fn convert_bytes_to_h256(bytes: &[Byte]) -> Result<H256> {
    match bytes.len() {
        32 => Ok(H256::from_slice(&bytes[..])),
        _ => Err("✘ Not enough bytes to convert to h256!".into())
    }
}

pub fn convert_json_value_to_string(value: Value) -> Result<String> {
    Ok(value.as_str().ok_or(NoneError("Could not unwrap. JSON value isn't a String!"))?.to_string())
}

fn left_pad_with_zero(string: &str) -> Result<String> {
    Ok(format!("0{}", string))
}

pub fn strip_hex_prefix(prefixed_hex : &str) -> Result<String> {
    let res = str::replace(prefixed_hex, "0x", "");
    match res.len() % 2 {
        0 => Ok(res),
        _ => left_pad_with_zero(&res),
    }
}

pub fn decode_hex(hex_to_decode: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(hex_to_decode)?)
}

pub fn decode_prefixed_hex(hex_to_decode: &str) -> Result<Vec<u8>> {
    strip_hex_prefix(&hex_to_decode).and_then(|hex| decode_hex(&hex))
}

pub fn get_not_in_state_err(substring: &str) -> String {
    format!("✘ No {} in state!" , substring)
}

pub fn get_no_overwrite_state_err(substring: &str) -> String {
    format!("✘ Cannot overwrite {} in state!" , substring)
}

pub fn convert_hex_to_bytes(hex: &str) -> Result<Bytes> {
    Ok(hex::decode(strip_hex_prefix(&hex)?)?)
}

pub fn safely_convert_hex_to_eth_address(hex: &str) -> Result<EthAddress> {
    match convert_hex_to_address(hex) {
        Ok(address) => Ok(address),
        Err(_) => {
            info!("✔ Could not parse hex: '{}'!", hex);
            info!("✔ Defaulting to safe eth address: 0x{}", hex::encode(SAFE_ETH_ADDRESS.as_bytes()));
            Ok(*SAFE_ETH_ADDRESS)
        }
    }
}

pub fn convert_hex_to_address(hex: &str) -> Result<EthAddress> { // TODO take str & rename to have ETH in it!
    Ok(EthAddress::from_slice(&decode_prefixed_hex(hex)?))
}

pub fn convert_hex_to_h256(hex: &str) -> Result<H256> {
    decode_prefixed_hex(hex)
        .and_then(|bytes| match bytes.len() {
            HASH_LENGTH => Ok(H256::from_slice(&bytes)),
            _ => Err(format!("✘ {} bytes required to create h256 type, {} provided!", HASH_LENGTH, bytes.len()).into())
        })
}

pub fn convert_hex_strings_to_h256s(hex_strings: Vec<&str>) -> Result<Vec<H256>> {
    let hashes: Result<Vec<H256>> = hex_strings.into_iter().map(convert_hex_to_h256).collect();
    Ok(hashes?)
}

pub fn convert_satoshis_to_ptoken(satoshis: u64) -> U256 {
    U256::from(satoshis) * U256::from(10u64.pow(PTOKEN_ERC777_NUM_DECIMALS - BTC_NUM_DECIMALS))
}

pub fn convert_ptoken_to_satoshis(ptoken: U256) -> u64 {
    match ptoken.checked_div(U256::from(10u64.pow(PTOKEN_ERC777_NUM_DECIMALS - BTC_NUM_DECIMALS))) {
        Some(amount) => amount.as_u64(),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        errors::AppError,
        btc_on_eth::eth::eth_test_utils::{
            HASH_HEX_CHARS,
            HEX_PREFIX_LENGTH,
        },
    };

    #[test]
    fn should_convert_satoshis_to_ptoken() {
        let satoshis = 1337;
        let expected_result = U256::from_dec_str("13370000000000").unwrap();
        let result = convert_satoshis_to_ptoken(satoshis);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_ptoken_to_satoshis() {
        let ptoken = U256::from_dec_str("13370000000000").unwrap();
        let expected_result = 1337;
        let result = convert_ptoken_to_satoshis(ptoken);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_decode_none_prefixed_hex_correctly() {
        let none_prefixed_hex = "c0ffee";
        assert!(!none_prefixed_hex.contains('x'));
        let expected_result = [192, 255, 238];
        let result = decode_hex(none_prefixed_hex).unwrap();
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_left_pad_string_with_zero_correctly() {
        let dummy_hex = "0xc0ffee";
        let expected_result = "00xc0ffee".to_string();
        let result = left_pad_with_zero(dummy_hex).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_strip_hex_prefix_correctly() {
        let dummy_hex = "0xc0ffee";
        let expected_result = "c0ffee".to_string();
        let result = strip_hex_prefix(dummy_hex).unwrap();
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_not_strip_missing_hex_prefix_correctly() {
        let dummy_hex = "c0ffee";
        let expected_result = "c0ffee".to_string();
        let result = strip_hex_prefix(dummy_hex).unwrap();
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_convert_hex_to_address_correctly() {
        let address_hex = "0xb2930b35844a230f00e51431acae96fe543a0347";
        let result = convert_hex_to_address(address_hex).unwrap();
        let expected_result = decode_prefixed_hex(address_hex).unwrap();
        let expected_result_bytes = &expected_result[..];
        assert_eq!(result.as_bytes(), expected_result_bytes);
    }

    #[test]
    fn should_fail_to_convert_bad_hex_to_address_correctly() {
        let bad_hex = "https://somewhere.com/address/0xb2930b35844a230f00e51431acae96fe543a0347";
        let result = convert_hex_to_address(bad_hex);
        assert!(result.is_err());
    }

    #[test]
    fn should_safely_convert_hex_to_eth_address_correctly() {
        let address_hex = "0xb2930b35844a230f00e51431acae96fe543a0347";
        let result = safely_convert_hex_to_eth_address(address_hex).unwrap();
        let expected_result = decode_prefixed_hex(address_hex).unwrap();
        let expected_result_bytes = &expected_result[..];
        assert_eq!(result.as_bytes(), expected_result_bytes);
    }

    #[test]
    fn should_revert_to_safe_eth_address_when_safely_convert_bad_hex_to_eth_address() {
        let bad_hex = "https://somewhere.com/address/0xb2930b35844a230f00e51431acae96fe543a0347";
        let result = safely_convert_hex_to_eth_address(bad_hex).unwrap();
        assert_eq!(result, *SAFE_ETH_ADDRESS);
    }

    #[test]
    fn should_convert_unprefixed_hex_to_bytes_correctly() {
        let hex = "c0ffee";
        let expected_result = [ 192, 255, 238 ];
        let result = convert_hex_to_bytes(hex).unwrap();
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_convert_prefixed_hex_to_bytes_correctly() {
        let hex = "0xc0ffee";
        let expected_result = [ 192, 255, 238 ];
        let result = convert_hex_to_bytes(hex).unwrap();
        assert_eq!(result, expected_result)
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
    fn should_decode_prefixed_hex_correctly() {
        let prefixed_hex = "0xc0ffee";
        let mut chars = prefixed_hex.chars();
        assert_eq!("0", chars.next().unwrap().to_string());
        assert_eq!("x", chars.next().unwrap().to_string());
        let expected_result = [192, 255, 238];
        let result = decode_prefixed_hex(prefixed_hex).unwrap();
        assert_eq!(result, expected_result)
    }
        #[test]
    fn should_convert_hex_to_h256_correctly() {
        let dummy_hash = "0xc5acf860fa849b72fc78855dcbc4e9b968a8af5cdaf79f03beeca78e6a9cec8b";
        assert_eq!(dummy_hash.len(), HASH_HEX_CHARS + HEX_PREFIX_LENGTH);
        let result = convert_hex_to_h256(dummy_hash).unwrap();
        let expected_result = decode_prefixed_hex(dummy_hash).unwrap();
        let expected_result_bytes = &expected_result[..];
        assert_eq!(result.as_bytes(), expected_result_bytes);
    }

    #[test]
    fn should_fail_to_convert_short_hex_to_h256_correctly() {
        let short_hash = "0xc5acf860fa849b72fc78855dcbc4e9b968a8af5cdaf79f03beeca78e6a9cec";
        let expected_error = format!(
            "✘ {} bytes required to create h256 type, {} provided!",
            HASH_LENGTH,
            hex::decode(&short_hash[2..]).unwrap().len(),
        );
        assert!(short_hash.len() < HASH_HEX_CHARS + HEX_PREFIX_LENGTH);
        match convert_hex_to_h256(short_hash) {
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            _ => panic!("Should have errored ∵ of short hash!")
        }
    }

    #[test]
    fn should_fail_to_convert_long_hex_to_h256_correctly() {
        let long_hash = "0xc5acf860fa849b72fc78855dcbc4e9b968a8af5cdaf79f03beeca78e6a9cecffff";
        let expected_error = format!(
            "✘ {} bytes required to create h256 type, {} provided!",
            HASH_LENGTH,
            hex::decode(&long_hash[2..]).unwrap().len(),
        );
        assert!(long_hash.len() > HASH_HEX_CHARS + HEX_PREFIX_LENGTH);
        match convert_hex_to_h256(long_hash) {
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            _ => panic!("Should have errored ∵ of short hash!")
        }
    }

    #[test]
    fn should_fail_to_convert_invalid_hex_to_h256_correctly() {
        let long_hash = "0xc5acf860fa849b72fc78855dcbc4e9b968a8af5cdaf79f03beeca78e6a9cecffzz";
        assert!(long_hash.len() > HASH_HEX_CHARS + HEX_PREFIX_LENGTH);
        assert!(long_hash.contains('z'));
        match convert_hex_to_h256(long_hash) {
            Err(AppError::HexError(e)) => assert!(e.to_string().contains("Invalid")),
            Err(AppError::Custom(_)) => panic!("Should be hex error!"),
            _ => panic!("Should have errored ∵ of invalid hash!")
        }
    }

    #[test]
    fn should_convert_hex_strings_to_h256s() {
        let str1 = "0xebfa2e7610ea186fa3fa97bbaa5db80cce033dfff7e546c6ee05493dbcbfda7a";
        let str2 = "0x08075826de57b85238fe1728a37b366ab755b95c65c59faec7b0f1054fca1654";
        let expected_result1 = convert_hex_to_h256(str1).unwrap();
        let expected_result2 = convert_hex_to_h256(str2).unwrap();
        let hex_strings: Vec<&str> = vec!(str1, str2);
        let results: Vec<H256> = convert_hex_strings_to_h256s(hex_strings).unwrap();
        assert_eq!(results[0], expected_result1);
        assert_eq!(results[1], expected_result2);
    }

    #[test]
    fn should_convert_h256_to_bytes() {
        let hash = H256::zero();
        let expected_result = vec![
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
        ];
        let result = convert_h256_to_bytes(hash);
        assert_eq!(expected_result, result);
    }

    #[test]
    fn should_convert_bytes_to_h256() {
        let hex = "ebfa2e7610ea186fa3fa97bbaa5db80cce033dfff7e546c6ee05493dbcbfda7a";
        let expected_result = convert_hex_to_h256(hex).unwrap();
        let bytes = hex::decode(hex).unwrap();
        let result = convert_bytes_to_h256(&bytes).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_decimal_string_to_u256() {
        let expected_result = 1337;
        let dec_str = "1337";
        let result = convert_dec_str_to_u256(dec_str).unwrap();
        assert_eq!(result.as_usize(), expected_result);
    }

    #[test]
    fn should_fail_to_convert_non_decimal_string_to_u256() {
        let expected_error = "✘ Error converting decimal string";
        let dec_str = "abcd";
        match convert_dec_str_to_u256(dec_str) {
            Err(AppError::Custom(e)) => assert!(e.contains(expected_error)),
            _ => panic!("Should not have converted non decimal string!")
        }
    }

    #[test]
    fn should_strip_newline_chars() {
        let new_line_char = "\n";
        let string = "a string".to_string();
        let test_vector = format!("{}{}", string, new_line_char);
        let length_before = test_vector.len();
        assert!(test_vector.contains(new_line_char));
        let result = strip_new_line_chars(string);
        let length_after = result.len();
        assert!(length_after < length_before);
        assert_eq!(length_after, length_before - new_line_char.len());
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
        let result = convert_bytes_to_u64(&bytes).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_error_converting_too_few_bytes_to_u64() {
        let expected_error = "✘ Not enough bytes to convert to u64!".to_string();
        let bytes = vec![255,255,255,255,255,255,255];
        assert!(bytes.len() < U64_NUM_BYTES);
        match  convert_bytes_to_u64(&bytes) {
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            Ok(_) => panic!("Shouldn't work!"),
            _ => panic!("Wrong error!"),
        }
    }

    #[test]
    fn should_error_converting_too_many_bytes_to_u64() {
        let expected_error = "✘ Too many bytes to convert to u64 without overflowing!".to_string();
        let bytes = vec![255,255,255,255,255,255,255,255,255];
        assert!(bytes.len() > U64_NUM_BYTES);
        match  convert_bytes_to_u64(&bytes) {
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            Ok(_) => panic!("Shouldn't work!"),
            _ => panic!("Wrong error!"),
        }
    }
}
