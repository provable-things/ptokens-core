use serde_json::{json, Value as JsonValue};

use crate::{
    chains::{
        eth::eth_traits::EthSigningCapabilities,
        evm::{eth_database_utils::get_eth_private_key_from_db, eth_types::EthSignature},
    },
    traits::DatabaseInterface,
    types::Result,
    utils::decode_hex_with_err_msg,
};

fn encode_eth_signed_message_as_json(message: &str, signature: &EthSignature) -> JsonValue {
    info!("✔ Encoding eth signed message as json...");
    json!({"message": message, "signature": format!("0x{}", hex::encode(&signature[..]))})
}

/// # Sign ASCII Message With ETH Key
///
/// Signs a given ASCII message with the ETH private key from the encrypted database. The function first
/// checks if the message to be signed is valid ASCII, and errors if not. This signing function
/// uses a recoverable `secp256k1` signature scheme with NO prefix prepended to the message.
pub fn sign_ascii_msg_with_eth_key_with_no_prefix<D: DatabaseInterface>(db: &D, message: &str) -> Result<String> {
    info!("✔ Checking message is valid ASCII...");
    if !message.is_ascii() {
        return Err("✘ Non-ASCII message passed. Only valid ASCII messages are supported.".into());
    }
    get_eth_private_key_from_db(db)
        .and_then(|key| key.sign_message_bytes(message.as_bytes()))
        .map(|signature| encode_eth_signed_message_as_json(message, &signature).to_string())
}

/// # Sign HEX Message With ETH Key
///
/// Signs a given HEX message with the ETH private key from the encrypted database. The function first
/// checks if the message to be signed is valid HEX, and errors if not. This signing function uses
/// a recoverable `secp256k1` signature scheme with the ethereum-specific prefix:
///
/// ```no_compile
/// "\x19Ethereum Signed Message:\n32"
/// ```
///
/// prepended to the message before signing.
pub fn sign_hex_msg_with_eth_key_with_prefix<D: DatabaseInterface>(db: &D, message: &str) -> Result<String> {
    decode_hex_with_err_msg(message, "Message to sign is NOT valid hex!")
        .and_then(|bytes| {
            let key = get_eth_private_key_from_db(db)?;
            key.sign_eth_prefixed_msg_bytes(&bytes)
        })
        .map(|signature| encode_eth_signed_message_as_json(message, &signature).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::evm::{eth_database_utils::put_eth_private_key_in_db, eth_test_utils::get_sample_eth_private_key},
        errors::AppError,
        test_utils::get_test_database,
    };

    #[test]
    fn should_return_error_if_message_is_not_valid_ascii() {
        let db = get_test_database();
        let message = "Grüße, 🦀";
        assert!(sign_ascii_msg_with_eth_key_with_no_prefix(&db, message).is_err());
    }

    #[test]
    fn should_sign_ascii_msg_with_eth_key_with_no_prefix() {
        let db = get_test_database();
        let eth_private_key = get_sample_eth_private_key();
        put_eth_private_key_in_db(&db, &eth_private_key).unwrap();
        let message = "Arbitrary message";
        let expected_result = json!({
            "message": "Arbitrary message",
            "signature": "0x15a75ee16c085117190c8efbcd349cd5a1a8014fe454954d0e1a80210e3d5b7c1a455fba5da51471045e53e297f6d0837099aba65d4d5c5b98ae60fa42ca443d00"
        }).to_string();
        let result = sign_ascii_msg_with_eth_key_with_no_prefix(&db, message).unwrap();
        assert_eq!(result, expected_result, "✘ Message signature is invalid!")
    }

    #[test]
    fn should_encode_eth_signed_message_as_json() {
        let expected_result = json!({
            "message": "Arbitrary message",
            "signature": "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        });
        let result = encode_eth_signed_message_as_json("Arbitrary message", &[0u8; 65]);
        assert_eq!(result, expected_result, "✘ Message signature json is invalid!")
    }

    #[test]
    fn should_sign_hex_msg_with_eth_key_with_prefix() {
        let db = get_test_database();
        let eth_private_key = get_sample_eth_private_key();
        put_eth_private_key_in_db(&db, &eth_private_key).unwrap();
        let hex_to_sign = "0xc0ffee";
        let result = sign_hex_msg_with_eth_key_with_prefix(&db, &hex_to_sign).unwrap();
        let expected_result = json!({
            "message":"0xc0ffee",
            "signature":"0xb2ba6c72332f321a100d4a686f4ecc7d5fc13707b62b292ef36270981e4276d70dc177553bf719ab4bbec181ab7b5fe530437a149d9a9dec449f2aa42b7c1add1c"}).to_string();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_fail_to_sign_invalid_hex_msg_with_eth_key_with_prefix() {
        let db = get_test_database();
        let eth_private_key = get_sample_eth_private_key();
        put_eth_private_key_in_db(&db, &eth_private_key).unwrap();
        let invalid_hex_to_sign = "0xcoffee";
        let expected_err = "Message to sign is NOT valid hex! Invalid character \'o\' at position 1";
        match sign_hex_msg_with_eth_key_with_prefix(&db, &invalid_hex_to_sign) {
            Err(AppError::Custom(err)) => assert_eq!(err, expected_err),
            Ok(_) => panic!("Should not have succeeded!"),
            Err(_) => panic!("Got wrong error!"),
        };
    }
}
