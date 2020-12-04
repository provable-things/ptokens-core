use crate::{
    chains::eth::{eth_database_utils::get_eth_private_key_from_db, eth_types::EthSignature},
    traits::DatabaseInterface,
    types::Result,
};
use serde_json::{json, Value as JsonValue};

fn encode_eth_signed_message_as_json(message: &str, signature: &EthSignature) -> Result<JsonValue> {
    info!("✔ Encoding eth signed message as json...");
    Ok(json!({"message": message, "signature": format!("0x{}", hex::encode(&signature[..]))}))
}

#[allow(dead_code)]
pub fn sign_message_with_eth_key<D, T>(db: &D, message: T) -> Result<JsonValue>
where
    D: DatabaseInterface,
    T: Into<String>,
{
    let message = message.into();
    info!("✔ Checking message is valid ASCII...");
    if !message.is_ascii() {
        return Err("✘ Non-ASCII message passed. Only valid ASCII messages are supported.".into());
    }
    let eth_private_key = get_eth_private_key_from_db(db)?;
    info!("✔ Signing message with eth key...");
    let signature = eth_private_key.sign_message_bytes(message.as_bytes())?;
    encode_eth_signed_message_as_json(&message, &signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        btc_on_eth::eth::eth_test_utils::get_sample_eth_private_key,
        chains::eth::eth_database_utils::put_eth_private_key_in_db,
        test_utils::get_test_database,
    };

    #[test]
    fn should_return_error_if_message_is_not_valid_ascii() {
        let db = get_test_database();
        let message = "Grüße, 🦀";
        assert!(sign_message_with_eth_key(&db, message).is_err());
    }

    #[test]
    fn should_sign_arbitrary_message() {
        let db = get_test_database();
        let eth_private_key = get_sample_eth_private_key();

        if let Err(e) = put_eth_private_key_in_db(&db, &eth_private_key) {
            panic!("Error putting eth private key in db: {}", e);
        }

        let message = "Arbitrary message";
        let valid_json = json!({
            "message": "Arbitrary message",
            "signature": "0x15a75ee16c085117190c8efbcd349cd5a1a8014fe454954d0e1a80210e3d5b7c1a455fba5da51471045e53e297f6d0837099aba65d4d5c5b98ae60fa42ca443d00"
        });

        assert_eq!(
            sign_message_with_eth_key(&db, message).unwrap(),
            valid_json,
            "✘ Message signature is invalid!"
        )
    }

    #[test]
    fn should_encode_eth_signed_message_as_json() {
        let valid_json = json!({
            "message": "Arbitrary message",
            "signature": "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        });
        assert_eq!(
            encode_eth_signed_message_as_json("Arbitrary message", &[0u8; 65]).unwrap(),
            valid_json,
            "✘ Message signature json is invalid!"
        )
    }
}
