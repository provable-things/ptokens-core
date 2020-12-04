use crate::utils::get_prefixed_db_key;
pub use serde_json::{json, Value as JsonValue};

pub fn get_utxo_constants_db_keys() -> JsonValue {
    json!({
        "UTXO_LAST":
            hex::encode(UTXO_LAST.to_vec()),
        "UTXO_FIRST":
            hex::encode(UTXO_FIRST.to_vec()),
        "UTXO_NONCE":
            hex::encode(UTXO_NONCE.to_vec()),
        "UTXO_BALANCE":
            hex::encode(UTXO_BALANCE.to_vec()),
    })
}

lazy_static! {
    pub static ref UTXO_FIRST: [u8; 32] = get_prefixed_db_key("utxo-first");
}

lazy_static! {
    pub static ref UTXO_LAST: [u8; 32] = get_prefixed_db_key("utxo-last");
}

lazy_static! {
    pub static ref UTXO_BALANCE: [u8; 32] = get_prefixed_db_key("utxo-balance");
}

lazy_static! {
    pub static ref UTXO_NONCE: [u8; 32] = get_prefixed_db_key("utxo-nonce");
}
