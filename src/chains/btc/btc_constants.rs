pub use serde_json::{
    json,
    Value as JsonValue,
};
use crate::utils::get_prefixed_db_key;

#[cfg(test)] // NOTE Because of real BTC tx test-vectors
pub const PTOKEN_P2SH_SCRIPT_BYTES: usize = 0;

#[cfg(not(test))]
pub const PTOKEN_P2SH_SCRIPT_BYTES: usize = 101;

pub const BTC_TAIL_LENGTH: u64 = 10;
pub const MINIMUM_REQUIRED_SATOSHIS: u64 = 5000;
pub const DEFAULT_BTC_SEQUENCE: u32 = 4_294_967_295; // NOTE: 0xFFFFFFFF

// NOTE: Following is used as placeholder for bad address parsing in ETH params!
pub const DEFAULT_BTC_ADDRESS: &str = "msTgHeQgPZ11LRcUdtfzagEfiZyKF57DhR";

pub fn get_btc_constants_db_keys() -> JsonValue {
    json!({
        "BTC_DIFFICULTY":
            hex::encode(BTC_DIFFICULTY_THRESHOLD.to_vec()),
        "BTC_ADDRESS_KEY":
            hex::encode(BTC_ADDRESS_KEY.to_vec()),
        "BTC_CANON_BLOCK_HASH_KEY":
            hex::encode(BTC_CANON_BLOCK_HASH_KEY.to_vec()),
        "BTC_LATEST_BLOCK_HASH_KEY":
            hex::encode(BTC_LATEST_BLOCK_HASH_KEY.to_vec()),
        "BTC_LINKER_HASH_KEY":
            hex::encode(BTC_LINKER_HASH_KEY.to_vec()),
        "BTC_ANCHOR_BLOCK_HASH_KEY":
            hex::encode(BTC_ANCHOR_BLOCK_HASH_KEY.to_vec()),
        "BTC_PRIVATE_KEY_DB_KEY":
            hex::encode(BTC_PRIVATE_KEY_DB_KEY.to_vec()),
        "BTC_CANON_TO_TIP_LENGTH_KEY":
            hex::encode(BTC_CANON_TO_TIP_LENGTH_KEY.to_vec()),
        "PTOKEN_GENESIS_HASH":
            hex::encode(PTOKEN_GENESIS_HASH.to_vec()),
        "BTC_NETWORK_KEY":
            hex::encode(BTC_NETWORK_KEY.to_vec()),
        "BTC_FEE_KEY":
            hex::encode(BTC_FEE_KEY.to_vec()),
        "BTC_ACCOUNT_NONCE_KEY":
            hex::encode(BTC_ACCOUNT_NONCE_KEY.to_vec()),
        "BTC_TAIL_BLOCK_HASH_KEY":
            hex::encode(BTC_TAIL_BLOCK_HASH_KEY.to_vec()),
    })
}

lazy_static! {
    pub static ref BTC_DIFFICULTY_THRESHOLD: [u8; 32] = get_prefixed_db_key(
        "btc-difficulty"
    );
}

lazy_static! {
    pub static ref BTC_ADDRESS_KEY: [u8; 32] = get_prefixed_db_key(
        "btc-address"
    );
}

lazy_static! {
    pub static ref BTC_CANON_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key(
        "btc-canon-block"
    );
}

lazy_static! {
    pub static ref BTC_LATEST_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key(
        "btc-latest-block"
    );
}

lazy_static! {
    pub static ref BTC_LINKER_HASH_KEY: [u8; 32] = get_prefixed_db_key(
        "btc-linker-hash"
    );
}

lazy_static! {
    pub static ref BTC_ANCHOR_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key(
        "btc-anchor-block"
    );
}
lazy_static! {
    pub static ref BTC_PRIVATE_KEY_DB_KEY: [u8; 32] = get_prefixed_db_key(
        "btc-private-key"
    );
}

lazy_static! {
    pub static ref BTC_CANON_TO_TIP_LENGTH_KEY: [u8; 32] = get_prefixed_db_key(
        "btc-canon-to-tip-length"
    );
}

lazy_static! {
    pub static ref PTOKEN_GENESIS_HASH: [u8; 32] = get_prefixed_db_key(
        "provable-ptoken"
    );
}

lazy_static! {
    pub static ref BTC_NETWORK_KEY: [u8; 32] = get_prefixed_db_key(
        "btc-network-key"
    );
}

lazy_static! {
    pub static ref BTC_FEE_KEY: [u8; 32] = get_prefixed_db_key(
        "btc-fee-key"
    );
}

lazy_static! {
    pub static ref BTC_ACCOUNT_NONCE_KEY: [u8; 32] = get_prefixed_db_key(
        "btc-account-nonce-key"
    );
}

lazy_static! {
    pub static ref BTC_TAIL_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key(
        "btc-tail-block-hash-key"
    );
}
