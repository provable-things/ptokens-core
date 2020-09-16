pub use serde_json::{
    json,
    Value as JsonValue,
};
use crate::utils::get_prefixed_db_key;

pub const PRODUCER_REPS: u64 = 12;
pub const PUBLIC_KEY_SIZE: usize = 33;
pub const PBTC_MINT_FXN_NAME: &str = "issue";
pub const REDEEM_ACTION_NAME: &str = "redeem";
pub const PUBLIC_KEY_CHECKSUM_SIZE: usize = 4;
pub const MEMO: &str = "BTC -> pBTC complete!";
pub const EOS_SCHEDULE_DB_PREFIX: &str = "EOS_SCHEDULE_";
pub const PEOS_ACCOUNT_PERMISSION_LEVEL: &str = "active";
pub const PUBLIC_KEY_WITH_CHECKSUM_SIZE: usize = PUBLIC_KEY_SIZE + PUBLIC_KEY_CHECKSUM_SIZE;
// NOTE: We use 59 minutes rather than 60 to give a little wiggle room for the clocks on the TEE devices.
pub const EOS_MAX_EXPIRATION_SECS: u32 = 3540;

pub fn get_eos_constants_db_keys() -> JsonValue {
    json!({
        "EOS_INCREMERKLE": hex::encode(EOS_INCREMERKLE.to_vec()),
        "EOS_ACCOUNT_NONCE": hex::encode(EOS_ACCOUNT_NONCE.to_vec()),
        "EOS_SCHEDULE_LIST": hex::encode(EOS_SCHEDULE_LIST.to_vec()),
        "EOS_CHAIN_ID_DB_KEY": hex::encode(EOS_CHAIN_ID_DB_KEY.to_vec()),
        "PROCESSED_TX_IDS_KEY": hex::encode(PROCESSED_TX_IDS_KEY.to_vec()),
        "EOS_ACCOUNT_NAME_KEY": hex::encode(EOS_ACCOUNT_NAME_KEY.to_vec()),
        "EOS_TOKEN_SYMBOL_KEY": hex::encode(EOS_TOKEN_SYMBOL_KEY.to_vec()),
        "EOS_PROTOCOL_FEATURES": hex::encode(EOS_PROTOCOL_FEATURES.to_vec()),
        "EOS_LAST_SEEN_BLOCK_ID": hex::encode(EOS_LAST_SEEN_BLOCK_ID.to_vec()),
        "EOS_PRIVATE_KEY_DB_KEY": hex::encode(EOS_PRIVATE_KEY_DB_KEY.to_vec()),
        "EOS_LAST_SEEN_BLOCK_NUM": hex::encode(EOS_LAST_SEEN_BLOCK_NUM.to_vec()),
    })
}

lazy_static! { pub static ref PROCESSED_TX_IDS_KEY: [u8; 32] = get_prefixed_db_key("eos-tx-ids"); }
lazy_static! { pub static ref EOS_INCREMERKLE: [u8; 32] = get_prefixed_db_key("eos-incremerkle"); }
lazy_static! { pub static ref EOS_ACCOUNT_NONCE: [u8; 32] = get_prefixed_db_key("eos-account-nonce"); }
lazy_static! { pub static ref EOS_SCHEDULE_LIST: [u8; 32] = get_prefixed_db_key("eos-schedule-list"); }
lazy_static! { pub static ref EOS_CHAIN_ID_DB_KEY: [u8; 32] = get_prefixed_db_key("eos-chain-id-key"); }
lazy_static! { pub static ref EOS_TOKEN_SYMBOL_KEY: [u8; 32] = get_prefixed_db_key("eos-token-ticker"); }
lazy_static! { pub static ref EOS_ACCOUNT_NAME_KEY: [u8; 32] = get_prefixed_db_key("eos-account-name"); }
lazy_static! { pub static ref EOS_PROTOCOL_FEATURES: [u8; 32] = get_prefixed_db_key("eos-protocol-features"); }
lazy_static! { pub static ref EOS_PRIVATE_KEY_DB_KEY: [u8; 32] = get_prefixed_db_key("eos-private-key-db-key"); }
lazy_static! { pub static ref EOS_LAST_SEEN_BLOCK_ID: [u8; 32] = get_prefixed_db_key("eos-last-seen-block-id"); }
lazy_static! { pub static ref EOS_LAST_SEEN_BLOCK_NUM: [u8; 32] = get_prefixed_db_key("eos-last-seen-block-num"); }
