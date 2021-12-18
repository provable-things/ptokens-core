pub use serde_json::{json, Value as JsonValue};

use crate::utils::get_prefixed_db_key;

pub const ZERO_ETH_VALUE: usize = 0;
pub const ETH_TAIL_LENGTH: u64 = 100;
pub const VALUE_FOR_MINTING_TX: usize = 0;
pub const VALUE_FOR_PTOKEN_DEPLOY: usize = 0;
pub const ETH_WORD_SIZE_IN_BYTES: usize = 32;
pub const ETH_ADDRESS_SIZE_IN_BYTES: usize = 20;
pub const MAX_BYTES_FOR_ETH_USER_DATA: usize = 2000;
pub const GAS_LIMIT_FOR_MINTING_TX: usize = 180_000;
pub const GAS_LIMIT_FOR_PTOKEN_DEPLOY: usize = 4_000_000;
pub const ETH_CORE_IS_INITIALIZED_JSON: &str = "{eth_core_initialized:true}";
pub const ETH_MESSAGE_PREFIX: &[u8; 26] = b"\x19Ethereum Signed Message:\n";
pub const PREFIXED_MESSAGE_HASH_LEN: &[u8; 2] = b"32";

pub fn get_eth_constants_db_keys() -> JsonValue {
    json!({
        "ETH_ADDRESS_KEY": hex::encode(ETH_ADDRESS_KEY.to_vec()),
        "ETH_CHAIN_ID_KEY": hex::encode(ETH_CHAIN_ID_KEY.to_vec()),
        "ETH_GAS_PRICE_KEY": hex::encode(ETH_GAS_PRICE_KEY.to_vec()),
        "ETH_LINKER_HASH_KEY": hex::encode(ETH_LINKER_HASH_KEY.to_vec()),
        "ANY_SENDER_NONCE_KEY": hex::encode(ANY_SENDER_NONCE_KEY.to_vec()),
        "ETH_ACCOUNT_NONCE_KEY": hex::encode(ETH_ACCOUNT_NONCE_KEY.to_vec()),
        "ETH_PRIVATE_KEY_DB_KEY": hex::encode(ETH_PRIVATE_KEY_DB_KEY.to_vec()),
        "ETH_TAIL_BLOCK_HASH_KEY": hex::encode(ETH_TAIL_BLOCK_HASH_KEY.to_vec()),
        "PTOKEN_GENESIS_HASH_KEY": hex::encode(PTOKEN_GENESIS_HASH_KEY.to_vec()),
        "ETH_CANON_BLOCK_HASH_KEY": hex::encode(ETH_CANON_BLOCK_HASH_KEY.to_vec()),
        "ETH_ANCHOR_BLOCK_HASH_KEY": hex::encode(ETH_ANCHOR_BLOCK_HASH_KEY.to_vec()),
        "ETH_LATEST_BLOCK_HASH_KEY": hex::encode(ETH_LATEST_BLOCK_HASH_KEY.to_vec()),
        "ETH_CANON_TO_TIP_LENGTH_KEY": hex::encode(ETH_CANON_TO_TIP_LENGTH_KEY.to_vec()),
        "ERC777_PROXY_CONTACT_ADDRESS_KEY": hex::encode(ERC777_PROXY_CONTACT_ADDRESS_KEY.to_vec()),
        "BTC_ON_ETH_SMART_CONTRACT_ADDRESS_KEY": hex::encode(BTC_ON_ETH_SMART_CONTRACT_ADDRESS_KEY.to_vec()),
        "EOS_ON_ETH_SMART_CONTRACT_ADDRESS_KEY": hex::encode(EOS_ON_ETH_SMART_CONTRACT_ADDRESS_KEY.to_vec()),
        "ERC20_ON_EVM_SMART_CONTRACT_ADDRESS_KEY": hex::encode(ERC20_ON_EVM_SMART_CONTRACT_ADDRESS_KEY.to_vec()),
        "ERC20_ON_EOS_SMART_CONTRACT_ADDRESS_KEY": hex::encode(ERC20_ON_EOS_SMART_CONTRACT_ADDRESS_KEY.to_vec()),
    })
}

lazy_static! {
    pub static ref ETH_CHAIN_ID_KEY: [u8; 32] = get_prefixed_db_key("eth-chain-id");
    pub static ref ETH_GAS_PRICE_KEY: [u8; 32] = get_prefixed_db_key("eth-gas-price");
    pub static ref ETH_ADDRESS_KEY: [u8; 32] = get_prefixed_db_key("eth-address-key");
    pub static ref ETH_LINKER_HASH_KEY: [u8; 32] = get_prefixed_db_key("linker-hash-key");
    pub static ref ANY_SENDER_NONCE_KEY: [u8; 32] = get_prefixed_db_key("any-sender-nonce");
    pub static ref ETH_ACCOUNT_NONCE_KEY: [u8; 32] = get_prefixed_db_key("eth-account-nonce");
    pub static ref PTOKEN_GENESIS_HASH_KEY: [u8; 32] = get_prefixed_db_key("provable-ptoken");
    pub static ref ETH_PRIVATE_KEY_DB_KEY: [u8; 32] = get_prefixed_db_key("eth-private-key-key");
    pub static ref ETH_CANON_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key("canon-block-hash-key");
    pub static ref ETH_TAIL_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key("eth-tail-block-hash-key");
    pub static ref ETH_ANCHOR_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key("anchor-block-hash-key");
    pub static ref ETH_LATEST_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key("latest-block-hash-key");
    pub static ref ETH_CANON_TO_TIP_LENGTH_KEY: [u8; 32] = get_prefixed_db_key("canon-to-tip-length-key");
    pub static ref BTC_ON_ETH_SMART_CONTRACT_ADDRESS_KEY: [u8; 32] = get_prefixed_db_key("eth-smart-contract");
    pub static ref ERC777_PROXY_CONTACT_ADDRESS_KEY: [u8; 32] =
        get_prefixed_db_key("erc-777-proxy-contract-address-key");
    pub static ref ERC20_ON_EOS_SMART_CONTRACT_ADDRESS_KEY: [u8; 32] =
        get_prefixed_db_key("erc20-on-eos-smart-contract-address-key");
    pub static ref EOS_ON_ETH_SMART_CONTRACT_ADDRESS_KEY: [u8; 32] =
        get_prefixed_db_key("eos-on-eth-smart-contract-address-key");
    pub static ref ERC20_ON_EVM_SMART_CONTRACT_ADDRESS_KEY: [u8; 32] =
        get_prefixed_db_key("erc20-on-evm-eth-smart-contract-address-key");
}
