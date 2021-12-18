use ethereum_types::H256 as EthHash;
pub use serde_json::{json, Value as JsonValue};

use crate::{chains::evm::nibble_utils::Nibbles, types::Byte, utils::get_prefixed_db_key};

pub const ZERO_BYTE: u8 = 0u8;
pub const ETH_TAIL_LENGTH: u64 = 100;
pub const HIGH_NIBBLE_MASK: Byte = 15u8; // NOTE: 15u8 == [0,0,0,0,1,1,1,1]
pub const NUM_BITS_IN_NIBBLE: usize = 4;
pub const NUM_NIBBLES_IN_BYTE: usize = 2;
pub static LEAF_NODE_STRING: &str = "leaf";
pub static BRANCH_NODE_STRING: &str = "branch";
pub static EXTENSION_NODE_STRING: &str = "extension";
pub const HASHED_NULL_NODE: EthHash = EthHash(HASHED_NULL_NODE_BYTES);
pub const ETH_CORE_IS_INITIALIZED_JSON: &str = "{evm_core_initialized:true}";
pub const EMPTY_NIBBLES: Nibbles = Nibbles {
    data: vec![],
    offset: 0,
};
pub const ERC20_VAULT_PEG_IN_EVENT_WITHOUT_USER_DATA_TOPIC_HEX: &str =
    "42877668473c4cba073df41397388516dc85c3bbae14b33603513924cec55e36";
pub const ETH_MESSAGE_PREFIX: &[u8; 26] = b"\x19Ethereum Signed Message:\n";
pub const PREFIXED_MESSAGE_HASH_LEN: &[u8; 2] = b"32";

lazy_static! {
    pub static ref ERC20_VAULT_PEG_IN_EVENT_WITHOUT_USER_DATA_TOPIC: [EthHash; 1] = {
        [EthHash::from_slice(
            &hex::decode(ERC20_VAULT_PEG_IN_EVENT_WITHOUT_USER_DATA_TOPIC_HEX)
                .expect("✘ Invalid hex in `ERC20_VAULT_PEG_IN_EVENT_WITHOUT_USER_DATA_TOPIC`!"),
        )]
    };
}

const HASHED_NULL_NODE_BYTES: [u8; 32] = [
    // NOTE: keccak hash of the RLP of null
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e, 0x5b, 0x48, 0xe0,
    0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

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
        "ERC20_ON_EOS_SMART_CONTRACT_ADDRESS_KEY": hex::encode(ERC20_ON_EOS_SMART_CONTRACT_ADDRESS_KEY.to_vec()),
    })
}

lazy_static! {
    pub static ref ETH_CHAIN_ID_KEY: [u8; 32] = get_prefixed_db_key("evm-chain-id");
    pub static ref ETH_GAS_PRICE_KEY: [u8; 32] = get_prefixed_db_key("evm-gas-price");
    pub static ref ETH_ADDRESS_KEY: [u8; 32] = get_prefixed_db_key("evm-address-key");
    pub static ref ETH_LINKER_HASH_KEY: [u8; 32] = get_prefixed_db_key("evm-linker-hash-key");
    pub static ref ANY_SENDER_NONCE_KEY: [u8; 32] = get_prefixed_db_key("evm-any-sender-nonce");
    pub static ref ETH_ACCOUNT_NONCE_KEY: [u8; 32] = get_prefixed_db_key("evm-account-nonce");
    pub static ref PTOKEN_GENESIS_HASH_KEY: [u8; 32] = get_prefixed_db_key("evm-provable-ptoken");
    pub static ref ETH_PRIVATE_KEY_DB_KEY: [u8; 32] = get_prefixed_db_key("evm-private-key-key");
    pub static ref ETH_CANON_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key("evm-canon-block-hash-key");
    pub static ref ETH_TAIL_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key("evm-tail-block-hash-key");
    pub static ref ETH_ANCHOR_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key("evm-anchor-block-hash-key");
    pub static ref ETH_LATEST_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key("evm-latest-block-hash-key");
    pub static ref ETH_CANON_TO_TIP_LENGTH_KEY: [u8; 32] = get_prefixed_db_key("evm-canon-to-tip-length-key");
    pub static ref BTC_ON_ETH_SMART_CONTRACT_ADDRESS_KEY: [u8; 32] = get_prefixed_db_key("evm-smart-contract");
    pub static ref ERC777_PROXY_CONTACT_ADDRESS_KEY: [u8; 32] =
        get_prefixed_db_key("evm-erc-777-proxy-contract-address-key");
    pub static ref ERC20_ON_EOS_SMART_CONTRACT_ADDRESS_KEY: [u8; 32] =
        get_prefixed_db_key("evm-erc20-on-eos-smart-contract-address-key");
    pub static ref EOS_ON_ETH_SMART_CONTRACT_ADDRESS_KEY: [u8; 32] =
        get_prefixed_db_key("evm-eos-on-eth-smart-contract-address-key");
}
