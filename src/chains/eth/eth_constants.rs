use ethereum_types::H256 as EthHash;
pub use serde_json::{
    json,
    Value as JsonValue,
};
use crate::{
    types::Byte,
    utils::get_prefixed_db_key,
    chains::eth::nibble_utils::Nibbles,
};

pub const ZERO_BYTE: u8 = 0u8;
pub const ZERO_ETH_VALUE: usize = 0;
pub const ETH_TAIL_LENGTH: u64 = 100;
pub const HIGH_NIBBLE_MASK: Byte = 15u8; // NOTE: 15u8 == [0,0,0,0,1,1,1,1]
pub const NUM_BITS_IN_NIBBLE: usize = 4;
pub const NUM_NIBBLES_IN_BYTE: usize = 2;
pub const VALUE_FOR_MINTING_TX: usize = 0;
pub static LEAF_NODE_STRING: &str = "leaf";
pub const VALUE_FOR_PTOKEN_DEPLOY: usize = 0;
pub const ETH_WORD_SIZE_IN_BYTES: usize = 32;
pub const ETH_ADDRESS_SIZE_IN_BYTES: usize = 20;
pub const GAS_LIMIT_FOR_MINTING_TX: usize = 120_000;
pub static BRANCH_NODE_STRING: &str = "branch";
pub const LOG_DATA_BTC_ADDRESS_START_INDEX: usize = 96;
pub const GAS_LIMIT_FOR_PTOKEN_DEPLOY: usize = 4_000_000;
pub static EXTENSION_NODE_STRING: &str = "extension";
pub const HASHED_NULL_NODE: EthHash = EthHash(HASHED_NULL_NODE_BYTES);
pub const EMPTY_NIBBLES: Nibbles = Nibbles { data: Vec::new(), offset: 0 };
pub const ERC20_PEG_IN_EVENT_TOPIC_HEX: &str = "42877668473c4cba073df41397388516dc85c3bbae14b33603513924cec55e36";
pub const BTC_ON_ETH_REDEEM_EVENT_TOPIC_HEX: &str = "78e6c3f67f57c26578f2487b930b70d844bcc8dd8f4d629fb4af81252ab5aa65";
pub const ETH_MESSAGE_PREFIX: &[u8; 26] = b"\x19Ethereum Signed Message:\n";
pub const PREFIXED_MESSAGE_HASH_LEN: &[u8; 2] = b"32";
pub const ETH_MAINNET_CHAIN_ID: u8 = 1;
pub const ETH_ROPSTEN_CHAIN_ID: u8 = 3;

#[cfg(not(test))]
lazy_static! {
    pub static ref BTC_ON_ETH_REDEEM_EVENT_TOPIC: [EthHash; 1] = {
        [
            EthHash::from_slice(&hex::decode(
                BTC_ON_ETH_REDEEM_EVENT_TOPIC_HEX
            ).expect("✘ Invalid hex in BTC_ON_ETH_REDEEM_EVENT_TOPIC")),
        ]
    };
}

lazy_static! {
    pub static ref ERC20_ON_EOS_PEG_IN_EVENT_TOPIC: [EthHash; 1] = {
        [
            EthHash::from_slice(&hex::decode(
                ERC20_PEG_IN_EVENT_TOPIC_HEX
            ).expect("✘ Invalid hex in PTOKEN_CONTRACT_TOPIC!")),
        ]
    };
}

#[cfg(test)]
lazy_static! {
    pub static ref BTC_ON_ETH_REDEEM_EVENT_TOPIC: [EthHash; 1] = {
        [
            EthHash::from_slice(&hex::decode(
            "fc62a6078634cc3b00bff541ac549ba6bfed8678765289f88f61e22c668198ba"
            ).expect("✘ Invalid hex in PTOKEN_CONTRACT_TOPIC!")),
        ]
    };
}

const HASHED_NULL_NODE_BYTES: [u8; 32] = [ // NOTE: keccak hash of the RLP of null
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21
];

pub fn get_eth_constants_db_keys() -> JsonValue {
    json!({
        "PTOKEN_GENESIS_HASH":
            hex::encode(PTOKEN_GENESIS_HASH.to_vec()),
        "ETH_CANON_TO_TIP_LENGTH_KEY":
            hex::encode(ETH_CANON_TO_TIP_LENGTH_KEY.to_vec()),
        "ETH_ANCHOR_BLOCK_HASH_KEY":
            hex::encode(ETH_ANCHOR_BLOCK_HASH_KEY.to_vec()),
        "ETH_LATEST_BLOCK_HASH_KEY":
            hex::encode(ETH_LATEST_BLOCK_HASH_KEY.to_vec()),
        "ETH_CANON_BLOCK_HASH_KEY":
            hex::encode(ETH_CANON_BLOCK_HASH_KEY.to_vec()),
        "ETH_LINKER_HASH_KEY":
            hex::encode(ETH_LINKER_HASH_KEY.to_vec()),
        "ETH_ACCOUNT_NONCE_KEY":
            hex::encode(ETH_ACCOUNT_NONCE_KEY.to_vec()),
        "BTC_ON_ETH_SMART_CONTRACT_ADDRESS_KEY":
            hex::encode(BTC_ON_ETH_SMART_CONTRACT_ADDRESS_KEY.to_vec()),
        "ERC20_ON_EOS_SMART_CONTRACT_ADDRESS_KEY":
            hex::encode(ERC20_ON_EOS_SMART_CONTRACT_ADDRESS_KEY.to_vec()),
        "ETH_ADDRESS_KEY":
            hex::encode(ETH_ADDRESS_KEY.to_vec()),
        "ETH_PRIVATE_KEY_DB_KEY":
            hex::encode(ETH_PRIVATE_KEY_DB_KEY.to_vec()),
        "ETH_CHAIN_ID_KEY":
            hex::encode(ETH_CHAIN_ID_KEY.to_vec()),
        "ETH_GAS_PRICE_KEY":
            hex::encode(ETH_GAS_PRICE_KEY.to_vec()),
        "ETH_TAIL_BLOCK_HASH_KEY":
            hex::encode(ETH_TAIL_BLOCK_HASH_KEY.to_vec()),
        "ANY_SENDER_NONCE_KEY":
            hex::encode(ANY_SENDER_NONCE_KEY.to_vec()),
        "ERC777_PROXY_CONTACT_ADDRESS_KEY":
            hex::encode(ERC777_PROXY_CONTACT_ADDRESS_KEY.to_vec()),
    })
}

lazy_static! {
    pub static ref PTOKEN_GENESIS_HASH: [u8; 32] = get_prefixed_db_key(
        "provable-ptoken"
    );
}

lazy_static! {
    pub static ref ETH_CANON_TO_TIP_LENGTH_KEY: [u8; 32] = get_prefixed_db_key(
        "canon-to-tip-length-key"
    );
}

lazy_static! {
    pub static ref ETH_ANCHOR_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key(
        "anchor-block-hash-key"
    );
}

lazy_static! {
    pub static ref ETH_LATEST_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key(
        "latest-block-hash-key"
    );
}

lazy_static! {
    pub static ref ETH_CANON_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key(
        "canon-block-hash-key"
    );
}

lazy_static! {
    pub static ref ETH_LINKER_HASH_KEY: [u8; 32] = get_prefixed_db_key(
        "linker-hash-key"
    );
}

lazy_static! {
    pub static ref ETH_ACCOUNT_NONCE_KEY: [u8; 32] = get_prefixed_db_key(
        "eth-account-nonce"
    );
}

lazy_static! {
    pub static ref BTC_ON_ETH_SMART_CONTRACT_ADDRESS_KEY: [u8; 32] = get_prefixed_db_key(
        "eth-smart-contract"
    );
}

lazy_static! {
    pub static ref ERC20_ON_EOS_SMART_CONTRACT_ADDRESS_KEY: [u8; 32] = get_prefixed_db_key(
        "erc20-on-eos-smart-contract-address-key"
    );
}

lazy_static! {
    pub static ref ETH_ADDRESS_KEY: [u8; 32] = get_prefixed_db_key(
        "eth-address-key"
    );
}

lazy_static! {
    pub static ref ETH_PRIVATE_KEY_DB_KEY: [u8; 32] = get_prefixed_db_key(
        "eth-private-key-key"
    );
}

lazy_static! {
    pub static ref ETH_CHAIN_ID_KEY: [u8; 32] = get_prefixed_db_key(
        "eth-chain-id"
    );
}

lazy_static! {
    pub static ref ETH_GAS_PRICE_KEY: [u8; 32] = get_prefixed_db_key(
        "eth-gas-price"
    );
}

lazy_static! {
    pub static ref ETH_TAIL_BLOCK_HASH_KEY: [u8; 32] = get_prefixed_db_key(
        "eth-tail-block-hash-key"
    );
}

lazy_static! {
    pub static ref ANY_SENDER_NONCE_KEY: [u8; 32] = get_prefixed_db_key(
        "any-sender-nonce"
    );
}

lazy_static! {
    pub static ref ERC777_PROXY_CONTACT_ADDRESS_KEY: [u8; 32] = get_prefixed_db_key(
        "erc-777-proxy-contract-address-key"
    );
}
