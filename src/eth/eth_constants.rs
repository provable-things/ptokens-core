use ethereum_types::H256 as EthHash;
use crate::{
    types::Byte,
    eth::nibble_utils::Nibbles,
};

pub const ZERO_BYTE: u8 = 0u8;
pub const ETH_TAIL_LENGTH: u64 = 100;
pub const HIGH_NIBBLE_MASK: Byte = 15u8; // NOTE: 15u8 == [0,0,0,0,1,1,1,1]
pub const NUM_BITS_IN_NIBBLE: usize = 4;
pub const NUM_NIBBLES_IN_BYTE: usize = 2;
pub const VALUE_FOR_MINTING_TX: usize = 0;
pub const VALUE_FOR_PTOKEN_DEPLOY: usize = 0;
pub const ETH_WORD_SIZE_IN_BYTES: usize = 32;
pub static LEAF_NODE_STRING: &'static str = "leaf";
pub const GAS_LIMIT_FOR_MINTING_TX: usize = 120_000;
pub static BRANCH_NODE_STRING: &'static str = "branch";
pub const LOG_DATA_BTC_ADDRESS_START_INDEX: usize = 96;
pub const GAS_LIMIT_FOR_PTOKEN_DEPLOY: usize = 2_800_000;
pub static EXTENSION_NODE_STRING: &'static str = "extension";
pub const HASHED_NULL_NODE: EthHash = EthHash(HASHED_NULL_NODE_BYTES);
pub static ETH_SMART_CONTRACT_MINTING_FXN_SIG: &'static str = "40c10f19";
pub const EMPTY_NIBBLES: Nibbles = Nibbles { data: Vec::new(), offset: 0 };
pub static REDEEM_EVENT_TOPIC_HEX: &'static str =
    "78e6c3f67f57c26578f2487b930b70d844bcc8dd8f4d629fb4af81252ab5aa65";

#[cfg(not(test))]
lazy_static! {
    pub static ref PTOKEN_CONTRACT_TOPICS: [EthHash; 1] = {
        [
            EthHash::from_slice(&hex::decode(
                REDEEM_EVENT_TOPIC_HEX
            ).expect("✘ Invalid hex in PTOKEN_CONTRACT_TOPIC!")),
        ]
    };
}

#[cfg(test)]
lazy_static! {
    pub static ref PTOKEN_CONTRACT_TOPICS: [EthHash; 1] = {
        [
            EthHash::from_slice(&hex::decode(
            "fc62a6078634cc3b00bff541ac549ba6bfed8678765289f88f61e22c668198ba"
            ).expect("✘ Invalid hex in PTOKEN_CONTRACT_TOPIC!")),
        ]
    };
}
// NOTE: keccak256("provable-ptoken")
// 7eb2e65416dd107602495454d1ed094ae475cff2f3bfb2e2ae68a1c52bc0d66f
pub static PTOKEN_GENESIS_HASH: [u8; 32] = [
  126, 178, 230, 84, 22, 221, 16, 118,
  2, 73, 84, 84, 209, 237, 9, 74,
  228, 117, 207, 242, 243, 191, 178, 226,
  174, 104, 161, 197, 43, 192, 214, 111
];

const HASHED_NULL_NODE_BYTES: [u8; 32] = [ // NOTE: keccak hash of the RLP of null
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
    0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
    0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21
];

// NOTE: keccak256("canon-to-tip-length-key")
// "192b7e4da694bf96fbc089656a3ba0f63f6263a95af257b693e8dee84334b38c";
pub static ETH_CANON_TO_TIP_LENGTH_KEY: [u8; 32] = [
    25, 43, 126, 77, 166, 148, 191, 150,
    251, 192, 137, 101, 106, 59, 160, 246,
    63, 98, 99, 169, 90, 242, 87, 182,
    147, 232, 222, 232, 67, 52, 179, 140
];

// NOTE: keccak256("anchor-block-hash-key")
// "1087f2e9bfa897df4da210822cc94bcf77ee11396cf9d3cd247b06aeeb289737";
pub static ETH_ANCHOR_BLOCK_HASH_KEY: [u8; 32] = [
    16, 135, 242, 233, 191, 168, 151, 223,
    77, 162, 16, 130, 44, 201, 75, 207,
    119, 238, 17, 57, 108, 249, 211,
    205, 36, 123, 6, 174, 235, 40, 151, 55
];

// NOTE: keccak256("latest-block-hash-key")
// "8b39bef2b5b1e9564bb4a60c8211c32e2f94dc88cae8cfbaad42b2e7e527ea7a";
pub static ETH_LATEST_BLOCK_HASH_KEY: [u8; 32] = [
    139, 57, 190, 242, 181, 177, 233, 86,
    75, 180, 166, 12, 130, 17, 195, 46,
    47, 148, 220, 136, 202, 232, 207, 186,
    173, 66, 178, 231, 229, 39, 234, 122
];

// NOTE: keccak256("canon-block-hash-key")
// "c737daae274d21e37403be7d3d562c493332c381ee2b0f3fa0b2286af8b8e5c2";
pub static ETH_CANON_BLOCK_HASH_KEY: [u8; 32] = [
    199, 55, 218, 174, 39, 77, 33, 227,
    116, 3, 190, 125, 61, 86, 44, 73,
    51, 50, 195, 129, 238, 43, 15, 63,
    160, 178, 40, 106, 248, 184, 229, 194
];

// NOTE: keccak256("linker-hash-key")
// "1c045b32a91a460a8a210de0a9b757da8fc21844f02399b558c3c87917122b58";
pub static ETH_LINKER_HASH_KEY: [u8; 32] = [
    28, 4, 91, 50, 169, 26, 70, 10,
    138, 33, 13, 224, 169, 183, 87, 218,
    143, 194, 24, 68, 240, 35, 153, 181,
    88, 195, 200, 121, 23, 18, 43, 88
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('eth-account-nonce').slice(2), 'hex')
// )
// 713a7d7396c523b7978cd822839e0186395053745941615b0370c0bb72b4dcf4
pub static ETH_ACCOUNT_NONCE_KEY: [u8; 32] = [
  113, 58, 125, 115, 150, 197, 35, 183,
  151, 140, 216, 34, 131, 158, 1, 134,
  57, 80, 83, 116, 89, 65, 97, 91,
  3, 112, 192, 187, 114, 180, 220, 244
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('eth-smart-contract').slice(2), 'hex')
// )
// f2289049ab0275224d98f6f7d6b2e5c0b301167d04b83aa724024fcad81d61fc
pub static ETH_SMART_CONTRACT_ADDRESS_KEY: [u8; 32] = [
    242, 40, 144, 73, 171, 2, 117, 34,
    77, 152, 246, 247, 214, 178, 229, 192,
    179, 1, 22, 125, 4, 184, 58, 167,
    36, 2, 79, 202, 216, 29, 97, 252
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('eth-address-key').slice(2), 'hex')
// )
// NOTE: The above text DOES NOT hash to below bytes! Must have typod!
// NOTE: Actual hex used is:
// 'c493aea55db4039052bae9cf66cad8819a3571c3939ae351d01218db0237e96a'
pub static ETH_ADDRESS_KEY: [u8; 32] = [
  196, 147, 174, 165, 93, 180, 3, 144,
  82, 186, 233, 207, 102, 202, 216, 129,
  154, 53, 113, 195, 147, 154, 227, 81,
  208, 18, 24, 219, 2, 55, 233, 106
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('eth-private-key-key').slice(2), 'hex')
// )
// eec538cafefe65e094e2e70364da2f2f6e752209e1974e38a9b23ca8ce22b73d
pub static ETH_PRIVATE_KEY_DB_KEY: [u8; 32] = [
  238, 197, 56, 202, 254, 254, 101, 224,
  148, 226, 231, 3, 100, 218, 47, 47,
  110, 117, 34, 9, 225, 151, 78, 56,
  169, 178, 60, 168, 206, 34, 183, 61,
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('eth-chain-id').slice(2), 'hex')
// )
// 47199e3b0ffc301baeedd4eb87ebf5ef3829496c8ab2660a6038a62e36e9222f
pub static ETH_CHAIN_ID_KEY: [u8; 32] = [
  71, 25, 158, 59, 15, 252, 48, 27,
  174, 237, 212, 235, 135, 235, 245, 239,
  56, 41, 73, 108, 138, 178, 102, 10,
  96, 56, 166, 46, 54, 233, 34, 47
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('eth-gas-price').slice(2), 'hex')
// )
// ecf932d3aca97f12884bc42af7607469feba2206e8b1d37ed1328d477c747346
pub static ETH_GAS_PRICE_KEY: [u8; 32] = [
  236, 249, 50, 211, 172, 169, 127, 18,
  136, 75, 196, 42, 247, 96, 116, 105,
  254, 186, 34, 6, 232, 177, 211, 126,
  209, 50, 141, 71, 124, 116, 115, 70
];
// NOTE (javascript): new Uint8Array(
//   Buffer.from(web3.utils.keccak256('eth-tail-block-hash-key').slice(2), 'hex')
// )
// 539205e110a233c64f983acf425f1d2cf6cb6535a0241a3722a512690eeba758
pub static ETH_TAIL_BLOCK_HASH_KEY: [u8; 32] = [
  83, 146, 5, 225, 16, 162, 51, 198,
  79, 152, 58, 207, 66, 95, 29, 44,
  246, 203, 101, 53, 160, 36, 26, 55,
  34, 165, 18, 105, 14, 235, 167, 88
];
