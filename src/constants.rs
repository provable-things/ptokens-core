#[cfg(feature="debug")]
pub const DEBUG_MODE: bool = true;

#[cfg(not(feature="debug"))]
pub const DEBUG_MODE: bool = false;

#[cfg(not(test))]
pub static ETH_BYTECODE_PATH: &'static str = "./ptoken-erc777-bytecode";

#[cfg(test)]
pub static ETH_BYTECODE_PATH: &'static str = "./src/eth/eth_test_utils/ptoken-erc777-bytecode";

pub const HASH_LENGTH: usize = 32;
pub const U64_NUM_BYTES: usize = 8;
pub const BTC_NUM_DECIMALS: u32 = 8;
pub const HASH_HEX_CHARS: usize  = 64;
pub const HEX_PREFIX_LENGTH: usize = 2;
pub const PTOKEN_ERC777_NUM_DECIMALS: u32 = 18;
pub const MINIMUM_REQUIRED_SATOSHIS: u64 = 5_000;
pub const PRIVATE_KEY_DATA_SENSITIVITY_LEVEL: Option<u8> = Some(255);
pub static SAFE_BTC_ADDRESS: &'static str = "136CTERaocm8dLbEtzCaFtJJX9jfFhnChK";

// NOTE: "0x71A440EE9Fa7F99FB9a697e96eC7839B8A1643B8"
pub static SAFE_ETH_ADDRESS: [u8; 20] = [
    113, 164, 64, 238, 159,
    167, 249, 159, 185, 166,
    151, 233, 110, 199, 131,
    155, 138, 22, 67, 184
];
