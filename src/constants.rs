use ethereum_types::Address as EthAddress;

#[cfg(feature = "debug")]
pub const DEBUG_MODE: bool = true;

#[cfg(not(feature = "debug"))]
pub const DEBUG_MODE: bool = false;

#[cfg(feature = "non-validating")]
pub const CORE_IS_VALIDATING: bool = false;

#[cfg(not(feature = "non-validating"))]
pub const CORE_IS_VALIDATING: bool = true;

pub const NOT_VALIDATING_WHEN_NOT_IN_DEBUG_MODE_ERROR: &str =
    "✘ Not allowed to skip validation when core is not build in `DEBUG` mode!`";

pub const U64_NUM_BYTES: usize = 8;
pub const BTC_NUM_DECIMALS: usize = 8;
pub const ETH_HASH_LENGTH: usize = 32;
pub const PTOKEN_ERC777_NUM_DECIMALS: u32 = 18;
pub const SAFE_EOS_ADDRESS: &str = "safu.ptokens";
pub const MIN_DATA_SENSITIVITY_LEVEL: Option<u8> = None;
pub const DEBUG_OUTPUT_MARKER: &str = "DEBUG_OUTPUT_MARKER";
pub const PRIVATE_KEY_DATA_SENSITIVITY_LEVEL: Option<u8> = Some(255);
pub const SAFE_BTC_ADDRESS: &str = "136CTERaocm8dLbEtzCaFtJJX9jfFhnChK";
pub const SAFE_ETH_ADDRESS_HEX: &str = "71A440EE9Fa7F99FB9a697e96eC7839B8A1643B8";

lazy_static! {
    pub static ref DB_KEY_PREFIX: &'static str = match option_env!("DB_KEY_PREFIX") {
        Some(prefix) => prefix,
        None => "",
    };
}

lazy_static! {
    pub static ref SAFE_ETH_ADDRESS: EthAddress = EthAddress::from_slice(&hex::decode(SAFE_ETH_ADDRESS_HEX).unwrap());
}
