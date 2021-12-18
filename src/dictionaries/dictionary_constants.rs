pub use serde_json::{json, Value as JsonValue};

use crate::utils::get_prefixed_db_key;

lazy_static! {
    // NOTE: The actual string hashed remains as it was originally for backwards compatibility.
    pub static ref EOS_ETH_DICTIONARY_KEY: [u8; 32] = get_prefixed_db_key("eos-erc20-dictionary");
}

lazy_static! {
    pub static ref ETH_EVM_DICTIONARY_KEY: [u8; 32] = get_prefixed_db_key("eth-evm-dictionary");
}
