#![cfg(test)]
use std::fs::read_to_string;

use crate::{dictionaries::eth_evm::EthEvmTokenDictionary, types::Result};

pub fn get_sample_eth_evm_dictionary_json_str() -> Result<String> {
    Ok(read_to_string(
        "src/dictionaries/eth_evm/test_utils/eth-evm-sample-dictionary.json",
    )?)
}

pub fn get_sample_eth_evm_dictionary() -> EthEvmTokenDictionary {
    EthEvmTokenDictionary::from_str(&get_sample_eth_evm_dictionary_json_str().unwrap()).unwrap()
}

mod tests {
    use super::*;

    #[test]
    fn should_get_sample_eth_evm_dictionary_json_str() {
        let result = get_sample_eth_evm_dictionary_json_str();
        assert!(result.is_ok());
    }
}
