#![cfg(test)]
use ethereum_types::Address as EthAddress;

use crate::dictionaries::eos_eth::{EosEthTokenDictionary, EosEthTokenDictionaryEntry, EosEthTokenDictionaryJson};

pub fn get_sample_eos_eth_token_dictionary_entry_1() -> EosEthTokenDictionaryEntry {
    let token_address_hex = "9f57CB2a4F462a5258a49E88B4331068a391DE66".to_string();
    EosEthTokenDictionaryEntry::new(
        18,
        9,
        "SAM1".to_string(),
        "SAM1".to_string(),
        "SampleToken_1".to_string(),
        EthAddress::from_slice(&hex::decode(&token_address_hex).unwrap()),
    )
}

pub fn get_sample_eos_eth_token_dictionary_entry_2() -> EosEthTokenDictionaryEntry {
    let token_address_hex = "9e57CB2a4F462a5258a49E88B4331068a391DE66".to_string();
    EosEthTokenDictionaryEntry::new(
        18,
        9,
        "SAM2".to_string(),
        "SAM2".to_string(),
        "sampletokens".to_string(),
        EthAddress::from_slice(&hex::decode(&token_address_hex).unwrap()),
    )
}

pub fn get_sample_eos_eth_token_dictionary() -> EosEthTokenDictionary {
    EosEthTokenDictionary::new(vec![
        get_sample_eos_eth_token_dictionary_entry_1(),
        get_sample_eos_eth_token_dictionary_entry_2(),
    ])
}

pub fn get_sample_eos_eth_token_dictionary_json() -> EosEthTokenDictionaryJson {
    get_sample_eos_eth_token_dictionary().to_json().unwrap()
}
