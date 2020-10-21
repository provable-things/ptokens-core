#![cfg(test)]
use ethereum_types::Address as EthAddress;
use crate::{
    chains::eos::eos_erc20_dictionary::{
        EosErc20Dictionary,
        EosErc20DictionaryJson,
        EosErc20DictionaryEntry,
    },
};

pub fn get_sample_eos_erc20_dictionary_entry_1() -> EosErc20DictionaryEntry {
    let token_address_hex = "9f57CB2a4F462a5258a49E88B4331068a391DE66".to_string();
    EosErc20DictionaryEntry::new(
        18,
        9,
        "SAM1".to_string(),
        "SAM1".to_string(),
        "SampleToken_1".to_string(),
        EthAddress::from_slice(&hex::decode(&token_address_hex).unwrap()),
    )
}

pub fn get_sample_eos_erc20_dictionary_entry_2() -> EosErc20DictionaryEntry {
    let token_address_hex = "9e57CB2a4F462a5258a49E88B4331068a391DE66".to_string();
    EosErc20DictionaryEntry::new(
        18,
        9,
        "SAM2".to_string(),
        "SAM2".to_string(),
        "SampleToken_2".to_string(),
        EthAddress::from_slice(&hex::decode(&token_address_hex).unwrap()),
    )
}

pub fn get_sample_eos_erc20_dictionary() -> EosErc20Dictionary {
    EosErc20Dictionary::new(vec![get_sample_eos_erc20_dictionary_entry_1(), get_sample_eos_erc20_dictionary_entry_2()])
}

pub fn get_sample_eos_erc20_dictionary_json() -> EosErc20DictionaryJson {
    get_sample_eos_erc20_dictionary().to_json().unwrap()
}
