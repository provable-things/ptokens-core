#![cfg(test)]
use std::{fs::read_to_string, path::Path};

use ethereum_types::Address as EthAddress;

use crate::{
    chains::{
        eth::{
            eth_crypto::eth_private_key::EthPrivateKey,
            eth_log::EthLog,
            eth_submission_material::EthSubmissionMaterial,
        },
        evm::{
            eth_crypto::eth_private_key::EthPrivateKey as EvmPrivateKey,
            eth_submission_material::EthSubmissionMaterial as EvmSubmissionMaterial,
        },
    },
    dictionaries::eth_evm::EthEvmTokenDictionary,
    types::Result,
};

fn get_sample_submission_material_string_n(chain_type: &str, n: usize) -> Result<String> {
    let path = format!(
        "src/erc20_on_evm/test_utils/{}-submission-material-{}.json",
        chain_type, n
    );
    match Path::new(&path).exists() {
        true => Ok(read_to_string(path)?),
        false => Err(format!(
            "✘ Cannot find sample {} submission material #{} file!",
            chain_type.to_uppercase(),
            n
        )
        .into()),
    }
}

pub fn get_evm_submission_material_n(n: usize) -> EvmSubmissionMaterial {
    EvmSubmissionMaterial::from_str(&get_sample_submission_material_string_n("evm", n).unwrap()).unwrap()
}

pub fn get_eth_submission_material_n(n: usize) -> EthSubmissionMaterial {
    EthSubmissionMaterial::from_str(&get_sample_submission_material_string_n("eth", n).unwrap()).unwrap()
}

const ERC20_ON_EVM_DICTIONARY_JSON: &str = "[{\"eth_symbol\":\"PNT\",\"evm_symbol\":\"PNT\",\"evm_address\":\"0xdaacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92\",\"eth_address\":\"0x89ab32156e46f46d02ade3fecbe5fc4243b9aaed\"},{\"eth_symbol\":\"OPIUM\",\"evm_symbol\":\"pOPIUM\",\"evm_address\":\"0x566cedd201f67e542a6851a2959c1a449a041945\",\"eth_address\":\"0x888888888889c00c67689029d7856aac1065ec11\"},{\"eth_symbol\":\"PTERIA\",\"evm_symbol\":\"PTERIA\",\"evm_address\":\"0x9f5377fa03dcd4016a33669b385be4d0e02f27bc\",\"eth_address\":\"0x02eca910cb3a7d43ebc7e8028652ed5c6b70259b\"},{\"eth_symbol\":\"BCP\",\"evm_symbol\":\"pBCP\",\"evm_address\":\"0xa114f89b49d6a58416bb07dbe09502c4f3a19e2f\",\"eth_address\":\"0xe4f726adc8e89c6a6017f01eada77865db22da14\"},{\"eth_symbol\":\"DEFI++\",\"evm_symbol\":\"pDEFI++\",\"evm_address\":\"0xae22e27d1f727b585549c10e26192b2bc01082ca\",\"eth_address\":\"0x8d1ce361eb68e9e05573443c407d4a3bed23b033\"}]";

pub fn get_sample_eth_evm_token_dictionary() -> EthEvmTokenDictionary {
    EthEvmTokenDictionary::from_str(&ERC20_ON_EVM_DICTIONARY_JSON).unwrap()
}

pub fn get_sample_vault_address() -> EthAddress {
    EthAddress::from_slice(&hex::decode("d608367b33c52293201af7fb578916a7c0784bd7").unwrap())
}

pub fn get_sample_eth_private_key() -> EthPrivateKey {
    EthPrivateKey::from_slice(&hex::decode("115bfcb3fd7cae5c2b996bf7bd1c012f804b98060f7e2f4d558542549e88440f").unwrap())
        .unwrap()
}

pub fn get_sample_evm_private_key() -> EvmPrivateKey {
    EvmPrivateKey::from_slice(&hex::decode("57a5a09577a0604b84870577598d4a24fe9e5b879650a0248ac96be7d9d3f3aa").unwrap())
        .unwrap()
}

pub fn get_sample_erc20_vault_log_with_user_data() -> EthLog {
    get_eth_submission_material_n(1).receipts[91].logs[3].clone()
}

mod tests {
    use super::*;

    #[test]
    fn should_get_evm_submission_material_n() {
        get_evm_submission_material_n(1);
    }

    #[test]
    fn should_get_eth_submission_material_n() {
        get_eth_submission_material_n(1);
    }

    #[test]
    fn should_get_sample_eth_private_key() {
        get_sample_eth_private_key();
    }

    #[test]
    fn should_get_sample_evm_private_key() {
        get_sample_evm_private_key();
    }

    #[test]
    fn should_get_sample_eth_evm_dictionary() {
        get_sample_eth_evm_token_dictionary();
    }
}
