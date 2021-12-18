#![cfg(test)]
use std::{fs::read_to_string, path::Path};

use crate::{
    chains::{
        eos::eos_submission_material::EosSubmissionMaterial,
        eth::eth_submission_material::EthSubmissionMaterial,
    },
    dictionaries::eos_eth::EosEthTokenDictionary,
    errors::AppError,
    types::Result,
};

fn get_sample_eos_submission_material_string_n(n: usize) -> Result<String> {
    let path = match n {
        1 => Ok("src/eos_on_eth/test_utils/eos-submission-material-1.json"),
        _ => Err(AppError::Custom(format!(
            "Cannot find EOS submission material num: {}",
            n
        ))),
    }?;
    match Path::new(&path).exists() {
        true => Ok(read_to_string(path)?),
        false => Err("✘ Cannot find sample EOS submission material file!".into()),
    }
}

fn get_sample_eth_submission_material_string_n(n: usize) -> Result<String> {
    let path = format!("src/eos_on_eth/test_utils/eth-submission-material-{}.json", n);
    match Path::new(&path).exists() {
        true => Ok(read_to_string(path)?),
        false => Err("✘ Cannot find sample ETH submission material file!".into()),
    }
}

pub fn get_eos_submission_material_n(n: usize) -> Result<EosSubmissionMaterial> {
    EosSubmissionMaterial::from_str(&get_sample_eos_submission_material_string_n(n)?)
}

pub fn get_eth_submission_material_n(n: usize) -> Result<EthSubmissionMaterial> {
    EthSubmissionMaterial::from_str(&get_sample_eth_submission_material_string_n(n)?)
}

pub fn get_eth_submission_material_with_bad_eos_account_name() -> EthSubmissionMaterial {
    EthSubmissionMaterial::from_str(
        &read_to_string("src/eos_on_eth/test_utils/eos-bad-account-name-submission-material.json").unwrap(),
    )
    .unwrap()
}

pub fn get_sample_eos_eth_token_dictionary() -> EosEthTokenDictionary {
    EosEthTokenDictionary::from_str("[{\"eos_token_decimals\":4,\"eth_token_decimals\":18,\"eos_symbol\":\"EOS\",\"eth_symbol\":\"PEOS\",\"eos_address\":\"eosio.token\",\"eth_address\":\"711c50b31ee0b9e8ed4d434819ac20b4fbbb5532\"},{\"eth_token_decimals\":18,\"eos_token_decimals\":4,\"eth_symbol\":\"TLOS\",\"eos_symbol\":\"TLOS\",\"eth_address\":\"7825e833d495f3d1c28872415a4aee339d26ac88\",\"eos_address\":\"eosio.token\"}]").unwrap()
}

pub fn get_eth_submission_material_with_two_peg_ins() -> EthSubmissionMaterial {
    EthSubmissionMaterial::from_str(
        &read_to_string("src/eos_on_eth/test_utils/eth-submission-material-with-two-eos-on-eth-pegins.json").unwrap(),
    )
    .unwrap()
}

mod tests {
    use super::*;

    #[test]
    fn should_get_sample_eos_eth_token_dictionary() {
        get_sample_eos_eth_token_dictionary();
    }

    #[test]
    fn should_get_eos_submission_material_n() {
        let result = get_eos_submission_material_n(1);
        assert!(result.is_ok());
    }

    #[test]
    fn should_get_eth_submission_material_n() {
        let result = get_eth_submission_material_n(1);
        assert!(result.is_ok());
    }
}
