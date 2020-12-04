#![cfg(test)]
use crate::{
    chains::eth::{eth_log::EthLog, eth_receipt::EthReceipt, eth_submission_material::EthSubmissionMaterial},
    erc20_on_eos::eth::peg_in_info::{Erc20OnEosPegInInfo, Erc20OnEosPegInInfos},
    types::Result,
};
use ethereum_types::{Address as EthAddress, H256 as EthHash, U256};
use std::{fs::read_to_string, path::Path};

pub const SAMPLE_ETH_SUBMISSION_MATERIAL_1: &str =
    "src/chains/eth/eth_test_utils/eth-submission-material-block-11011551.json";
pub const SAMPLE_ETH_SUBMISSION_MATERIAL_0: &str =
    "src/chains/eth/eth_test_utils/eth-submission-material-block-8739996-with-erc20-peg-in-event.json";
pub const SAMPLE_ETH_SUBMISSION_MATERIAL_2: &str =
    "src/chains/eth/eth_test_utils/eth-submission-material-block-11087536-with-erc20-peg-in-event.json";

pub fn get_sample_eth_submission_material_string_n(n: usize) -> Result<String> {
    let path = match n {
        0 => Ok(SAMPLE_ETH_SUBMISSION_MATERIAL_0),
        1 => Ok(SAMPLE_ETH_SUBMISSION_MATERIAL_1),
        2 => Ok(SAMPLE_ETH_SUBMISSION_MATERIAL_2),
        _ => Err(format!("Cannot find sample eth submission material num: {}", n)),
    }?;
    match Path::new(&path).exists() {
        true => Ok(read_to_string(path)?),
        false => Err(format!("✘ Cannot find file @ '{}'!", path).into()),
    }
}

pub fn get_sample_eth_submission_material_n(n: usize) -> Result<EthSubmissionMaterial> {
    get_sample_eth_submission_material_string_n(n).and_then(|string| EthSubmissionMaterial::from_str(&string))
}

pub fn get_sample_receipt_n(n: usize, receipt_index: usize) -> Result<EthReceipt> {
    get_sample_eth_submission_material_n(n).map(|block| block.receipts.0[receipt_index].clone())
}

pub fn get_sample_log_n(n: usize, receipt_index: usize, log_index: usize) -> Result<EthLog> {
    get_sample_receipt_n(n, receipt_index).map(|receipt| receipt.logs.0[log_index].clone())
}

pub fn get_sample_submission_material_with_erc20_peg_in_event() -> Result<EthSubmissionMaterial> {
    get_sample_eth_submission_material_n(0)
}

pub fn get_sample_receipt_with_erc20_peg_in_event() -> Result<EthReceipt> {
    get_sample_receipt_n(0, 17)
}

pub fn get_sample_log_with_erc20_peg_in_event() -> Result<EthLog> {
    get_sample_log_n(0, 17, 1)
}

pub fn get_sample_log_with_erc20_peg_in_event_2() -> Result<EthLog> {
    get_sample_log_n(2, 16, 1)
}

// TODO The eth->eos decimal conversion makes this a bad example now. Get a better one!
pub fn get_sample_erc20_on_eos_peg_in_info() -> Result<Erc20OnEosPegInInfo> {
    Ok(Erc20OnEosPegInInfo::new(
        U256::from_dec_str("1337").unwrap(),
        EthAddress::from_slice(&hex::decode("fedfe2616eb3661cb8fed2782f5f0cc91d59dcac").unwrap()),
        EthAddress::from_slice(&hex::decode("9f57cb2a4f462a5258a49e88b4331068a391de66").unwrap()),
        "aneosaddress".to_string(),
        EthHash::from_slice(&hex::decode("241f386690b715422102edf42f5c9edcddea16b64f17d02bad572f5f341725c0").unwrap()),
        "SampleToken".to_string(),
        "0.000000000 SAM".to_string(),
    ))
}

pub fn get_sample_erc20_on_eos_peg_in_infos() -> Result<Erc20OnEosPegInInfos> {
    Ok(Erc20OnEosPegInInfos::new(vec![get_sample_erc20_on_eos_peg_in_info()?]))
}
