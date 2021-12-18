#![cfg(test)]
use crate::{
    btc_on_eos::eos::redeem_info::{BtcOnEosRedeemInfo, BtcOnEosRedeemInfos},
    chains::eos::eos_test_utils::get_sample_eos_submission_material_n,
};

pub fn get_sample_redeem_info() -> BtcOnEosRedeemInfo {
    let action_proof = get_sample_eos_submission_material_n(1).action_proofs[0].clone();
    BtcOnEosRedeemInfo::from_action_proof(&action_proof).unwrap()
}

pub fn get_sample_redeem_infos() -> BtcOnEosRedeemInfos {
    BtcOnEosRedeemInfos::new(vec![get_sample_redeem_info(), get_sample_redeem_info()])
}
