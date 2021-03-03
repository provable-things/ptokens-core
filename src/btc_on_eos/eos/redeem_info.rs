use std::str::from_utf8;

use derive_more::{Constructor, Deref};
use eos_primitives::{AccountName as EosAccountName, Checksum256};

use crate::{
    chains::{
        btc::btc_constants::MINIMUM_REQUIRED_SATOSHIS,
        eos::{
            eos_action_proofs::EosActionProof,
            eos_global_sequences::{GlobalSequence, GlobalSequences, ProcessedGlobalSequences},
            eos_state::EosState,
        },
    },
    traits::DatabaseInterface,
    types::Result,
    utils::convert_bytes_to_u64,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Deref, Constructor)]
pub struct BtcOnEosRedeemInfos(pub Vec<BtcOnEosRedeemInfo>);

impl BtcOnEosRedeemInfos {
    pub fn sum(&self) -> u64 {
        self.0.iter().fold(0, |acc, infos| acc + infos.amount)
    }

    pub fn get_global_sequences(&self) -> GlobalSequences {
        GlobalSequences::new(
            self.0
                .iter()
                .map(|infos| infos.global_sequence)
                .collect::<Vec<GlobalSequence>>(),
        )
    }

    pub fn from_action_proofs(action_proofs: &[EosActionProof]) -> Result<BtcOnEosRedeemInfos> {
        Ok(BtcOnEosRedeemInfos::new(
            action_proofs
                .iter()
                .map(|ref action_proof| BtcOnEosRedeemInfo::from_action_proof(action_proof))
                .collect::<Result<Vec<BtcOnEosRedeemInfo>>>()?,
        ))
    }

    pub fn filter_out_already_processed_txs(
        &self,
        processed_tx_ids: &ProcessedGlobalSequences,
    ) -> Result<BtcOnEosRedeemInfos> {
        Ok(BtcOnEosRedeemInfos::new(
            self.iter()
                .filter(|info| !processed_tx_ids.contains(&info.global_sequence))
                .cloned()
                .collect::<Vec<BtcOnEosRedeemInfo>>(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtcOnEosRedeemInfo {
    pub amount: u64,
    pub recipient: String,
    pub from: EosAccountName,
    pub originating_tx_id: Checksum256,
    pub global_sequence: GlobalSequence,
}

impl BtcOnEosRedeemInfo {
    pub fn get_eos_amount_from_proof(proof: &EosActionProof) -> Result<u64> {
        proof
            .check_proof_action_data_length(15, "Not enough data to parse `BtcOnEosRedeemInfo` amount from proof!")
            .and_then(|_| convert_bytes_to_u64(&proof.action.data[8..=15].to_vec()))
    }

    pub fn get_action_sender_from_proof(proof: &EosActionProof) -> Result<EosAccountName> {
        proof
            .check_proof_action_data_length(7, "Not enough data to parse `BtcOnEosRedeemInfo` sender from proof!")
            .and_then(|_| {
                let result = EosAccountName::new(convert_bytes_to_u64(&proof.action.data[..=7].to_vec())?);
                debug!("✔ Account name parsed from redeem action: {}", result);
                Ok(result)
            })
    }

    pub fn get_redeem_address_from_proof(proof: &EosActionProof) -> Result<String> {
        proof
            .check_proof_action_data_length(25, "Not enough data to parse `BtcOnEosRedeemInfo` redeemer from proof!")
            .and_then(|_| Ok(from_utf8(&proof.action.data[25..])?.to_string()))
    }

    pub fn from_action_proof(proof: &EosActionProof) -> Result<Self> {
        info!("✔ Converting action proof to `btc-on-eos` redeem info...");
        Ok(Self {
            originating_tx_id: proof.tx_id,
            amount: Self::get_eos_amount_from_proof(proof)?,
            from: Self::get_action_sender_from_proof(proof)?,
            global_sequence: proof.action_receipt.global_sequence,
            recipient: Self::get_redeem_address_from_proof(proof)?,
        })
    }
}

pub fn maybe_parse_redeem_infos_and_put_in_state<D: DatabaseInterface>(state: EosState<D>) -> Result<EosState<D>> {
    info!("✔ Parsing redeem params from actions data...");
    BtcOnEosRedeemInfos::from_action_proofs(&state.action_proofs).and_then(|redeem_infos| {
        info!("✔ Parsed {} sets of redeem info!", redeem_infos.len());
        state.add_btc_on_eos_redeem_infos(redeem_infos)
    })
}

pub fn filter_out_value_too_low_btc_on_eos_redeem_infos(
    redeem_infos: &BtcOnEosRedeemInfos,
) -> Result<BtcOnEosRedeemInfos> {
    Ok(BtcOnEosRedeemInfos::new(
        redeem_infos
            .iter()
            .map(|redeem_info| redeem_info.amount)
            .zip(redeem_infos.0.iter())
            .filter_map(|(amount, redeem_info)| match amount >= MINIMUM_REQUIRED_SATOSHIS {
                true => Some(redeem_info),
                false => {
                    info!("✘ Filtering redeem redeem info ∵ value too low: {:?}", redeem_info);
                    None
                },
            })
            .cloned()
            .collect::<Vec<BtcOnEosRedeemInfo>>(),
    ))
}

pub fn maybe_filter_value_too_low_redeem_infos_in_state<D: DatabaseInterface>(
    state: EosState<D>,
) -> Result<EosState<D>> {
    info!("✔ Filtering out any redeem infos below minimum # of Satoshis...");
    filter_out_value_too_low_btc_on_eos_redeem_infos(&state.btc_on_eos_redeem_infos)
        .and_then(|new_infos| state.replace_btc_on_eos_redeem_infos(new_infos))
}

pub fn maybe_filter_out_already_processed_tx_ids_from_state<D: DatabaseInterface>(
    state: EosState<D>,
) -> Result<EosState<D>> {
    info!("✔ Filtering out already processed tx IDs...");
    state
        .btc_on_eos_redeem_infos
        .filter_out_already_processed_txs(&state.processed_tx_ids)
        .and_then(|filtered| state.add_btc_on_eos_redeem_infos(filtered))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::chains::eos::{
        eos_test_utils::get_sample_eos_submission_material_n,
        eos_utils::convert_hex_to_checksum256,
    };

    #[test]
    fn should_get_amount_from_proof() {
        let proof = &get_sample_eos_submission_material_n(1).action_proofs[0].clone();
        let expected_result: u64 = 5111;
        let result = BtcOnEosRedeemInfo::get_eos_amount_from_proof(&proof).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_sender_from_proof() {
        let proof = &get_sample_eos_submission_material_n(1).action_proofs[0].clone();
        let expected_result = EosAccountName::from_str("provtestable").unwrap();
        let result = BtcOnEosRedeemInfo::get_action_sender_from_proof(&proof).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_redeem_address_from_proof() {
        let proof = &get_sample_eos_submission_material_n(1).action_proofs[0].clone();
        let expected_result = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM";
        let result = BtcOnEosRedeemInfo::get_redeem_address_from_proof(&proof).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_btc_on_eos_redeem_infos_from_action_proof_2() {
        let expected_result = BtcOnEosRedeemInfo {
            global_sequence: 577606126,
            amount: 1,
            recipient: "mr6ioeUxNMoavbr2VjaSbPAovzzgDT7Su9".to_string(),
            from: EosAccountName::from_str("provabletest").unwrap(),
            originating_tx_id: convert_hex_to_checksum256(
                &"34dff748d2bbb9504057d4be24c69b8ac38b2905f7e911dd0e9ed3bf369bae03".to_string(),
            )
            .unwrap(),
        };
        let action_proof = get_sample_eos_submission_material_n(2).action_proofs[0].clone();
        let result = BtcOnEosRedeemInfo::from_action_proof(&action_proof).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_btc_on_eos_redeem_infos_from_action_proof_3() {
        let expected_result = BtcOnEosRedeemInfo {
            global_sequence: 583774614,
            amount: 5666,
            recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
            from: EosAccountName::from_str("provabletest").unwrap(),
            originating_tx_id: convert_hex_to_checksum256(
                &"51f0dbbaf6989e9b980d0fa18bd70ddfc543851ff65140623d2cababce2ceb8c".to_string(),
            )
            .unwrap(),
        };
        let action_proof = get_sample_eos_submission_material_n(3).action_proofs[0].clone();
        let result = BtcOnEosRedeemInfo::from_action_proof(&action_proof).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_btc_on_eos_redeem_infos_from_action_proof_4() {
        let expected_result = BtcOnEosRedeemInfo {
            global_sequence: 579818529,
            amount: 5555,
            recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
            from: EosAccountName::from_str("provtestable").unwrap(),
            originating_tx_id: convert_hex_to_checksum256(
                &"8eaafcb796002a12e0f48ebc0f832bacca72a8b370e00967c65619a2c1814a04".to_string(),
            )
            .unwrap(),
        };
        let action_proof = get_sample_eos_submission_material_n(4).action_proofs[0].clone();
        let result = BtcOnEosRedeemInfo::from_action_proof(&action_proof).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_btc_on_eos_redeem_infos_from_action_proof_5() {
        let expected_result = BtcOnEosRedeemInfo {
            global_sequence: 579838915,
            amount: 5111,
            recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
            from: EosAccountName::from_str("provtestable").unwrap(),
            originating_tx_id: convert_hex_to_checksum256(
                &"aebe7cd1a4687485bc5db87bfb1bdfb44bd1b7f9c080e5cb178a411fd99d2fd5".to_string(),
            )
            .unwrap(),
        };
        let action_proof = get_sample_eos_submission_material_n(1).action_proofs[0].clone();
        let result = BtcOnEosRedeemInfo::from_action_proof(&action_proof).unwrap();
        assert_eq!(result, expected_result);
    }
}
