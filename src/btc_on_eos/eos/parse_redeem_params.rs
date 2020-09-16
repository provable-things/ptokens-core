use std::str::from_utf8;
use eos_primitives::{
    Symbol as EosSymbol,
    AccountName as EosAccountName,
};
use crate::{
    traits::DatabaseInterface,
    types::{
        Byte,
        Result,
    },
    btc_on_eos::{
        utils::convert_bytes_to_u64,
        eos::{
            eos_state::EosState,
            eos_types::{
                ActionProof,
                RedeemParams,
            },
        },
    },
};

#[allow(dead_code)] // TODO Use when checking for correct sybmol!
fn get_eos_symbol_from_action_data(
    action_data: &[Byte]
) -> Result<EosSymbol> {
    Ok(EosSymbol::new(convert_bytes_to_u64(&action_data[16..24].to_vec())?))
}

fn get_eos_amount_from_action_data(
    action_data: &[Byte]
) -> Result<u64> {
    convert_bytes_to_u64(&action_data[8..16].to_vec())
}

fn get_redeem_action_sender_from_action_data(
    action_data: &[Byte]
) -> Result<EosAccountName> {
    Ok(EosAccountName::new(convert_bytes_to_u64(&action_data[..8].to_vec())?))
}

fn get_redeem_address_from_action_data(
    action_data: &[Byte],
) -> Result<String> {
    Ok(from_utf8(&action_data[25..])?.to_string())
}

impl RedeemParams {
    pub fn from_action_proof(
        action_proof: &ActionProof,
    ) -> Result<Self> {
        Ok(
            RedeemParams {
                global_sequence: action_proof
                    .action_receipt
                    .global_sequence,
                amount: get_eos_amount_from_action_data(
                    &action_proof.action.data,
                )?,
                from: get_redeem_action_sender_from_action_data(
                    &action_proof.action.data,
                )?,
                recipient: get_redeem_address_from_action_data(
                    &action_proof.action.data,
                )?,
                originating_tx_id: action_proof.tx_id,
            }
        )
    }
}

pub fn parse_redeem_params_from_action_proofs(
    action_proofs: &[ActionProof]
) -> Result<Vec<RedeemParams>> {
    action_proofs
        .iter()
        .map(|proof| RedeemParams::from_action_proof(proof))
        .collect()
}

pub fn maybe_parse_redeem_params_and_put_in_state<D>(
    state: EosState<D>
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    info!("✔ Parsing redeem params from actions data...");
    parse_redeem_params_from_action_proofs(&state.action_proofs)
        .and_then(|params| {
            debug!("✔ Parsed {} sets of params!", params.len());
            state.add_redeem_params(params)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use crate::btc_on_eos::{
        utils::convert_hex_to_checksum256,
        eos::eos_test_utils::get_sample_eos_submission_material_n,
    };

    #[test]
    fn should_get_sender_from_action_data() {
        let expected_result = EosAccountName::from_str("provtestable")
            .unwrap();
        let action_data = get_sample_eos_submission_material_n(1)
            .action_proofs[0]
            .action
            .data
            .clone();
        let result = get_redeem_action_sender_from_action_data(
            &action_data
        ).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_symbol_from_action_data() {
        let expected_result = EosSymbol::from_str("8,PFFF")
            .unwrap();
        let action_data = get_sample_eos_submission_material_n(1)
            .action_proofs[0]
            .action
            .data
            .clone();
        let result = get_eos_symbol_from_action_data(&action_data)
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_amount_from_action_data() {
        let expected_result: u64 = 5111;
        let action_data = get_sample_eos_submission_material_n(1)
            .action_proofs[0]
            .action
            .data
            .clone();
        let result = get_eos_amount_from_action_data(&action_data)
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_redeem_address_serialized_action() {
        let expected_result = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM"
            .to_string();
        let action_data = get_sample_eos_submission_material_n(1)
            .action_proofs[0]
            .action
            .data
            .clone();
        let result = get_redeem_address_from_action_data(&action_data)
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_redeem_params_from_action_proof_2() {
        let expected_result = RedeemParams {
            global_sequence: 577606126,
            amount: 1,
            recipient: "mr6ioeUxNMoavbr2VjaSbPAovzzgDT7Su9"
                .to_string(),
            from: EosAccountName::from_str("provabletest")
                .unwrap(),
            originating_tx_id: convert_hex_to_checksum256(
            &"34dff748d2bbb9504057d4be24c69b8ac38b2905f7e911dd0e9ed3bf369bae03"
                .to_string()
            ).unwrap(),
        };
        let action_proof = get_sample_eos_submission_material_n(2)
            .action_proofs[0]
            .clone();
        let result = RedeemParams::from_action_proof(&action_proof)
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_redeem_params_from_action_proof_3() {
        let expected_result = RedeemParams {
            global_sequence: 583774614,
            amount: 5666,
            recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM"
                .to_string(),
            from: EosAccountName::from_str("provabletest")
                .unwrap(),
            originating_tx_id: convert_hex_to_checksum256(
            &"51f0dbbaf6989e9b980d0fa18bd70ddfc543851ff65140623d2cababce2ceb8c"
                .to_string()
            ).unwrap(),
        };
        let action_proof = get_sample_eos_submission_material_n(3)
            .action_proofs[0]
            .clone();
        let result = RedeemParams::from_action_proof(&action_proof)
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_redeem_params_from_action_proof_4() {
        let expected_result = RedeemParams {
            global_sequence: 579818529,
            amount: 5555,
            recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM"
                .to_string(),
            from: EosAccountName::from_str("provtestable")
                .unwrap(),
            originating_tx_id: convert_hex_to_checksum256(
            &"8eaafcb796002a12e0f48ebc0f832bacca72a8b370e00967c65619a2c1814a04"
                .to_string()
            ).unwrap(),
        };
        let action_proof = get_sample_eos_submission_material_n(4)
            .action_proofs[0]
            .clone();
        let result = RedeemParams::from_action_proof(&action_proof)
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_redeem_params_from_action_proof_5() {
        let expected_result = RedeemParams {
            global_sequence: 579838915,
            amount: 5111,
            recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM"
                .to_string(),
            from: EosAccountName::from_str("provtestable")
                .unwrap(),
            originating_tx_id: convert_hex_to_checksum256(
            &"aebe7cd1a4687485bc5db87bfb1bdfb44bd1b7f9c080e5cb178a411fd99d2fd5"
                .to_string()
            ).unwrap(),
        };
        let action_proof = get_sample_eos_submission_material_n(1)
            .action_proofs[0]
            .clone();
        let result = RedeemParams::from_action_proof(&action_proof)
            .unwrap();
        assert_eq!(result, expected_result);
    }
}
