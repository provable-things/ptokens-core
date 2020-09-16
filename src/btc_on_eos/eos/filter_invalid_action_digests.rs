use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::eos::{
        eos_state::EosState,
        eos_types::{
            ActionProofs,
            ActionProof,
        },
    },
};

fn filter_out_invalid_action_receipt_digests(
    action_proofs: &[ActionProof]
) -> Result<ActionProofs> {
    let filtered = action_proofs
        .iter()
        .map(|proof| proof.action_receipt.to_digest())
        .map(hex::encode)
        .zip(action_proofs.iter())
        .filter(|(digest, proof)| digest == &proof.action_proof[0])
        .map(|(_, proof)| proof)
        .cloned()
        .collect::<ActionProofs>();
    debug!("Num proofs before: {}", action_proofs.len());
    debug!("Num proofs after : {}", filtered.len());
    Ok(filtered)
}

pub fn maybe_filter_out_invalid_action_receipt_digests<D>(
    state: EosState<D>
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    info!("✔ Filtering out invalid action digests...");
    filter_out_invalid_action_receipt_digests(&state.action_proofs)
        .and_then(|proofs| state.replace_action_proofs(proofs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_on_eos::{
        eos::eos_test_utils::get_sample_action_proof_n,
    };

    #[test]
    fn should_not_filter_out_valid_action_receipt_digests() {
        let action_proofs = vec![
            get_sample_action_proof_n(1),
            get_sample_action_proof_n(2),
        ];
        let result = filter_out_invalid_action_receipt_digests(&action_proofs)
            .unwrap();

        assert_eq!(result, action_proofs);
    }

    #[test]
    fn should_filter_out_invalid_action_receipt_digests() {
        let action_proofs = vec![
            get_sample_action_proof_n(1),
            get_sample_action_proof_n(2),
        ];

        let mut proof_with_invalid_receipt = get_sample_action_proof_n(3);
        proof_with_invalid_receipt.action_receipt.global_sequence = 42;

        let mut dirty_action_proofs = vec![proof_with_invalid_receipt];
        dirty_action_proofs.extend_from_slice(&action_proofs);

        let result = filter_out_invalid_action_receipt_digests(&dirty_action_proofs)
            .unwrap();

        assert_eq!(result, action_proofs);
    }
}
