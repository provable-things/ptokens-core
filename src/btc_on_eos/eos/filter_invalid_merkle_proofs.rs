use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::eos::{
        eos_state::EosState,
        eos_types::{
            ActionProofs,
            ActionProof,
        },
        eos_merkle_utils::verify_merkle_proof,
    },
};

fn filter_out_proofs_with_invalid_merkle_proofs(
    action_proofs: &[ActionProof],
) -> Result<ActionProofs> {
    let filtered = action_proofs
        .iter()
        .map(|proof_data| proof_data.action_proof.as_slice())
        .map(verify_merkle_proof)
        .collect::<Result<Vec<bool>>>()?
        .into_iter()
        .zip(action_proofs.iter())
        .filter(|(proof_is_valid, _)| *proof_is_valid)
        .map(|(_, proof)| proof)
        .cloned()
        .collect::<ActionProofs>();
    debug!("Num proofs before: {}", action_proofs.len());
    debug!("Num proofs after : {}", filtered.len());
    Ok(filtered)
}

pub fn maybe_filter_out_proofs_with_invalid_merkle_proofs<D>(
    state: EosState<D>
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    info!("✔ Filtering out invalid merkle proofs...");
    filter_out_proofs_with_invalid_merkle_proofs(&state.action_proofs)
        .and_then(|proofs| state.replace_action_proofs(proofs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_on_eos::eos::eos_test_utils::get_sample_action_proof_n;

    #[test]
    fn should_not_filter_out_proofs_with_valid_merkle_proofs() {
        let action_proofs = vec![
            get_sample_action_proof_n(4),
            get_sample_action_proof_n(1),
        ];
        let result = filter_out_proofs_with_invalid_merkle_proofs(&action_proofs).unwrap();

        assert_eq!(result, action_proofs);
    }

    #[test]
    fn should_filter_out_proofs_with_invalid_merkle_proofs() {
        let mut dirty_action_proofs = vec![
            get_sample_action_proof_n(4),
            get_sample_action_proof_n(1),
        ];

        dirty_action_proofs[0].action_proof.pop();

        let result = filter_out_proofs_with_invalid_merkle_proofs(&dirty_action_proofs)
            .unwrap();

        assert_eq!(result, [get_sample_action_proof_n(1)]);
    }
}
