use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::eos::{
        eos_state::EosState,
        eos_types::{
            ActionProof,
            ActionProofs,
        },
    },
};

fn filter_duplicate_proofs(
    action_proofs: &[ActionProof]
) -> Result<ActionProofs> {
    let mut filtered: ActionProofs = Vec::new();
    action_proofs
        .iter()
        .map(|proof| {
            if !filtered.contains(&proof) {
                filtered.push(proof.clone())
            }
        })
        .for_each(drop);
    debug!("Num proofs before: {}", action_proofs.len());
    debug!("Num proofs after : {}", filtered.len());
    Ok(filtered)
}

pub fn maybe_filter_duplicate_proofs_from_state<D>(
    state: EosState<D>
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe filtering duplicate proofs from state...");
    filter_duplicate_proofs(&state.action_proofs)
        .and_then(|proofs| state.replace_action_proofs(proofs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_on_eos::eos::eos_test_utils::get_sample_action_proof_n;

    #[test]
    fn should_not_filter_duplicate_action_proofs_if_there_are_no_duplicates() {
        let expected_num_proofs_after = 2;
        let expected_num_proofs_before = 2;

        let proofs_no_duplicates = vec![
            get_sample_action_proof_n(4),
            get_sample_action_proof_n(1),
        ];

        let num_proofs_before = proofs_no_duplicates.len();
        assert_eq!(num_proofs_before, expected_num_proofs_before);

        let result = filter_duplicate_proofs(&proofs_no_duplicates)
            .unwrap();

        assert_eq!(result.len(), num_proofs_before);
        assert_eq!(result.len(), expected_num_proofs_after);

        assert_eq!(result[0], get_sample_action_proof_n(4));
        assert_eq!(result[1], get_sample_action_proof_n(1));
    }

    #[test]
    fn should_filter_duplicate_action_proofs() {
        let expected_num_proofs_after = 2;
        let expected_num_proofs_before = 3;

        let proofs_with_duplicate = vec![
            get_sample_action_proof_n(1),
            get_sample_action_proof_n(2),
            get_sample_action_proof_n(2),
        ];

        let num_proofs_before = proofs_with_duplicate.len();
        assert_eq!(num_proofs_before, expected_num_proofs_before);

        let result = filter_duplicate_proofs(&proofs_with_duplicate)
            .unwrap();

        assert!(result.len() < num_proofs_before);
        assert_eq!(result.len(), expected_num_proofs_after);

        assert_eq!(result[0], get_sample_action_proof_n(1));
        assert_eq!(result[1], get_sample_action_proof_n(2));
    }
}
