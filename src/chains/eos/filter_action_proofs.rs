use std::str::FromStr;

use eos_chain::{AccountName as EosAccountName, ActionName as EosActionName, Checksum256};

use crate::{
    chains::eos::{
        eos_action_proofs::{EosActionProof, EosActionProofs},
        eos_database_utils::get_eos_account_name_from_db,
        eos_merkle_utils::verify_merkle_proof,
        eos_state::EosState,
        eos_utils::{convert_bytes_to_checksum256, get_digest_from_eos_action},
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn filter_proofs_with_wrong_action_mroot(
    action_mroot: &Checksum256,
    action_proofs: &[EosActionProof],
) -> Result<EosActionProofs> {
    let filtered = action_proofs
        .iter()
        .filter(|proof_data| proof_data.action_proof[proof_data.action_proof.len() - 1] == action_mroot.to_string())
        .cloned()
        .collect::<EosActionProofs>();
    debug!("Num proofs before: {}", action_proofs.len());
    debug!("Num proofs after : {}", filtered.len());
    Ok(filtered)
}

pub fn filter_proofs_for_account(
    action_proofs: &[EosActionProof],
    required_account_name: EosAccountName,
) -> Result<EosActionProofs> {
    info!("✔ Filtering proofs for EOS account `{}`", required_account_name);
    let filtered: EosActionProofs = action_proofs
        .iter()
        .filter(|proof| proof.action.account == required_account_name)
        .cloned()
        .collect();
    debug!("Num proofs before: {}", action_proofs.len());
    debug!("Num proofs after: {}", filtered.len());
    Ok(filtered)
}

pub fn filter_proofs_for_accounts(
    action_proofs: &[EosActionProof],
    account_names: &[EosAccountName],
) -> Result<EosActionProofs> {
    Ok(account_names
        .iter()
        .map(|account_name| filter_proofs_for_account(action_proofs, *account_name))
        .collect::<Result<Vec<EosActionProofs>>>()?
        .concat())
}

fn filter_for_proofs_with_action_name(action_proofs: &[EosActionProof], action_name: &str) -> Result<EosActionProofs> {
    let required_action_name = EosActionName::from_str(action_name)?;
    let filtered: EosActionProofs = action_proofs
        .iter()
        .filter(|proof| proof.action.name == required_action_name)
        .cloned()
        .collect();
    debug!("Num proofs before: {}", action_proofs.len());
    debug!(" Num proofs after: {}", filtered.len());
    Ok(filtered)
}

pub fn filter_out_proofs_with_invalid_merkle_proofs(action_proofs: &[EosActionProof]) -> Result<EosActionProofs> {
    let filtered = action_proofs
        .iter()
        .map(|proof_data| proof_data.action_proof.as_slice())
        .map(verify_merkle_proof)
        .collect::<Result<Vec<bool>>>()?
        .into_iter()
        .zip(action_proofs.iter())
        .filter_map(|(proof_is_valid, proof)| if proof_is_valid { Some(proof) } else { None })
        .cloned()
        .collect::<EosActionProofs>();
    debug!("Num proofs before: {}", action_proofs.len());
    debug!("Num proofs after : {}", filtered.len());
    Ok(filtered)
}

pub fn filter_out_invalid_action_receipt_digests(action_proofs: &[EosActionProof]) -> Result<EosActionProofs> {
    let filtered = action_proofs
        .iter()
        .filter_map(|proof| proof.action_receipt.to_digest().ok())
        .map(hex::encode)
        .zip(action_proofs.iter())
        .filter_map(|(digest, proof)| {
            if digest == proof.action_proof[0] {
                Some(proof)
            } else {
                None
            }
        })
        .cloned()
        .collect::<EosActionProofs>();
    debug!("Num proofs before: {}", action_proofs.len());
    debug!("Num proofs after : {}", filtered.len());
    Ok(filtered)
}

pub fn filter_out_proofs_with_action_digests_not_in_action_receipts(
    action_proofs: &[EosActionProof],
) -> Result<EosActionProofs> {
    let filtered = action_proofs
        .iter()
        .map(|proof| get_digest_from_eos_action(&proof.action))
        .map(|digest_bytes| convert_bytes_to_checksum256(&digest_bytes?))
        .collect::<Result<Vec<Checksum256>>>()?
        .into_iter()
        .zip(action_proofs.iter())
        .filter_map(|(digest, proof)| {
            if digest == proof.action_receipt.act_digest {
                Some(proof)
            } else {
                None
            }
        })
        .cloned()
        .collect::<EosActionProofs>();
    debug!("Num proofs before: {}", action_proofs.len());
    debug!("Num proofs after : {}", filtered.len());
    Ok(filtered)
}

pub fn filter_duplicate_proofs(action_proofs: &[EosActionProof]) -> Result<EosActionProofs> {
    let mut filtered: EosActionProofs = Vec::new();
    action_proofs.iter().for_each(|proof| {
        if !filtered.contains(proof) {
            filtered.push(proof.clone());
        }
    });
    debug!("Num proofs before: {}", action_proofs.len());
    debug!("Num proofs after : {}", filtered.len());
    Ok(filtered)
}

pub fn maybe_filter_duplicate_proofs_from_state<D: DatabaseInterface>(state: EosState<D>) -> Result<EosState<D>> {
    info!("✔ Maybe filtering duplicate proofs from state...");
    filter_duplicate_proofs(&state.action_proofs).and_then(|proofs| state.replace_action_proofs(proofs))
}

pub fn maybe_filter_out_proofs_for_accounts_not_in_token_dictionary<D: DatabaseInterface>(
    state: EosState<D>,
) -> Result<EosState<D>> {
    info!("✔ Filtering out proofs for accounts NOT in the token dictionary...");
    debug!("✔ Number of proofs before: {}", state.action_proofs.len());
    filter_proofs_for_accounts(
        &state.action_proofs,
        &state.get_eos_eth_token_dictionary()?.to_eos_accounts()?,
    )
    .and_then(|proofs| {
        debug!("✔ Number of proofs after: {}", proofs.len());
        state.replace_action_proofs(proofs)
    })
}

pub fn maybe_filter_out_proofs_for_wrong_eos_account_name<D: DatabaseInterface>(
    state: EosState<D>,
) -> Result<EosState<D>> {
    info!("✔ Filtering out proofs for accounts we don't care about...");
    filter_proofs_for_account(&state.action_proofs, get_eos_account_name_from_db(&state.db)?)
        .and_then(|proofs| state.replace_action_proofs(proofs))
}

pub fn maybe_filter_proofs_for_action_name<D: DatabaseInterface>(
    state: EosState<D>,
    action_name: &str,
) -> Result<EosState<D>> {
    info!("✔ Filtering for proofs with action name: {}", action_name);
    filter_for_proofs_with_action_name(&state.action_proofs, action_name)
        .and_then(|proofs| state.replace_action_proofs(proofs))
}

pub fn maybe_filter_out_action_proof_receipt_mismatches_and_return_state<D: DatabaseInterface>(
    state: EosState<D>,
) -> Result<EosState<D>> {
    info!("✔ Filtering proofs w/ action digests NOT in action receipts...");
    filter_out_proofs_with_action_digests_not_in_action_receipts(&state.action_proofs)
        .and_then(|proofs| state.replace_action_proofs(proofs))
}

pub fn maybe_filter_out_invalid_action_receipt_digests<D: DatabaseInterface>(
    state: EosState<D>,
) -> Result<EosState<D>> {
    info!("✔ Filtering out invalid action digests...");
    filter_out_invalid_action_receipt_digests(&state.action_proofs)
        .and_then(|proofs| state.replace_action_proofs(proofs))
}

pub fn maybe_filter_out_proofs_with_invalid_merkle_proofs<D: DatabaseInterface>(
    state: EosState<D>,
) -> Result<EosState<D>> {
    info!("✔ Filtering out invalid merkle proofs...");
    filter_out_proofs_with_invalid_merkle_proofs(&state.action_proofs)
        .and_then(|proofs| state.replace_action_proofs(proofs))
}

pub fn maybe_filter_out_proofs_with_wrong_action_mroot<D: DatabaseInterface>(
    state: EosState<D>,
) -> Result<EosState<D>> {
    info!("✔ Filtering out proofs with wrong `action_mroot`...");
    filter_proofs_with_wrong_action_mroot(&state.get_eos_block_header()?.action_mroot, &state.action_proofs)
        .and_then(|proofs| state.replace_action_proofs(proofs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::eos::{
        eos_constants::REDEEM_ACTION_NAME,
        eos_test_utils::get_sample_action_proof_n,
        eos_utils::convert_hex_to_checksum256,
    };

    #[test]
    fn should_not_filter_out_proofs_with_action_digests_in_action_receipts() {
        let action_proofs = vec![get_sample_action_proof_n(4), get_sample_action_proof_n(1)];
        let result = filter_out_proofs_with_action_digests_not_in_action_receipts(&action_proofs).unwrap();

        assert_eq!(result, action_proofs);
    }

    #[test]
    fn should_filter_out_proofs_with_action_digests_not_in_action_receipts() {
        let action_proofs = vec![get_sample_action_proof_n(4), get_sample_action_proof_n(1)];

        let mut proof_with_invalid_action = get_sample_action_proof_n(3);
        proof_with_invalid_action.action.data[0] = 42;

        let mut dirty_action_proofs = vec![proof_with_invalid_action];
        dirty_action_proofs.extend_from_slice(&action_proofs);

        let result = filter_out_proofs_with_action_digests_not_in_action_receipts(&dirty_action_proofs).unwrap();

        assert_eq!(result, action_proofs);
    }

    #[test]
    fn should_not_filter_duplicate_action_proofs_if_there_are_no_duplicates() {
        let expected_num_proofs_after = 2;
        let expected_num_proofs_before = 2;

        let proofs_no_duplicates = vec![get_sample_action_proof_n(4), get_sample_action_proof_n(1)];

        let num_proofs_before = proofs_no_duplicates.len();
        assert_eq!(num_proofs_before, expected_num_proofs_before);

        let result = filter_duplicate_proofs(&proofs_no_duplicates).unwrap();

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

        let result = filter_duplicate_proofs(&proofs_with_duplicate).unwrap();

        assert!(result.len() < num_proofs_before);
        assert_eq!(result.len(), expected_num_proofs_after);

        assert_eq!(result[0], get_sample_action_proof_n(1));
        assert_eq!(result[1], get_sample_action_proof_n(2));
    }

    #[test]
    fn should_not_filter_out_valid_action_receipt_digests() {
        let action_proofs = vec![get_sample_action_proof_n(1), get_sample_action_proof_n(2)];
        let result = filter_out_invalid_action_receipt_digests(&action_proofs).unwrap();

        assert_eq!(result, action_proofs);
    }

    #[test]
    fn should_filter_out_invalid_action_receipt_digests() {
        let action_proofs = vec![get_sample_action_proof_n(1), get_sample_action_proof_n(2)];

        let mut proof_with_invalid_receipt = get_sample_action_proof_n(3);
        proof_with_invalid_receipt.action_receipt.global_sequence = 42;

        let mut dirty_action_proofs = vec![proof_with_invalid_receipt];
        dirty_action_proofs.extend_from_slice(&action_proofs);

        let result = filter_out_invalid_action_receipt_digests(&dirty_action_proofs).unwrap();

        assert_eq!(result, action_proofs);
    }

    #[test]
    fn should_not_filter_out_proofs_with_valid_merkle_proofs() {
        let action_proofs = vec![get_sample_action_proof_n(4), get_sample_action_proof_n(1)];
        let result = filter_out_proofs_with_invalid_merkle_proofs(&action_proofs).unwrap();

        assert_eq!(result, action_proofs);
    }

    #[test]
    fn should_filter_out_proofs_with_invalid_merkle_proofs() {
        let mut dirty_action_proofs = vec![get_sample_action_proof_n(4), get_sample_action_proof_n(1)];

        dirty_action_proofs[0].action_proof.pop();

        let result = filter_out_proofs_with_invalid_merkle_proofs(&dirty_action_proofs).unwrap();

        assert_eq!(result, [get_sample_action_proof_n(1)]);
    }

    #[test]
    fn should_not_filter_out_proofs_for_required_account() {
        let action_proofs = vec![get_sample_action_proof_n(4), get_sample_action_proof_n(1)];
        let account = EosAccountName::from_str("pbtctokenxxx").unwrap();

        assert_eq!(
            filter_proofs_for_account(&action_proofs, account).unwrap(),
            action_proofs
        );
    }

    #[test]
    fn should_filter_out_proofs_for_other_accounts() {
        let action_proofs = vec![get_sample_action_proof_n(4), get_sample_action_proof_n(1)];
        let account = EosAccountName::from_str("provtestable").unwrap();

        assert_eq!(filter_proofs_for_account(&action_proofs, account).unwrap(), []);
    }

    #[test]
    fn should_not_filter_out_proofs_for_valid_actions() {
        let required_action_name = REDEEM_ACTION_NAME;
        let action_proofs = vec![get_sample_action_proof_n(4), get_sample_action_proof_n(1)];
        let result = filter_for_proofs_with_action_name(&action_proofs, &required_action_name).unwrap();

        assert_eq!(result, action_proofs);
    }

    #[test]
    fn should_filter_out_proofs_for_other_actions() {
        let required_action_name = REDEEM_ACTION_NAME;
        let invalid_action_name = EosActionName::from_str("setproducers").unwrap();

        let mut dirty_action_proofs = vec![get_sample_action_proof_n(4), get_sample_action_proof_n(1)];
        dirty_action_proofs[0].action.name = invalid_action_name;

        assert_ne!(
            dirty_action_proofs[0].action.name,
            EosActionName::from_str(required_action_name).unwrap()
        );

        let result = filter_for_proofs_with_action_name(&dirty_action_proofs, &required_action_name).unwrap();

        assert_eq!(result, [get_sample_action_proof_n(1)]);
    }

    #[test]
    fn should_not_filter_proofs_with_correct_action_mroot() {
        let action_proofs = vec![
            get_sample_action_proof_n(1),
            get_sample_action_proof_n(1),
            get_sample_action_proof_n(1),
        ];
        let action_mroot =
            convert_hex_to_checksum256("6ba2320b7d71d69770735f92b22f0d986d7e5d72f8842fa93b5604c63dd515c7").unwrap();
        let result = filter_proofs_with_wrong_action_mroot(&action_mroot, &action_proofs).unwrap();

        assert_eq!(result, action_proofs);
    }

    #[test]
    fn should_filter_proofs_with_wrong_action_mroot() {
        let action_proofs = vec![get_sample_action_proof_n(4), get_sample_action_proof_n(1)];
        let action_mroot =
            convert_hex_to_checksum256("10c0518e15ae178bdd622e3f31249f0f12071c68045dd565a267a522df8ba96c").unwrap();
        let result = filter_proofs_with_wrong_action_mroot(&action_mroot, &action_proofs).unwrap();

        assert_eq!(result, [get_sample_action_proof_n(4)]);
    }
}
