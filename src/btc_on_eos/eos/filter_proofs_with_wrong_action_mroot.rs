use eos_primitives::Checksum256;
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

fn filter_proofs_with_wrong_action_mroot(
    action_mroot: &Checksum256,
    action_proofs: &[ActionProof],
) -> Result<ActionProofs> {
    let filtered = action_proofs
        .iter()
        .filter(|proof_data|
            proof_data.action_proof[proof_data.action_proof.len() - 1] ==
            action_mroot.to_string()
        )
        .cloned()
        .collect::<ActionProofs>();
    debug!("Num proofs before: {}", action_proofs.len());
    debug!("Num proofs after : {}", filtered.len());
    Ok(filtered)
}

pub fn maybe_filter_out_proofs_with_wrong_action_mroot<D>(
    state: EosState<D>
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    info!("✔ Filtering out proofs with wrong `action_mroot`...");
    filter_proofs_with_wrong_action_mroot(
        &state.get_eos_block_header()?.action_mroot,
        &state.action_proofs,
    )
        .and_then(|proofs| state.replace_action_proofs(proofs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_on_eos::{
        eos::eos_test_utils::get_sample_action_proof_n,
        utils::convert_hex_to_checksum256,
    };

    #[test]
    fn should_not_filter_proofs_with_correct_action_mroot() {
        let action_proofs = vec![
            get_sample_action_proof_n(1),
            get_sample_action_proof_n(1),
            get_sample_action_proof_n(1),
        ];
        let action_mroot = convert_hex_to_checksum256("6ba2320b7d71d69770735f92b22f0d986d7e5d72f8842fa93b5604c63dd515c7").unwrap();
        let result = filter_proofs_with_wrong_action_mroot(&action_mroot, &action_proofs).unwrap();

        assert_eq!(result, action_proofs);
    }

    #[test]
    fn should_filter_proofs_with_wrong_action_mroot() {
        let action_proofs = vec![
            get_sample_action_proof_n(4),
            get_sample_action_proof_n(1),
        ];
        let action_mroot = convert_hex_to_checksum256("10c0518e15ae178bdd622e3f31249f0f12071c68045dd565a267a522df8ba96c").unwrap();
        let result = filter_proofs_with_wrong_action_mroot(&action_mroot, &action_proofs).unwrap();

        assert_eq!(result, [get_sample_action_proof_n(4)]);
    }
}
