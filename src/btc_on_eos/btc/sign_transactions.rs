use crate::{
    btc_on_eos::btc::minting_params::BtcOnEosMintingParams,
    chains::{
        btc::{btc_database_utils::get_btc_canon_block_from_db, btc_state::BtcState},
        eos::{
            eos_crypto::{
                eos_private_key::EosPrivateKey,
                eos_transaction::{get_signed_eos_ptoken_issue_tx, EosSignedTransaction, EosSignedTransactions},
            },
            eos_database_utils::{get_eos_account_name_string_from_db, get_eos_chain_id_from_db},
        },
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn get_signed_eos_ptoken_issue_txs(
    ref_block_num: u16,
    ref_block_prefix: u32,
    chain_id: &str,
    pk: &EosPrivateKey,
    account: &str,
    minting_params: &BtcOnEosMintingParams,
) -> Result<EosSignedTransactions> {
    info!("✔ Signing {} txs...", minting_params.len());
    Ok(EosSignedTransactions::new(
        minting_params
            .iter()
            .map(|params| {
                get_signed_eos_ptoken_issue_tx(
                    ref_block_num,
                    ref_block_prefix,
                    &params.to,
                    &params.amount,
                    chain_id,
                    pk,
                    account,
                )
            })
            .collect::<Result<Vec<EosSignedTransaction>>>()?,
    ))
}

pub fn maybe_sign_canon_block_txs_and_add_to_state<D: DatabaseInterface>(state: BtcState<D>) -> Result<BtcState<D>> {
    info!("✔ Maybe signing minting txs...");
    get_signed_eos_ptoken_issue_txs(
        state.get_eos_ref_block_num()?,
        state.get_eos_ref_block_prefix()?,
        &get_eos_chain_id_from_db(&state.db)?,
        &EosPrivateKey::get_from_db(&state.db)?,
        &get_eos_account_name_string_from_db(&state.db)?,
        &get_btc_canon_block_from_db(&state.db)?.get_eos_minting_params(),
    )
    .and_then(|signed_txs| state.add_signed_txs(signed_txs))
}
