use crate::{
    chains::{
        btc::btc_database_utils::{get_btc_account_nonce_from_db, put_btc_account_nonce_in_db},
        eos::eos_state::EosState,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn increment_btc_account_nonce<D>(db: &D, current_nonce: u64, num_signatures: u64) -> Result<()>
where
    D: DatabaseInterface,
{
    let new_nonce = num_signatures + current_nonce;
    info!(
        "✔ Incrementing btc account nonce by {} nonce from {} to {}",
        num_signatures, current_nonce, new_nonce
    );
    put_btc_account_nonce_in_db(db, new_nonce)
}

pub fn maybe_increment_btc_signature_nonce_and_return_eos_state<D>(state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    let num_txs = &state.btc_on_eos_signed_txs.len();
    match num_txs {
        0 => {
            info!("✔ No signatures in state ∴ not incrementing nonce");
            Ok(state)
        },
        _ => increment_btc_account_nonce(&state.db, get_btc_account_nonce_from_db(&state.db)?, *num_txs as u64)
            .and(Ok(state)),
    }
}
