use crate::{
    chains::{
        eos::{
            eos_database_utils::get_eos_account_nonce_from_db,
            increment_eos_account_nonce::increment_eos_account_nonce,
        },
        eth::eth_state::EthState,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn maybe_increment_eos_account_nonce_and_return_state<D>(state: EthState<D>) -> Result<EthState<D>>
where
    D: DatabaseInterface,
{
    let num_txs = &state.get_num_eos_txs();
    match num_txs {
        0 => {
            info!("✔ No signatures in state ∴ not incrementing eos account nonce");
            Ok(state)
        },
        _ => increment_eos_account_nonce(&state.db, get_eos_account_nonce_from_db(&state.db)?, *num_txs as u64)
            .and(Ok(state)),
    }
}
