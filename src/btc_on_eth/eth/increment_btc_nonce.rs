use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::{
        eth::eth_state::EthState,
        btc::btc_database_utils::increment_btc_account_nonce_in_db,
    },
};

pub fn maybe_increment_btc_nonce_in_db_and_return_state<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    match &state.btc_transactions {
        None => {
            info!("✔ Not incrementing BTC account nonce - no signatures made!");
            Ok(state)
        }
        Some(signed_txs) => {
            info!("✔ Incrementing BTC account nonce by {}", signed_txs.len());
            increment_btc_account_nonce_in_db(&state.db, signed_txs.len() as u64).and(Ok(state))
        }
    }
}
