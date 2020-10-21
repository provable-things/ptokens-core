use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::{
        eos::eos_state::EosState,
        eth::eth_database_utils::increment_eth_account_nonce_in_db,
    },
};

pub fn maybe_increment_eth_nonce_in_db_and_return_state<D>(
    state: EosState<D>
) -> Result<EosState<D>> where D: DatabaseInterface {
    let num_txs = state.erc20_on_eos_signed_txs.len() as u64;
    match num_txs {
        0 => {
            info!("✔ Not incrementing ETH account nonce - no signatures made!");
            Ok(state)
        }
        _ => {
            info!("✔ Incrementing ETH account nonce by {}", num_txs);
            increment_eth_account_nonce_in_db(&state.db, num_txs).and(Ok(state))
        }
    }
}
