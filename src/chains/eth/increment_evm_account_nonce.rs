use crate::{
    chains::{
        eth::eth_state::EthState,
        evm::{
            eth_database_utils::get_eth_account_nonce_from_db as get_evm_account_nonce_from_db,
            increment_evm_account_nonce::increment_evm_account_nonce,
        },
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn maybe_increment_evm_account_nonce_and_return_eth_state<D: DatabaseInterface>(
    state: EthState<D>,
) -> Result<EthState<D>> {
    let num_txs = state.erc20_on_evm_evm_signed_txs.len();
    if num_txs == 0 {
        info!("✔ No signatures in state ∴ not incrementing EVM account nonce");
        Ok(state)
    } else {
        increment_evm_account_nonce(&state.db, get_evm_account_nonce_from_db(&state.db)?, num_txs as u64).and(Ok(state))
    }
}
