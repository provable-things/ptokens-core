use crate::{
    chains::{
        eth::{
            eth_database_utils::get_eth_account_nonce_from_db,
            increment_eth_account_nonce::increment_eth_account_nonce,
        },
        evm::eth_state::EthState as EvmState,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn maybe_increment_eth_account_nonce_and_return_evm_state<D: DatabaseInterface>(
    state: EvmState<D>,
) -> Result<EvmState<D>> {
    let num_txs = state.erc20_on_evm_eth_signed_txs.len();
    if num_txs == 0 {
        info!("✔ No signatures in state ∴ not incrementing ETH account nonce");
        Ok(state)
    } else {
        increment_eth_account_nonce(&state.db, get_eth_account_nonce_from_db(&state.db)?, num_txs as u64).and(Ok(state))
    }
}
