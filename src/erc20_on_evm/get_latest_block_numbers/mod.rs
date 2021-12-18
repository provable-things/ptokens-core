use serde::{Deserialize, Serialize};

use crate::{
    chains::{
        eth::eth_database_utils::get_latest_eth_block_number,
        evm::eth_database_utils::get_latest_eth_block_number as get_latest_evm_block_number,
    },
    erc20_on_evm::check_core_is_initialized::check_core_is_initialized,
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Serialize, Deserialize)]
struct BlockNumbers {
    eth_latest_block_number: usize,
    evm_latest_block_number: usize,
}

/// # Get Latest Block Numbers
///
/// This function returns a JSON containing the last processed block number of each of the
/// blockchains this instance manages.
pub fn get_latest_block_numbers<D: DatabaseInterface>(db: D) -> Result<String> {
    info!("✔ Getting latest `ERC20-on-EVM` block numbers...");
    check_core_is_initialized(&db).and_then(|_| {
        Ok(serde_json::to_string(&BlockNumbers {
            eth_latest_block_number: get_latest_eth_block_number(&db)?,
            evm_latest_block_number: get_latest_evm_block_number(&db)?,
        })?)
    })
}
