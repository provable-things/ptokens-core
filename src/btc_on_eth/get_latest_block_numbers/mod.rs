use serde::{Deserialize, Serialize};

use crate::{
    btc_on_eth::check_core_is_initialized::check_core_is_initialized,
    chains::{
        btc::btc_database_utils::get_latest_btc_block_number,
        eth::eth_database_utils::get_latest_eth_block_number,
    },
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Serialize, Deserialize)]
struct BlockNumbers {
    btc_latest_block_number: u64,
    eth_latest_block_number: usize,
}

/// # Get Latest Block Numbers
///
/// This function returns a JSON containing the last processed block number of each of the
/// blockchains this instance manages.
pub fn get_latest_block_numbers<D: DatabaseInterface>(db: D) -> Result<String> {
    info!("✔ Getting latest block numbers...");
    check_core_is_initialized(&db).and_then(|_| {
        Ok(serde_json::to_string(&BlockNumbers {
            btc_latest_block_number: get_latest_btc_block_number(&db)?,
            eth_latest_block_number: get_latest_eth_block_number(&db)?,
        })?)
    })
}
