use crate::{
    types::Result,
    traits::DatabaseInterface,
    erc20_on_eos::check_core_is_initialized::check_core_is_initialized,
    chains::{
        eth::eth_database_utils::get_latest_eth_block_number,
        eos::eos_database_utils::get_latest_eos_block_number,
    },
};

#[derive(Serialize, Deserialize)]
struct BlockNumbers { eth_latest_block_number: usize, eos_latest_block_number: u64,
}

pub fn get_latest_block_numbers<D>(db: D) -> Result<String> where D: DatabaseInterface {
    info!("✔ Getting latest block numbers...");
    check_core_is_initialized(&db)
        .and_then(|_| {
            Ok(serde_json::to_string(
                &BlockNumbers {
                    eth_latest_block_number: get_latest_eth_block_number(&db)?,
                    eos_latest_block_number: get_latest_eos_block_number(&db)?,
                }
            )?)
        })
}
