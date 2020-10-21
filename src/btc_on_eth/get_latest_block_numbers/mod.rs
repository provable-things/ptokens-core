use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::eth::eth_database_utils::get_latest_eth_block_number,
    btc_on_eth::{
        btc::btc_database_utils::get_latest_btc_block_number,
        check_core_is_initialized::check_core_is_initialized,
    },
};

#[derive(Serialize, Deserialize)]
struct BlockNumbers {
    btc_latest_block_number: u64,
    eth_latest_block_number: usize,
}

pub fn get_latest_block_numbers<D>(
    db: D,
) -> Result<String>
    where D: DatabaseInterface
{
    info!("✔ Getting latest block numbers...");
    check_core_is_initialized(&db)
        .and_then(|_| {
            Ok(serde_json::to_string(
                &BlockNumbers {
                    btc_latest_block_number: get_latest_btc_block_number(&db)?,
                    eth_latest_block_number: get_latest_eth_block_number(&db)?,
                }
            )?)
        })
}
