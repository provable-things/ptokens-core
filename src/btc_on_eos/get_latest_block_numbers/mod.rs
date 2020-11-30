use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::check_core_is_initialized::check_btc_core_is_initialized,
    chains::{
        eos::eos_database_utils::get_latest_eos_block_number,
        btc::btc_database_utils::get_latest_btc_block_number,
    },
};

#[derive(Serialize, Deserialize)]
struct BlockNumbers {
    btc_latest_block_number: u64,
    eos_latest_block_number: u64,
}

pub fn get_latest_block_numbers<D: DatabaseInterface>(db: D) -> Result<String> {
    info!("✔ Getting latest block numbers...");
    check_btc_core_is_initialized(&db)
        .and_then(|_| {
            Ok(serde_json::to_string(
                &BlockNumbers {
                    btc_latest_block_number: get_latest_btc_block_number(&db)?,
                    eos_latest_block_number: get_latest_eos_block_number(&db)?,
                }
            )?)
        })
}
