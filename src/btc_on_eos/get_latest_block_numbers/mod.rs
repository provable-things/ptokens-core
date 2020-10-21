use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::eos::eos_database_utils::get_latest_eos_block_number,
    btc_on_eos::{
        btc::btc_database_utils::get_latest_btc_block_number,
        check_core_is_initialized::check_btc_core_is_initialized,
    },
};

#[derive(Serialize, Deserialize)]
struct BlockNumbers {
    btc_latest_block_number: u64,
    eos_latest_block_number: u64,
}

pub fn get_latest_block_numbers<D>(
    db: D,
) -> Result<String>
    where D: DatabaseInterface
{
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
