use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::{
        btc::btc_database_utils::get_btc_latest_block_number,
        check_core_is_initialized::check_btc_core_is_initialized,
        eos::eos_database_utils::get_eos_last_seen_block_num_from_db,
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
                    btc_latest_block_number:
                        get_btc_latest_block_number(&db)?,
                    eos_latest_block_number:
                        get_eos_last_seen_block_num_from_db(&db)?,
                }
            )?)
        })
}
