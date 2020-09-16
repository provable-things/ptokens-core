use crate::{
    traits::DatabaseInterface,
    btc_on_eos::eos::eos_database_utils::get_processed_tx_ids_from_db,
};

pub fn is_eos_core_initialized<D>(db: &D) -> bool where D: DatabaseInterface {
    trace!("✔ Checking if EOS core has been initialized...");
    match get_processed_tx_ids_from_db(db) {
        Ok(_)=> {
            trace!("✔ EOS core *HAS* been initialized!");
            true
        }
        _ => {
            trace!("✔ EOS core has *NOT* been initialized!");
            false
        }
    }
}
