use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::eos::{
        eos_state::EosState,
        eos_database_utils::get_processed_tx_ids_from_db,
    },
};

pub fn get_processed_tx_ids_and_add_to_state<D>(state: EosState<D>) -> Result<EosState<D>> where D: DatabaseInterface {
    get_processed_tx_ids_from_db(&state.db).and_then(|tx_ids| state.add_processed_tx_ids(tx_ids))
}
