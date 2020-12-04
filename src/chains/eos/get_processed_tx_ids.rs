use crate::{
    chains::eos::{eos_database_utils::get_processed_tx_ids_from_db, eos_state::EosState},
    traits::DatabaseInterface,
    types::Result,
};

pub fn get_processed_tx_ids_and_add_to_state<D>(state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    get_processed_tx_ids_from_db(&state.db).and_then(|tx_ids| state.add_processed_tx_ids(tx_ids))
}
