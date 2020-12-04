use crate::{
    chains::eos::{eos_database_utils::get_incremerkle_from_db, eos_state::EosState},
    traits::DatabaseInterface,
    types::Result,
};

pub fn get_incremerkle_and_add_to_state<D>(state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    get_incremerkle_from_db(&state.db).map(|incremerkle| state.add_incremerkle(incremerkle))
}
