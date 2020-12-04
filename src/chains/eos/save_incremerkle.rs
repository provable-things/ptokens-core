use crate::{
    chains::eos::{eos_database_utils::put_incremerkle_in_db, eos_state::EosState},
    traits::DatabaseInterface,
    types::Result,
};

pub fn save_incremerkle_from_state_to_db<D>(state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Saving incremerkle from state to db...");
    put_incremerkle_in_db(&state.db, &state.incremerkle).and(Ok(state))
}
