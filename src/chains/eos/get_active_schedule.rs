use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::eos::{
        eos_state::EosState,
        eos_database_utils::get_eos_schedule_from_db,
    },
};

pub fn get_active_schedule_from_db_and_add_to_state<D>(
    state: EosState<D>,
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    info!("✔ Getting EOS producer list and adding to state...");
    get_eos_schedule_from_db(&state.db, state.get_eos_block_header()?.schedule_version)
        .and_then(|schedule| state.add_active_schedule(schedule))
}
