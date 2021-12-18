use crate::{
    chains::eos::{eos_database_utils::get_eos_schedule_from_db, eos_state::EosState},
    constants::CORE_IS_VALIDATING,
    traits::DatabaseInterface,
    types::Result,
};

pub fn get_active_schedule_from_db_and_add_to_state<D: DatabaseInterface>(state: EosState<D>) -> Result<EosState<D>> {
    if CORE_IS_VALIDATING {
        info!("✔ Getting EOS active-schedule/producer-list and adding to state...");
        get_eos_schedule_from_db(&state.db, state.get_eos_block_header()?.schedule_version)
            .and_then(|schedule| state.add_active_schedule(schedule))
    } else {
        info!("✔ Not getting EOS active-schedule/producer-list ∵ core is NOT validating!");
        Ok(state)
    }
}
