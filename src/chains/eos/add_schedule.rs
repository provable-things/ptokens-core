use crate::{
    chains::eos::{eos_database_utils::put_eos_schedule_in_db, eos_state::EosState},
    traits::DatabaseInterface,
    types::Result,
};

pub fn maybe_add_new_eos_schedule_to_db_and_return_state<D>(state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    match &state.get_eos_block_header()?.new_producer_schedule {
        None => {
            info!("✔ No new schedule in block ∴ nothing to add to db!");
            Ok(state)
        },
        Some(new_schedule) => {
            info!(
                "✔ New producers schedule version {} found in EOS block, adding to db...",
                new_schedule.version
            );
            put_eos_schedule_in_db(&state.db, new_schedule).and(Ok(state))
        },
    }
}
