#![allow(dead_code)]
use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::eos::{
        eos_state::EosState,
        eos_database_utils::put_eos_schedule_in_db,
    },
};

pub fn maybe_add_new_eos_schedule_to_db<D: DatabaseInterface>(state: EosState<D>) -> Result<EosState<D>> {
    match &state.get_eos_block_header()?.new_producer_schedule {
        None => {
            info!("✔ No new schedule in block ∴ nothing to add to db!");
            Ok(state)
        }
        Some(new_schedule) => {
            info!("✔ New producers schedule version {} found in EOS block, adding to db...", new_schedule.version);
            put_eos_schedule_in_db(&state.db, &new_schedule)
                .and(Ok(state))
        }
    }
}
