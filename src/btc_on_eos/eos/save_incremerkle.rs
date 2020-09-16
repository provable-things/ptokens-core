use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::{
        eos::{
            eos_state::EosState,
            eos_database_utils::put_incremerkle_in_db,
        },
    },
};

pub fn save_incremerkle_from_state_to_db<D>(
    state: EosState<D>
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    info!("✔ Saving incremerkle from state to db...");
    put_incremerkle_in_db(&state.db, &state.incremerkle)
        .and(Ok(state))
}
