use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::{
        eos::{
            eos_state::EosState,
            eos_database_utils::get_incremerkle_from_db,
        },
    },
};

pub fn get_incremerkle_and_add_to_state<D>(
    state: EosState<D>
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    get_incremerkle_from_db(&state.db)
        .map(|incremerkle| state.add_incremerkle(incremerkle))
}
