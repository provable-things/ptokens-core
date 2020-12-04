use crate::{
    chains::eos::{eos_database_utils::put_eos_last_seen_block_id_in_db, eos_state::EosState},
    traits::DatabaseInterface,
    types::Result,
};

pub fn save_latest_block_id_to_db<D>(state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Saving latest EOS block ID in db...");
    put_eos_last_seen_block_id_in_db(&state.db, &state.get_eos_block_header()?.id()?).and(Ok(state))
}
