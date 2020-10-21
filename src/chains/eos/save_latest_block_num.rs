use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::eos::{
        eos_state::EosState,
        eos_database_utils::put_eos_last_seen_block_num_in_db,
    },
};

pub fn save_latest_block_num_to_db<D>(state: EosState<D>) -> Result<EosState<D>> where D: DatabaseInterface {
    info!("✔ Saving latest EOS block num in db...");
    put_eos_last_seen_block_num_in_db(&state.db, state.get_eos_block_num()?).and(Ok(state))
}
