use crate::{
    chains::eth::{eth_database_utils::eth_block_exists_in_db, eth_state::EthState},
    traits::DatabaseInterface,
    types::Result,
};

pub fn check_for_parent_of_block_in_state<D: DatabaseInterface>(state: EthState<D>) -> Result<EthState<D>> {
    info!("✔ Checking block's parent exists in database...");
    match eth_block_exists_in_db(&state.db, &state.get_parent_hash()?) {
        true => {
            info!("✔ Block's parent exists in database!");
            Ok(state)
        },
        false => Err("✘ Block Rejected - no parent exists in database!".into()),
    }
}
