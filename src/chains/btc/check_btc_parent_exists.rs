use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::{
        btc_state::BtcState,
        btc_database_utils::get_btc_block_from_db,
    },
};

pub fn check_for_parent_of_btc_block_in_state<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Checking BTC block's parent exists in database...");
    match get_btc_block_from_db(&state.db, &state.get_btc_block_and_id()?.block.header.prev_blockhash) {
        Ok(_)=> {
            info!("✔ BTC block's parent exists in database!");
            Ok(state)
        },
        _ => Err("✘ BTC block Rejected - no parent exists in database!".into()),
    }
}
