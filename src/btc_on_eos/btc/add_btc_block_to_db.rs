use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::btc::{
        btc_state::BtcState,
        btc_database_utils::{
            put_btc_block_in_db,
            btc_block_exists_in_db,
        },
    },
};

pub fn maybe_add_btc_block_to_db<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Checking if BTC block is already in the db...");
    match btc_block_exists_in_db(&state.db, &state.get_btc_block_and_id()?.id) {
        true => Err("✘ BTC Block Rejected - it's already in the db!".into()),
        false => {
            let block = state.get_btc_block_in_db_format()?;
            info!("✔ BTC block not in db!");
            info!("✔ Adding BTC block to db: {:?}", block);
            put_btc_block_in_db(&state.db, block)
                .map(|_| {
                    info!("✔ BTC block added to database!");
                    state
                })
        }
    }
}
