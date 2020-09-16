use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::btc_constants::BTC_CANON_BLOCK_HASH_KEY,
    btc_on_eos::btc::{
        btc_state::BtcState,
        btc_database_utils::{
            key_exists_in_db,
            put_btc_canon_block_hash_in_db,
        },
    },
};

pub fn maybe_set_btc_canon_block_hash<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
   where D: DatabaseInterface
{
    info!("✔ Checking BTC canon block hash is set in database...");
    match key_exists_in_db(
        &state.db,
        &BTC_CANON_BLOCK_HASH_KEY.to_vec(),
        None,
    ) {
        true => {
            info!("✔ BTC canon block hash set in database!");
            Ok(state)
        },
        false => {
            info!("✔ Setting BTC canon block hash from block in state...");
            put_btc_canon_block_hash_in_db(
                &state.db,
                &state.get_btc_block_and_id()?.id
            ).map(|_| state)
        }
    }
}
