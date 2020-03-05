use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc::{
        btc_state::BtcState,
        btc_constants::BTC_ANCHOR_BLOCK_HASH_KEY,
        btc_database_utils::{
            key_exists_in_db,
            put_btc_anchor_block_hash_in_db,
        }
    },
};

pub fn is_btc_anchor_block_hash_set<D>(
    db: &D
) -> bool
    where D: DatabaseInterface
{
    key_exists_in_db(db, &BTC_ANCHOR_BLOCK_HASH_KEY.to_vec(), None)
}

pub fn maybe_set_btc_anchor_block_hash<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Checking BTC anchor block hash is set in database...");
    match is_btc_anchor_block_hash_set(&state.db) {
        true => {
            info!("✔ BTC anchor block hash set in database");
            Ok(state)
        },
        false => {
            info!("✔ Setting BTC anchor hash from block in state...");
            put_btc_anchor_block_hash_in_db(
                &state.db,
                &state.get_btc_block_and_id()?.id
            )
                .and_then(|_| Ok(state))
        }
    }
}
