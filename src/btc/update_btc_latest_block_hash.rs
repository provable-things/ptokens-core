use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc::{
        btc_state::BtcState,
        btc_database_utils::{
            get_btc_latest_block_from_db,
            put_btc_latest_block_hash_in_db,
        },
    },
};

fn is_block_subsequent(
    block_in_question_height: &u64,
    latest_block_from_database_height: &u64,
) -> bool {
    latest_block_from_database_height == &(block_in_question_height + 1)
}

pub fn maybe_update_btc_latest_block_hash<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    get_btc_latest_block_from_db(&state.db)
        .and_then(|latest_block_and_id|
            match is_block_subsequent(
                &latest_block_and_id.height,
                &state.get_btc_block_and_id()?.height,
            ) {
                false => {
                    info!(
                        "✔ BTC block NOT subsequent {}",
                        "∴ NOT updating latest block hash",
                    );
                    Ok(state)
                }
                true => {
                    info!(
                        "✔ BTC block IS subsequent {}",
                        "∴ updating latest block hash...",
                    );
                    put_btc_latest_block_hash_in_db(
                        &state.db,
                        &state.get_btc_block_and_id()?.id,
                    )
                        .and_then(|_| Ok(state))
                }
            }
        )
}
