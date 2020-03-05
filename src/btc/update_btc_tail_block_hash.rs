use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc::{
        btc_state::BtcState,
        btc_types::BtcBlockInDbFormat,
        btc_constants::BTC_TAIL_LENGTH,
        btc_database_utils::{
            get_btc_tail_block_from_db,
            get_btc_latest_block_from_db,
            put_btc_tail_block_hash_in_db,
            get_btc_canon_to_tip_length_from_db,
            maybe_get_nth_ancestor_btc_block_and_id,
        },
    },
};

fn does_tail_block_require_updating<D>(
    db: &D,
    calculated_tail_block: &BtcBlockInDbFormat,
) -> Result<bool>
    where D: DatabaseInterface
{
    trace!("✔ Checking if BTC tail block needs updating...");
    get_btc_tail_block_from_db(db)
        .map(|db_tail_block|
            db_tail_block.height <= calculated_tail_block.height - 1
        )
}

pub fn maybe_update_btc_tail_block_hash<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe updating BTC tail block hash...");
    let canon_to_tip_length = get_btc_canon_to_tip_length_from_db(&state.db)?;
    get_btc_latest_block_from_db(&state.db)
        .map(|latest_btc_block| {
            info!(
                "✔ Searching for tail block {} blocks back from tip...",
                canon_to_tip_length + BTC_TAIL_LENGTH,
            );
            maybe_get_nth_ancestor_btc_block_and_id(
                &state.db,
                &latest_btc_block.id,
                &(canon_to_tip_length + BTC_TAIL_LENGTH),
            )
        })
        .and_then(|maybe_ancester_block_and_id|
            match maybe_ancester_block_and_id {
                None => {
                    info!(
                        "✔ No {}th ancestor block in db yet ∴ {}",
                        canon_to_tip_length,
                        "not updating tail block hash!",
                    );
                    Ok(state)
                }
                Some(ancestor_block) => {
                    info!(
                        "✔ {}th ancestor block found...",
                        canon_to_tip_length + BTC_TAIL_LENGTH,
                    );
                    match does_tail_block_require_updating(
                        &state.db,
                        &ancestor_block
                    )? {
                        false => {
                            info!("✔ BTC tail block does not require updating");
                            Ok(state)
                        }
                        true => {
                            info!("✔ Updating BTC tail block...");
                            put_btc_tail_block_hash_in_db(
                                &state.db,
                                &ancestor_block.id
                            )
                                .and_then(|_| Ok(state))
                        }
                    }
                }
            }
        )
}
