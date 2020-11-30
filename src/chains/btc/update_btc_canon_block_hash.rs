use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::{
        btc_state::BtcState,
        btc_block::BtcBlockInDbFormat,
        btc_database_utils::{
            get_btc_canon_block_from_db,
            get_btc_latest_block_from_db,
            put_btc_canon_block_hash_in_db,
            get_btc_canon_to_tip_length_from_db,
            maybe_get_nth_ancestor_btc_block_and_id,
        },
    },
};

fn does_canon_block_require_updating<D>(
    db: &D,
    calculated_canon_block: &BtcBlockInDbFormat,
) -> Result<bool>
    where D: DatabaseInterface
{
    info!("✔ Checking if BTC canon block needs updating...");
    get_btc_canon_block_from_db(db)
        .map(|db_canon_block_and_receipts|
            db_canon_block_and_receipts.height <
                calculated_canon_block.height
        )
}

pub fn maybe_update_btc_canon_block_hash<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe updating BTC canon block hash...");
    let canon_to_tip_length = get_btc_canon_to_tip_length_from_db(&state.db)?;
    get_btc_latest_block_from_db(&state.db)
        .map(|latest_btc_block| {
            maybe_get_nth_ancestor_btc_block_and_id(
                &state.db,
                &latest_btc_block.id,
                canon_to_tip_length,
            )
        })
        .and_then(|maybe_ancester_block_and_id|
            match maybe_ancester_block_and_id {
                None => {
                    info!(
                        "✔ No {}th ancestor block in db yet ∴ {}",
                        canon_to_tip_length,
                        "not updating canon block hash!",
                    );
                    Ok(state)
                }
                Some(ancestor_block) => {
                    info!(
                        "✔ {}th ancestor block found...",
                        canon_to_tip_length,
                    );
                    match does_canon_block_require_updating(
                        &state.db,
                        &ancestor_block
                    )? {
                        false => {
                            info!("✔ BTC canon block does not require updating");
                            Ok(state)
                        }
                        true => {
                            info!("✔ Updating BTC canon block...");
                            put_btc_canon_block_hash_in_db(
                                &state.db,
                                &ancestor_block.id
                            ).map(|_| state)
                        }
                    }
                }
            }
        )
}
