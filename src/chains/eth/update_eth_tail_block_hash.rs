use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::eth::{
        eth_state::EthState,
        eth_constants::ETH_TAIL_LENGTH,
        eth_submission_material::EthSubmissionMaterial,
        eth_database_utils::{
            get_eth_tail_block_from_db,
            get_eth_latest_block_from_db,
            put_eth_tail_block_hash_in_db,
            get_eth_canon_to_tip_length_from_db,
            maybe_get_nth_ancestor_eth_submission_material,
        },
    },
};

fn does_tail_block_require_updating<D>(
    db: &D,
    calculated_tail_block: &EthSubmissionMaterial,
) -> Result<bool>
    where D: DatabaseInterface
{
    info!("✔ Checking if ETH tail block needs updating...");
    get_eth_tail_block_from_db(db)
        .and_then(|db_tail_block| Ok(db_tail_block.get_block_number()? < calculated_tail_block.get_block_number()?))
}

pub fn maybe_update_eth_tail_block_hash<D>(db: &D) -> Result<()> where D: DatabaseInterface {
    info!("✔ Maybe updating ETH tail block hash...");
    let canon_to_tip_length = get_eth_canon_to_tip_length_from_db(db)?;
    get_eth_latest_block_from_db(db)
        .and_then(|latest_eth_block| {
            info!("✔ Searching for tail block {} blocks back from tip...", canon_to_tip_length + ETH_TAIL_LENGTH);
            maybe_get_nth_ancestor_eth_submission_material(
                db,
                &latest_eth_block.get_block_hash()?,
                canon_to_tip_length + ETH_TAIL_LENGTH,
            )
        })
        .and_then(|maybe_ancester_block_and_id|
            match maybe_ancester_block_and_id {
                None => {
                    info!("✔ No {}th ancestor block in db ∴ {}", canon_to_tip_length, "not updating tail block hash!");
                    Ok(())
                }
                Some(ancestor_block) => {
                    info!("✔ {}th ancestor block found...", canon_to_tip_length + ETH_TAIL_LENGTH);
                    match does_tail_block_require_updating(db, &ancestor_block)? {
                        false => {
                            info!("✔ ETH tail block does not require updating");
                            Ok(())
                        }
                        true => {
                            info!("✔ Updating ETH tail block...");
                            put_eth_tail_block_hash_in_db(db, &ancestor_block.get_block_hash()?)
                        }
                    }
                }
            }
        )
}

pub fn maybe_update_eth_tail_block_hash_and_return_state<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe updating ETH tail block hash...");
    maybe_update_eth_tail_block_hash(&state.db).and(Ok(state))
}
