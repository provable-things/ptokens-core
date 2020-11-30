use bitcoin_hashes::{
    Hash,
    sha256d,
};
use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::{
        btc_state::BtcState,
        btc_constants::PTOKEN_GENESIS_HASH,
        btc_database_utils::{
            put_btc_linker_hash_in_db,
            get_btc_tail_block_from_db,
            get_btc_linker_hash_from_db,
            get_btc_anchor_block_from_db,
            maybe_get_parent_btc_block_and_id,
        },
    },
};

fn calculate_linker_hash(
    hash_to_link_to: &sha256d::Hash,
    anchor_block_hash: &sha256d::Hash,
    linker_hash: &sha256d::Hash,
) -> sha256d::Hash {
    debug!("✔ Calculating linker hash...");
    debug!("✔ Hash to link to: {}", hex::encode(hash_to_link_to));
    let mut data = Vec::new();
    hash_to_link_to.to_vec().iter().cloned().for_each(|byte| data.push(byte));
    anchor_block_hash.to_vec().iter().cloned().for_each(|byte| data.push(byte));
    linker_hash.to_vec().iter().cloned().for_each(|byte| data.push(byte));
    sha256d::Hash::hash(&data)
}

pub fn get_linker_hash_or_genesis_hash<D>(
    db: &D
) -> Result<sha256d::Hash>
    where D: DatabaseInterface
{
    match get_btc_linker_hash_from_db(db) {
        Ok(hash) => {
            trace!("✔ BTC linker hash exists in DB!");
            Ok(hash)
        }
        _ => {
            trace!("✔ No BTC linker has in db, using genesis hash...");
            Ok(sha256d::Hash::from_slice(&PTOKEN_GENESIS_HASH.to_vec())?)
        }
    }
}

fn get_new_linker_hash<D>(
    db: &D,
    block_hash_to_link_to: &sha256d::Hash,
) -> Result<sha256d::Hash>
    where D: DatabaseInterface
{
    info!("✔ Calculating new linker hash...");
    get_btc_anchor_block_from_db(db)
        .and_then(|anchor_block|
            Ok(calculate_linker_hash(&block_hash_to_link_to, &anchor_block.id, &get_linker_hash_or_genesis_hash(db)?))
        )
}

pub fn maybe_update_btc_linker_hash<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe updating BTC linker hash...");
    get_btc_tail_block_from_db(&state.db)
        .and_then(|btc_tail_block|
            match maybe_get_parent_btc_block_and_id(&state.db, &btc_tail_block.id) {
                Some(parent_btc_block) => {
                    info!("✔ BTC tail block has parent in db ∴ updating BTC linker hash!");
                    put_btc_linker_hash_in_db(&state.db, &get_new_linker_hash(&state.db, &parent_btc_block.id)?)
                        .and(Ok(state))
                }
                None => {
                    info!("✔ BTC tail block has no parent in db ∴ NOT updating BTC linker hash!");
                    Ok(state)
                }
            }
        )
}
