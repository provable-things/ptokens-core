use bitcoin::{
    hashes::{sha256d, Hash},
    BlockHash,
};

use crate::{
    chains::btc::{
        btc_constants::PTOKEN_GENESIS_HASH_KEY,
        btc_database_utils::{
            get_btc_anchor_block_from_db,
            get_btc_linker_hash_from_db,
            get_btc_tail_block_from_db,
            maybe_get_parent_btc_block_and_id,
            put_btc_linker_hash_in_db,
        },
        btc_state::BtcState,
    },
    traits::DatabaseInterface,
    types::Result,
};

fn calculate_linker_hash(
    hash_to_link_to: &BlockHash,
    anchor_block_hash: &BlockHash,
    linker_hash: &BlockHash,
) -> Result<BlockHash> {
    debug!("✔ Calculating linker hash...");
    debug!("✔ Hash to link to: {}", hex::encode(hash_to_link_to));
    debug!("✔ Anchor block hash: {}", hex::encode(anchor_block_hash));
    debug!("✔ Linker hash: {}", hex::encode(linker_hash));
    let mut data_to_be_hashed = Vec::new();
    hash_to_link_to
        .to_vec()
        .iter()
        .cloned()
        .for_each(|byte| data_to_be_hashed.push(byte));
    anchor_block_hash
        .to_vec()
        .iter()
        .cloned()
        .for_each(|byte| data_to_be_hashed.push(byte));
    linker_hash
        .to_vec()
        .iter()
        .cloned()
        .for_each(|byte| data_to_be_hashed.push(byte));
    Ok(BlockHash::from_slice(&sha256d::Hash::hash(&data_to_be_hashed))?)
}

pub fn get_linker_hash_or_genesis_hash<D>(db: &D) -> Result<BlockHash>
where
    D: DatabaseInterface,
{
    match get_btc_linker_hash_from_db(db) {
        Ok(hash) => {
            trace!("✔ BTC linker hash exists in DB!");
            Ok(hash)
        },
        _ => {
            trace!("✔ No BTC linker has in db, using genesis hash...");
            Ok(BlockHash::from_slice(&PTOKEN_GENESIS_HASH_KEY.to_vec())?)
        },
    }
}

fn get_new_linker_hash<D>(db: &D, block_hash_to_link_to: &BlockHash) -> Result<BlockHash>
where
    D: DatabaseInterface,
{
    info!("✔ Calculating new linker hash...");
    get_btc_anchor_block_from_db(db).and_then(|anchor_block| {
        calculate_linker_hash(
            block_hash_to_link_to,
            &anchor_block.id,
            &get_linker_hash_or_genesis_hash(db)?,
        )
    })
}

pub fn maybe_update_btc_linker_hash<D>(state: BtcState<D>) -> Result<BtcState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Maybe updating BTC linker hash...");
    get_btc_tail_block_from_db(&state.db).and_then(|btc_tail_block| {
        match maybe_get_parent_btc_block_and_id(&state.db, &btc_tail_block.id) {
            Some(parent_btc_block) => {
                info!("✔ BTC tail block has parent in db ∴ updating BTC linker hash!");
                put_btc_linker_hash_in_db(&state.db, &get_new_linker_hash(&state.db, &parent_btc_block.id)?)
                    .and(Ok(state))
            },
            None => {
                info!("✔ BTC tail block has no parent in db ∴ NOT updating BTC linker hash!");
                Ok(state)
            },
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_calculate_linker_hash_correctly() {
        let genesis_hash = BlockHash::from_slice(&PTOKEN_GENESIS_HASH_KEY.to_vec()).unwrap();
        let hash_to_link_to = BlockHash::from_slice(
            &hex::decode("0000000000000000000014e600bf5c544e6cc08b7f8514e5e3e4abd41891c8ba").unwrap(),
        )
        .unwrap();
        let anchor = BlockHash::from_slice(
            &hex::decode("00000000000000000005a4928a729b77d4fadc72253d006d77a46aea41c13504").unwrap(),
        )
        .unwrap();
        let result = hex::encode(calculate_linker_hash(&hash_to_link_to, &anchor, &genesis_hash).unwrap());
        let expected_result = "23b12747466db4476f5c66ebc5fb05e2f0e6c2ba9dc74d7104fb76400ffb1631";
        assert_eq!(result, expected_result);
    }
}
