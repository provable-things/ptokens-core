use bitcoin::network::constants::Network as BtcNetwork;
use bitcoin_hashes::{sha256d, Hash};

use crate::{
    chains::btc::{
        btc_block::BtcBlockInDbFormat,
        btc_constants::{
            BTC_ACCOUNT_NONCE_KEY,
            BTC_ADDRESS_KEY,
            BTC_ANCHOR_BLOCK_HASH_KEY,
            BTC_CANON_BLOCK_HASH_KEY,
            BTC_CANON_TO_TIP_LENGTH_KEY,
            BTC_DIFFICULTY_THRESHOLD,
            BTC_FEE_KEY,
            BTC_LATEST_BLOCK_HASH_KEY,
            BTC_LINKER_HASH_KEY,
            BTC_NETWORK_KEY,
            BTC_PRIVATE_KEY_DB_KEY,
            BTC_PUBLIC_KEY_DB_KEY,
            BTC_TAIL_BLOCK_HASH_KEY,
        },
        btc_crypto::btc_private_key::BtcPrivateKey,
        btc_state::BtcState,
        btc_types::BtcPubKeySlice,
        btc_utils::{
            convert_btc_address_to_bytes,
            convert_btc_network_to_bytes,
            convert_bytes_to_btc_address,
            convert_bytes_to_btc_network,
            convert_bytes_to_btc_pub_key_slice,
        },
    },
    constants::MIN_DATA_SENSITIVITY_LEVEL,
    database_utils::{get_u64_from_db, put_u64_in_db},
    errors::AppError,
    traits::DatabaseInterface,
    types::{Byte, DataSensitivity, Result},
    utils::{convert_bytes_to_u64, convert_u64_to_bytes},
};

pub fn put_btc_pub_key_slice_in_db<D: DatabaseInterface>(db: &D, pub_key_slice: &BtcPubKeySlice) -> Result<()> {
    db.put(
        BTC_PUBLIC_KEY_DB_KEY.to_vec(),
        pub_key_slice.to_vec(),
        MIN_DATA_SENSITIVITY_LEVEL,
    )
}

pub fn get_btc_public_key_slice_from_db<D: DatabaseInterface>(db: &D) -> Result<BtcPubKeySlice> {
    db.get(BTC_PUBLIC_KEY_DB_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .and_then(|bytes| convert_bytes_to_btc_pub_key_slice(&bytes))
}

pub fn increment_btc_account_nonce_in_db<D: DatabaseInterface>(db: &D, amount_to_increment_by: u64) -> Result<()> {
    info!("✔ Incrementing BTC account nonce in db...");
    get_btc_account_nonce_from_db(db).and_then(|nonce| put_btc_account_nonce_in_db(db, nonce + amount_to_increment_by))
}

pub fn start_btc_db_transaction<D: DatabaseInterface>(state: BtcState<D>) -> Result<BtcState<D>> {
    state.db.start_transaction().map(|_| {
        info!("✔ Database transaction begun for BTC block submission!");
        state
    })
}

pub fn end_btc_db_transaction<D: DatabaseInterface>(state: BtcState<D>) -> Result<BtcState<D>> {
    state.db.end_transaction().map(|_| {
        info!("✔ Database transaction ended for BTC block submission!");
        state
    })
}

pub fn get_btc_account_nonce_from_db<D: DatabaseInterface>(db: &D) -> Result<u64> {
    trace!("✔ Getting BTC account nonce from db...");
    get_u64_from_db(db, &BTC_ACCOUNT_NONCE_KEY.to_vec())
}

pub fn put_btc_account_nonce_in_db<D: DatabaseInterface>(db: &D, nonce: u64) -> Result<()> {
    trace!("✔ Putting BTC account nonce of {} in db...", nonce);
    put_u64_in_db(db, &BTC_ACCOUNT_NONCE_KEY.to_vec(), nonce)
}

pub fn get_btc_fee_from_db<D: DatabaseInterface>(db: &D) -> Result<u64> {
    trace!("✔ Getting BTC fee from db...");
    db.get(BTC_FEE_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .and_then(|bytes| convert_bytes_to_u64(&bytes))
}

pub fn put_btc_fee_in_db<D: DatabaseInterface>(db: &D, fee: u64) -> Result<()> {
    trace!("✔ Adding BTC fee of '{}' satoshis-per-byte to db...", fee);
    db.put(
        BTC_FEE_KEY.to_vec(),
        convert_u64_to_bytes(fee),
        MIN_DATA_SENSITIVITY_LEVEL,
    )
}

pub fn get_btc_network_from_db<D: DatabaseInterface>(db: &D) -> Result<BtcNetwork> {
    db.get(BTC_NETWORK_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .and_then(|bytes| convert_bytes_to_btc_network(&bytes))
}

pub fn put_btc_network_in_db<D: DatabaseInterface>(db: &D, network: BtcNetwork) -> Result<()> {
    trace!("✔ Adding BTC '{}' network to database...", network);
    db.put(
        BTC_NETWORK_KEY.to_vec(),
        convert_btc_network_to_bytes(network)?,
        MIN_DATA_SENSITIVITY_LEVEL,
    )
}

pub fn put_btc_difficulty_in_db<D: DatabaseInterface>(db: &D, difficulty: u64) -> Result<()> {
    trace!("✔ Putting BTC difficulty threshold of {} in db...", difficulty);
    db.put(
        BTC_DIFFICULTY_THRESHOLD.to_vec(),
        convert_u64_to_bytes(difficulty),
        MIN_DATA_SENSITIVITY_LEVEL,
    )
}

pub fn get_btc_difficulty_from_db<D: DatabaseInterface>(db: &D) -> Result<u64> {
    trace!("✔ Getting BTC difficulty threshold from db...");
    db.get(BTC_DIFFICULTY_THRESHOLD.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .and_then(|bytes| convert_bytes_to_u64(&bytes))
}

pub fn get_latest_btc_block_number<D: DatabaseInterface>(db: &D) -> Result<u64> {
    trace!("✔ Getting BTC latest block number from db...");
    get_btc_latest_block_from_db(db).map(|block_and_id| block_and_id.height)
}

pub fn get_special_btc_block_from_db<D: DatabaseInterface>(db: &D, block_type: &str) -> Result<BtcBlockInDbFormat> {
    get_special_hash_from_db(db, block_type).and_then(|block_hash| get_btc_block_from_db(db, &block_hash))
}

pub fn get_special_hash_from_db<D: DatabaseInterface>(db: &D, hash_type: &str) -> Result<sha256d::Hash> {
    let key = match hash_type {
        "tail" => Ok(BTC_TAIL_BLOCK_HASH_KEY.to_vec()),
        "canon" => Ok(BTC_CANON_BLOCK_HASH_KEY.to_vec()),
        "anchor" => Ok(BTC_ANCHOR_BLOCK_HASH_KEY.to_vec()),
        "latest" => Ok(BTC_LATEST_BLOCK_HASH_KEY.to_vec()),
        _ => Err(AppError::Custom(format!(
            "✘ Cannot get special BTC hash of type: {}!",
            hash_type
        ))),
    }?;
    trace!("✔ Getting special BTC hash from db of type: {}", hash_type);
    get_btc_hash_from_db(db, &key.to_vec())
}

pub fn put_special_btc_block_in_db<D: DatabaseInterface>(
    db: &D,
    block_and_id: &BtcBlockInDbFormat,
    block_type: &str,
) -> Result<()> {
    trace!("✔ Putting special BTC block in db of type: {}", block_type);
    put_btc_block_in_db(db, &block_and_id).and_then(|_| put_special_btc_hash_in_db(db, &block_type, &block_and_id.id))
}

pub fn put_special_btc_hash_in_db<D: DatabaseInterface>(db: &D, hash_type: &str, hash: &sha256d::Hash) -> Result<()> {
    let key = match hash_type {
        "tail" => Ok(BTC_TAIL_BLOCK_HASH_KEY.to_vec()),
        "canon" => Ok(BTC_CANON_BLOCK_HASH_KEY.to_vec()),
        "anchor" => Ok(BTC_ANCHOR_BLOCK_HASH_KEY.to_vec()),
        "latest" => Ok(BTC_LATEST_BLOCK_HASH_KEY.to_vec()),
        _ => Err(AppError::Custom(format!(
            "✘ Cannot store special BTC hash of type: {}!",
            hash_type
        ))),
    }?;
    put_btc_hash_in_db(db, &key, hash)
}

pub fn btc_block_exists_in_db<D: DatabaseInterface>(db: &D, btc_block_id: &sha256d::Hash) -> bool {
    info!(
        "✔ Checking for existence of BTC block: {}",
        hex::encode(btc_block_id.to_vec())
    );
    key_exists_in_db(db, &btc_block_id.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
}

pub fn key_exists_in_db<D: DatabaseInterface>(db: &D, key: &[Byte], sensitivity: DataSensitivity) -> bool {
    trace!("✔ Checking for existence of key: {}", hex::encode(key));
    db.get(key.to_vec(), sensitivity).is_ok()
}

pub fn put_btc_canon_to_tip_length_in_db<D: DatabaseInterface>(db: &D, btc_canon_to_tip_length: u64) -> Result<()> {
    db.put(
        BTC_CANON_TO_TIP_LENGTH_KEY.to_vec(),
        convert_u64_to_bytes(btc_canon_to_tip_length),
        MIN_DATA_SENSITIVITY_LEVEL,
    )
}

pub fn get_btc_canon_to_tip_length_from_db<D: DatabaseInterface>(db: &D) -> Result<u64> {
    db.get(BTC_CANON_TO_TIP_LENGTH_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .and_then(|bytes| convert_bytes_to_u64(&bytes))
}

pub fn put_btc_private_key_in_db<D: DatabaseInterface>(db: &D, pk: &BtcPrivateKey) -> Result<()> {
    trace!("✔ Saving BTC private key into db...");
    pk.write_to_db(db, &BTC_PRIVATE_KEY_DB_KEY.to_vec())
}

pub fn get_btc_private_key_from_db<D: DatabaseInterface>(db: &D) -> Result<BtcPrivateKey> {
    db.get(BTC_PRIVATE_KEY_DB_KEY.to_vec(), Some(255))
        .and_then(|bytes| BtcPrivateKey::from_slice(&bytes[..], get_btc_network_from_db(db)?))
}

pub fn put_btc_canon_block_in_db<D: DatabaseInterface>(db: &D, block: &BtcBlockInDbFormat) -> Result<()> {
    trace!("✔ Putting BTC canon block in db...");
    put_special_btc_block_in_db(db, block, "canon")
}

pub fn get_btc_anchor_block_from_db<D: DatabaseInterface>(db: &D) -> Result<BtcBlockInDbFormat> {
    trace!("✔ Getting BTC anchor block from db...");
    get_special_btc_block_from_db(db, "anchor")
}

pub fn get_btc_latest_block_from_db<D: DatabaseInterface>(db: &D) -> Result<BtcBlockInDbFormat> {
    trace!("✔ Getting BTC latest block from db...");
    get_special_btc_block_from_db(db, "latest")
}

pub fn get_btc_tail_block_from_db<D: DatabaseInterface>(db: &D) -> Result<BtcBlockInDbFormat> {
    trace!("✔ Getting BTC tail block from db...");
    get_special_btc_block_from_db(db, "tail")
}

pub fn get_btc_canon_block_from_db<D: DatabaseInterface>(db: &D) -> Result<BtcBlockInDbFormat> {
    trace!("✔ Getting BTC canon block from db...");
    get_special_btc_block_from_db(db, "canon")
}

pub fn get_btc_anchor_block_hash_from_db<D: DatabaseInterface>(db: &D) -> Result<sha256d::Hash> {
    trace!("✔ Getting BTC anchor block hash from db...");
    get_btc_hash_from_db(db, &BTC_ANCHOR_BLOCK_HASH_KEY.to_vec())
}

pub fn put_btc_anchor_block_hash_in_db<D: DatabaseInterface>(db: &D, hash: &sha256d::Hash) -> Result<()> {
    trace!("✔ Putting BTC anchor block hash in db...");
    put_btc_hash_in_db(db, &BTC_ANCHOR_BLOCK_HASH_KEY.to_vec(), hash)
}

pub fn put_btc_latest_block_hash_in_db<D: DatabaseInterface>(db: &D, hash: &sha256d::Hash) -> Result<()> {
    trace!("✔ Putting BTC latest block hash in db...");
    put_btc_hash_in_db(db, &BTC_LATEST_BLOCK_HASH_KEY.to_vec(), hash)
}

pub fn put_btc_tail_block_hash_in_db<D: DatabaseInterface>(db: &D, hash: &sha256d::Hash) -> Result<()> {
    trace!("✔ Putting BTC tail block hash in db...");
    put_btc_hash_in_db(db, &BTC_TAIL_BLOCK_HASH_KEY.to_vec(), hash)
}

pub fn put_btc_canon_block_hash_in_db<D: DatabaseInterface>(db: &D, hash: &sha256d::Hash) -> Result<()> {
    trace!("✔ Putting BTC canon block hash in db...");
    put_btc_hash_in_db(db, &BTC_CANON_BLOCK_HASH_KEY.to_vec(), hash)
}

pub fn get_btc_linker_hash_from_db<D: DatabaseInterface>(db: &D) -> Result<sha256d::Hash> {
    trace!("✔ Getting BTC linker hash from db...");
    get_btc_hash_from_db(db, &BTC_LINKER_HASH_KEY.to_vec())
}

pub fn put_btc_linker_hash_in_db<D: DatabaseInterface>(db: &D, hash: &sha256d::Hash) -> Result<()> {
    trace!("✔ Putting BTC linker hash in db...");
    put_btc_hash_in_db(db, &BTC_LINKER_HASH_KEY.to_vec(), hash)
}

pub fn put_btc_hash_in_db<D: DatabaseInterface>(db: &D, key: &[Byte], hash: &sha256d::Hash) -> Result<()> {
    db.put(key.to_vec(), hash.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
}

pub fn get_btc_hash_from_db<D: DatabaseInterface>(db: &D, key: &[Byte]) -> Result<sha256d::Hash> {
    db.get(key.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .and_then(|bytes| Ok(sha256d::Hash::from_slice(&bytes)?))
}

pub fn maybe_get_parent_btc_block_and_id<D: DatabaseInterface>(
    db: &D,
    id: &sha256d::Hash,
) -> Option<BtcBlockInDbFormat> {
    trace!("✔ Maybe getting BTC parent block for id: {}", id);
    maybe_get_nth_ancestor_btc_block_and_id(db, id, 1)
}

pub fn maybe_get_nth_ancestor_btc_block_and_id<D: DatabaseInterface>(
    db: &D,
    id: &sha256d::Hash,
    n: u64,
) -> Option<BtcBlockInDbFormat> {
    debug!(
        "✔ Maybe getting ancestor #{} of BTC block id: {}",
        n,
        hex::encode(id.to_vec())
    );
    match maybe_get_btc_block_from_db(db, id) {
        None => {
            debug!("✘ No ancestor #{} BTC block found!", n);
            None
        },
        Some(block_in_db_format) => match n {
            0 => Some(block_in_db_format),
            _ => maybe_get_nth_ancestor_btc_block_and_id(db, &block_in_db_format.prev_blockhash, n - 1),
        },
    }
}

pub fn put_btc_address_in_db<D: DatabaseInterface>(db: &D, btc_address: &str) -> Result<()> {
    trace!("✔ Putting BTC address {} in db...", btc_address);
    db.put(
        BTC_ADDRESS_KEY.to_vec(),
        convert_btc_address_to_bytes(btc_address)?,
        MIN_DATA_SENSITIVITY_LEVEL,
    )
}

pub fn get_btc_address_from_db<D: DatabaseInterface>(db: &D) -> Result<String> {
    trace!("✔  Getting BTC address from db...");
    db.get(BTC_ADDRESS_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .map(convert_bytes_to_btc_address)
}

pub fn put_btc_block_in_db<D: DatabaseInterface>(db: &D, block: &BtcBlockInDbFormat) -> Result<()> {
    debug!("✔ Putting BTC block in db: {:?}", block);
    block
        .to_bytes()
        .and_then(|bytes| db.put(block.get_db_key(), bytes, MIN_DATA_SENSITIVITY_LEVEL))
}

pub fn maybe_get_btc_block_from_db<D: DatabaseInterface>(db: &D, id: &sha256d::Hash) -> Option<BtcBlockInDbFormat> {
    trace!("✔ Maybe getting BTC block of id: {}", hex::encode(id.to_vec()));
    match get_btc_block_from_db(db, id) {
        Ok(block_and_id) => {
            trace!("✔ BTC block found!");
            Some(block_and_id)
        },
        Err(e) => {
            trace!("✘ No BTC block found ∵ {}", e);
            None
        },
    }
}

pub fn get_btc_block_from_db<D: DatabaseInterface>(db: &D, id: &sha256d::Hash) -> Result<BtcBlockInDbFormat> {
    trace!("✔ Getting BTC block from db via id: {}", hex::encode(id.to_vec()));
    db.get(id.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .and_then(|bytes| BtcBlockInDbFormat::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::btc::btc_test_utils::{
            get_sample_btc_block_in_db_format,
            get_sample_btc_private_key,
            get_sample_btc_pub_key_slice,
            get_sample_sequential_btc_blocks_in_db_format,
            SAMPLE_TARGET_BTC_ADDRESS,
        },
        test_utils::get_test_database,
    };

    #[test]
    fn non_existing_key_should_not_exist_in_db() {
        let db = get_test_database();
        let result = key_exists_in_db(&db, &BTC_CANON_TO_TIP_LENGTH_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL);
        assert!(!result);
    }

    #[test]
    fn existing_key_should_exist_in_db() {
        let db = get_test_database();
        let length = 5;
        put_btc_canon_to_tip_length_in_db(&db, length).unwrap();
        let result = key_exists_in_db(&db, &BTC_CANON_TO_TIP_LENGTH_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL);
        assert!(result);
    }

    #[test]
    fn should_get_and_put_btc_canon_to_tip_length_in_db() {
        let db = get_test_database();
        let length = 6;
        put_btc_canon_to_tip_length_in_db(&db, length).unwrap();
        let result = get_btc_canon_to_tip_length_from_db(&db).unwrap();
        assert_eq!(result, length);
    }

    #[test]
    fn should_get_and_save_btc_private_key_in_db() {
        let db = get_test_database();
        put_btc_network_in_db(&db, BtcNetwork::Testnet).unwrap();
        let pk = get_sample_btc_private_key();
        put_btc_private_key_in_db(&db, &pk).unwrap();
        let result = get_btc_private_key_from_db(&db).unwrap();
        assert_eq!(result.to_public_key(), pk.to_public_key());
    }

    #[test]
    fn should_error_putting_non_existent_block_type_in_db() {
        let db = get_test_database();
        let non_existent_block_type = "non-existent block type!";
        let block = get_sample_btc_block_in_db_format().unwrap();
        let expected_error = format!("✘ Cannot store special BTC hash of type: {}!", non_existent_block_type);
        match put_special_btc_block_in_db(&db, &block, non_existent_block_type) {
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            Ok(_) => panic!("Should not have succeeded!"),
            _ => panic!("Wrong error received!"),
        }
    }

    #[test]
    fn should_put_special_block_in_db() {
        let db = get_test_database();
        let block = get_sample_btc_block_in_db_format().unwrap();
        let block_type = "canon";
        put_special_btc_block_in_db(&db, &block, block_type).unwrap();
        match get_btc_canon_block_from_db(&db) {
            Err(e) => panic!("Error geting canon block: {}", e),
            Ok(block_from_db) => assert_eq!(block_from_db, block),
        }
    }

    #[test]
    fn should_error_getting_non_existent_special_block() {
        let db = get_test_database();
        let non_existent_block_type = "does not exist";
        let expected_error = format!("✘ Cannot get special BTC hash of type: {}!", non_existent_block_type);
        match get_special_btc_block_from_db(&db, non_existent_block_type) {
            Ok(_) => panic!("Should not have got special block!"),
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            _ => panic!("Wrong error when getting non-existent block type!"),
        }
    }

    #[test]
    fn should_get_special_block_type() {
        let db = get_test_database();
        let block = get_sample_btc_block_in_db_format().unwrap();
        put_btc_block_in_db(&db, &block).unwrap();
        put_btc_anchor_block_hash_in_db(&db, &block.id).unwrap();
        let result = get_special_btc_block_from_db(&db, "anchor").unwrap();
        assert_eq!(result, block);
    }

    #[test]
    fn should_get_and_put_anchor_block_hash_in_db() {
        let db = get_test_database();
        let anchor_block_hash = get_sample_btc_block_in_db_format().unwrap().id;
        put_btc_anchor_block_hash_in_db(&db, &anchor_block_hash).unwrap();
        let result = get_btc_anchor_block_hash_from_db(&db).unwrap();
        assert_eq!(result, anchor_block_hash);
    }

    #[test]
    fn should_put_latest_block_hash_in_db() {
        let db = get_test_database();
        let latest_block_hash = get_sample_btc_block_in_db_format().unwrap().id;
        put_btc_latest_block_hash_in_db(&db, &latest_block_hash).unwrap();
    }

    #[test]
    fn should_put_canon_block_hash_in_db() {
        let db = get_test_database();
        let canon_block_hash = get_sample_btc_block_in_db_format().unwrap().id;
        put_btc_canon_block_hash_in_db(&db, &canon_block_hash).unwrap();
    }

    #[test]
    fn should_get_and_put_linker_hash_in_db() {
        let db = get_test_database();
        let linker_hash = get_sample_btc_block_in_db_format().unwrap().id;
        put_btc_linker_hash_in_db(&db, &linker_hash).unwrap();
        let result = get_btc_linker_hash_from_db(&db).unwrap();
        assert_eq!(result, linker_hash);
    }

    #[test]
    fn should_put_hash_in_db() {
        let db = get_test_database();
        let hash = get_sample_btc_block_in_db_format().unwrap().id;
        put_btc_hash_in_db(&db, &BTC_LINKER_HASH_KEY.to_vec(), &hash).unwrap();
        let result = get_btc_hash_from_db(&db, &BTC_LINKER_HASH_KEY.to_vec()).unwrap();
        assert_eq!(result, hash);
    }

    #[test]
    fn should_not_get_parent_block_if_non_existent() {
        let db = get_test_database();
        let test_block = get_sample_btc_block_in_db_format().unwrap();
        assert!(maybe_get_parent_btc_block_and_id(&db, &test_block.id).is_none());
    }

    #[test]
    fn should_get_parent_block() {
        let db = get_test_database();
        let blocks = get_sample_sequential_btc_blocks_in_db_format();
        let test_block = blocks[blocks.len() - 1].clone();
        let expected_result = blocks[blocks.len() - 2].clone();
        blocks
            .iter()
            .map(|block| put_btc_block_in_db(&db, &block))
            .collect::<Result<()>>()
            .unwrap();
        let result = maybe_get_parent_btc_block_and_id(&db, &test_block.id).unwrap();
        assert_eq!(result, expected_result);
        assert!(result.id == test_block.prev_blockhash);
    }

    #[test]
    fn should_get_and_put_btc_block_in_db() {
        let db = get_test_database();
        let block_and_id = get_sample_btc_block_in_db_format().unwrap();
        put_btc_block_in_db(&db, &block_and_id).unwrap();
        let result = get_btc_block_from_db(&db, &block_and_id.id).unwrap();
        assert_eq!(result, block_and_id);
    }

    #[test]
    fn should_get_and_put_btc_address_in_database() {
        let db = get_test_database();
        put_btc_address_in_db(&db, &SAMPLE_TARGET_BTC_ADDRESS.to_string()).unwrap();
        let result = get_btc_address_from_db(&db).unwrap();
        assert_eq!(result, SAMPLE_TARGET_BTC_ADDRESS);
    }

    #[test]
    fn should_get_and_put_btc_fee_in_db() {
        let fee = 666;
        let db = get_test_database();
        put_btc_fee_in_db(&db, fee).unwrap();
        let result = get_btc_fee_from_db(&db).unwrap();
        assert_eq!(result, fee)
    }

    #[test]
    fn should_get_and_put_btc_network_in_db() {
        let db = get_test_database();
        let network = BtcNetwork::Bitcoin;
        put_btc_network_in_db(&db, network).unwrap();
        let result = get_btc_network_from_db(&db).unwrap();
        assert_eq!(result, network)
    }

    #[test]
    fn should_get_and_put_btc_difficulty_in_db() {
        let difficulty = 1337;
        let db = get_test_database();
        put_btc_difficulty_in_db(&db, difficulty).unwrap();
        let result = get_btc_difficulty_from_db(&db).unwrap();
        assert_eq!(result, difficulty)
    }

    #[test]
    fn should_maybe_get_btc_block_from_db_if_none_extant() {
        let db = get_test_database();
        let block = get_sample_btc_block_in_db_format().unwrap();
        let block_hash = block.id;
        assert!(maybe_get_btc_block_from_db(&db, &block_hash).is_none());
    }

    #[test]
    fn should_maybe_get_btc_block_from_db_if_extant() {
        let db = get_test_database();
        let block = get_sample_btc_block_in_db_format().unwrap();
        put_btc_block_in_db(&db, &block).unwrap();
        let block_hash = block.id;
        let result = maybe_get_btc_block_from_db(&db, &block_hash).unwrap();
        assert_eq!(result, block);
    }

    #[test]
    fn none_existent_block_should_not_exist_in_db() {
        let db = get_test_database();
        let block_hash = get_sample_btc_block_in_db_format().unwrap().id;
        let result = btc_block_exists_in_db(&db, &block_hash);
        assert!(!result);
    }

    #[test]
    fn existing_block_should_exist_in_db() {
        let db = get_test_database();
        let block = get_sample_btc_block_in_db_format().unwrap();
        put_btc_block_in_db(&db, &block).unwrap();
        let block_hash = block.id;
        let result = btc_block_exists_in_db(&db, &block_hash);
        assert!(result);
    }

    #[test]
    fn should_save_and_get_btc_pub_key_slice_from_db() {
        let db = get_test_database();
        let pub_key_slice = get_sample_btc_pub_key_slice();
        put_btc_pub_key_slice_in_db(&db, &pub_key_slice).unwrap();
        let result = get_btc_public_key_slice_from_db(&db).unwrap();
        result
            .iter()
            .enumerate()
            .for_each(|(i, e)| assert_eq!(e, &pub_key_slice[i]));
    }
}
