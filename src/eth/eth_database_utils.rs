use ethereum_types::{
    H256 as EthHash,
    Address as EthAddress,
};
use crate::{
    errors::AppError,
    traits::DatabaseInterface,
    types::{
        Bytes,
        Result,
        DataSensitivity,
    },
    database_utils::{
        put_u64_in_db,
        get_u64_from_db,
    },
    utils::{
        convert_bytes_to_u64,
        convert_u64_to_bytes,
        convert_h256_to_bytes,
        convert_bytes_to_h256,
    },
    eth::{
        eth_state::EthState,
        eth_types::EthBlockAndReceipts,
        eth_crypto::eth_private_key::EthPrivateKey,
        eth_constants::{
            ETH_ADDRESS_KEY,
            ETH_CHAIN_ID_KEY,
            ETH_GAS_PRICE_KEY,
            ETH_LINKER_HASH_KEY,
            ETH_ACCOUNT_NONCE_KEY,
            ETH_PRIVATE_KEY_DB_KEY,
            ETH_TAIL_BLOCK_HASH_KEY,
            ETH_CANON_BLOCK_HASH_KEY,
            ETH_LATEST_BLOCK_HASH_KEY,
            ETH_ANCHOR_BLOCK_HASH_KEY,
            ETH_CANON_TO_TIP_LENGTH_KEY,
            ETH_SMART_CONTRACT_ADDRESS_KEY,
        },
        eth_json_codec::{
            encode_eth_block_and_receipts_as_json_bytes,
            decode_eth_block_and_receipts_from_json_bytes,
        },
    },
};

pub fn start_eth_db_transaction<D>(
    state: EthState<D>,
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    state
        .db
        .start_transaction()
        .map(|_| {
            info!("✔ Database transaction begun for ETH block submission!");
            state
        })
}

pub fn end_eth_db_transaction<D>(
    state: EthState<D>,
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    state
        .db
        .end_transaction()
        .map(|_| {
            info!("✔ Database transaction ended for ETH block submission!");
            state
        })
}

pub fn put_eth_canon_to_tip_length_in_db<D>(
    db: &D,
    length: &u64,
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Putting ETH canon-to-tip length of {} in db...", length);
    db.put(
        ETH_CANON_TO_TIP_LENGTH_KEY.to_vec(),
        convert_u64_to_bytes(length),
        None,
    )
}

pub fn get_eth_canon_to_tip_length_from_db<D>(db: &D) -> Result<u64>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH canon-to-tip length from db...");
    db.get(ETH_CANON_TO_TIP_LENGTH_KEY.to_vec(), None)
        .and_then(|bytes| convert_bytes_to_u64(&bytes))
}

pub fn put_eth_latest_block_in_db<D>(
    db: &D,
    eth_block_and_receipts: &EthBlockAndReceipts,
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Putting ETH latest block in db...");
    put_special_eth_block_in_db(db, eth_block_and_receipts, "latest")
}

pub fn put_eth_anchor_block_in_db<D>(
    db: &D,
    eth_block_and_receipts: &EthBlockAndReceipts,
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Putting ETH anchor block in db...");
    put_special_eth_block_in_db(db, eth_block_and_receipts, "anchor")
}

pub fn put_eth_canon_block_in_db<D>(
    db: &D,
    eth_block_and_receipts: &EthBlockAndReceipts,
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Putting ETH canon block in db...");
    put_special_eth_block_in_db(db, eth_block_and_receipts, "canon")
}

pub fn put_eth_tail_block_in_db<D>(
    db: &D,
    eth_block_and_receipts: &EthBlockAndReceipts,
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Putting ETH tail block in db...");
    put_special_eth_block_in_db(db, eth_block_and_receipts, "tail")
}

pub fn put_eth_latest_block_hash_in_db<D>(
    db: &D,
    eth_hash: &EthHash
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Putting ETH latest block hash in db...");
    put_special_eth_hash_in_db(db, "latest", eth_hash)
}

pub fn put_eth_anchor_block_hash_in_db<D>(
    db: &D,
    eth_hash: &EthHash
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Putting ETH anchor block hash in db...");
    put_special_eth_hash_in_db(db, "anchor", eth_hash)
}

pub fn put_eth_canon_block_hash_in_db<D>(
    db: &D,
    eth_hash: &EthHash
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Putting ETH canon block hash in db...");
    put_special_eth_hash_in_db(db, "canon", eth_hash)
}

pub fn put_eth_tail_block_hash_in_db<D>(
    db: &D,
    eth_hash: &EthHash
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Putting ETH tail block hash in db...");
    put_special_eth_hash_in_db(db, "tail", eth_hash)
}

pub fn put_eth_linker_hash_in_db<D>(
    db: &D,
    eth_hash: EthHash
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Putting ETH linker hash in db...");
    put_special_eth_hash_in_db(db, "linker", &eth_hash)
}

pub fn put_special_eth_block_in_db<D>(
    db: &D,
    eth_block_and_receipts: &EthBlockAndReceipts,
    block_type: &str,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting ETH special block in db of type: {}", block_type);
    put_eth_block_and_receipts_in_db(db, &eth_block_and_receipts)
        .and_then(|_|
            put_special_eth_hash_in_db(
                db,
                &block_type,
                &eth_block_and_receipts.block.hash
            )
        )
}

pub fn put_special_eth_hash_in_db<D>(
    db: &D,
    hash_type: &str,
    hash: &EthHash,
) -> Result<()>
    where D: DatabaseInterface
{
    let key = match hash_type {
        "linker" => Ok(ETH_LINKER_HASH_KEY.to_vec()),
        "canon" => Ok(ETH_CANON_BLOCK_HASH_KEY.to_vec()),
        "tail" => Ok(ETH_TAIL_BLOCK_HASH_KEY.to_vec()),
        "anchor" => Ok(ETH_ANCHOR_BLOCK_HASH_KEY.to_vec()),
        "latest" => Ok(ETH_LATEST_BLOCK_HASH_KEY.to_vec()),
        _ => Err(AppError::Custom(
            format!("✘ Cannot store special ETH hash of type: {}!", hash_type)
        ))
    }?;
    put_eth_hash_in_db(db, &key, hash)
}

pub fn get_latest_eth_block_number<D>(db: &D) -> Result<usize>
    where D: DatabaseInterface
{
    info!("✔ Getting latest ETH block number from db...");
    match get_special_eth_block_from_db(db, "latest") {
        Ok(result) => Ok(result.block.number.as_usize()),
        Err(e) => Err(e)
    }
}

pub fn get_eth_tail_block_from_db<D>(db: &D) -> Result<EthBlockAndReceipts>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH tail block from db...");
    get_special_eth_block_from_db(db, "tail")
}

pub fn get_eth_latest_block_from_db<D>(db: &D) -> Result<EthBlockAndReceipts>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH latest block from db...");
    get_special_eth_block_from_db(db, "latest")
}

pub fn get_eth_anchor_block_from_db<D>(db: &D) -> Result<EthBlockAndReceipts>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH anchor block from db...");
    get_special_eth_block_from_db(db, "anchor")
}

pub fn get_eth_canon_block_from_db<D>(
    db: &D
) -> Result<EthBlockAndReceipts>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH canon block from db...");
    get_special_eth_block_from_db(db, "canon")
}

pub fn get_eth_tail_block_hash_from_db<D>(db: &D) -> Result<EthHash>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH tail block hash from db...");
    get_special_eth_hash_from_db(db, "tail")
}

pub fn get_eth_latest_block_hash_from_db<D>(db: &D) -> Result<EthHash>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH latest block hash from db...");
    get_special_eth_hash_from_db(db, "latest")
}

pub fn get_eth_anchor_block_hash_from_db<D>(db: &D) -> Result<EthHash>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH anchor block hash from db...");
    get_special_eth_hash_from_db(db, "anchor")
}

pub fn get_eth_canon_block_hash_from_db<D>(db: &D) -> Result<EthHash>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH canon block hash from db...");
    get_special_eth_hash_from_db(db, "canon")
}

pub fn get_eth_linker_hash_from_db<D>(db: &D) -> Result<EthHash>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH linker hash from db...");
    get_special_eth_hash_from_db(db, "linker")
}

pub fn get_special_eth_hash_from_db<D>(
    db: &D,
    hash_type: &str,
) -> Result<EthHash>
    where D: DatabaseInterface
{
    let key = match hash_type {
        "linker" => Ok(ETH_LINKER_HASH_KEY),
        "canon" => Ok(ETH_CANON_BLOCK_HASH_KEY),
        "tail" => Ok(ETH_TAIL_BLOCK_HASH_KEY),
        "anchor" => Ok(ETH_ANCHOR_BLOCK_HASH_KEY),
        "latest" => Ok(ETH_LATEST_BLOCK_HASH_KEY),
        _ => Err(AppError::Custom(
            format!("✘ Cannot get ETH special hash of type: {}!", hash_type)
        ))
    }?;
    trace!("✔ Getting special ETH hash from db of type: {}", hash_type);
    get_eth_hash_from_db(db, &key.to_vec())
}

pub fn get_eth_hash_from_db<D>(db: &D, key: &Bytes) -> Result<EthHash>
    where D: DatabaseInterface
{
    trace!(
        "✔ Getting ETH hash from db under key: {}",
        hex::encode(&key)
    );
    db.get(key.to_vec(), None)
        .and_then(|bytes| Ok(EthHash::from_slice(&bytes)))
}

pub fn get_special_eth_block_from_db<D>(
    db: &D,
    block_type: &str,
) -> Result<EthBlockAndReceipts>
    where D: DatabaseInterface
{
    get_special_eth_hash_from_db(db, block_type)
        .and_then(|block_hash| get_eth_block_from_db(db, &block_hash))
}

pub fn put_eth_hash_in_db<D>(
    db: &D,
    key: &Bytes,
    eth_hash: &EthHash
) -> Result<()>
    where D: DatabaseInterface
{
    db.put(key.to_vec(), convert_h256_to_bytes(*eth_hash), None)
}

pub fn eth_block_exists_in_db<D>(db: &D, block_hash: &EthHash) -> bool
    where D: DatabaseInterface
{
    info!(
        "✔ Checking for existence of ETH block: {}",
       hex::encode(block_hash.as_bytes().to_vec())
   );
    key_exists_in_db(db, &block_hash.as_bytes().to_vec(), None)
}

pub fn get_hash_from_db_via_hash_key<D>(
    db: &D,
    hash_key: EthHash,
) -> Result<Option<EthHash>>
    where D: DatabaseInterface
{
    match db.get(convert_h256_to_bytes(hash_key), None) {
        Ok(bytes) => Ok(Some(convert_bytes_to_h256(&bytes)?)),
        Err(_) => Ok(None),
    }
}

pub fn put_eth_block_and_receipts_in_db<D>(
    db: &D,
    eth_block_and_receipts: &EthBlockAndReceipts,
) -> Result<()>
    where D: DatabaseInterface
{
    let key = convert_h256_to_bytes(eth_block_and_receipts.block.hash.clone());
    trace!("✔ Adding block to database under key: {:?}", hex::encode(&key));
    db.put(
        key,
        encode_eth_block_and_receipts_as_json_bytes(eth_block_and_receipts)?,
        None,
    )
}

pub fn maybe_get_parent_eth_block_and_receipts<D>(
    db: &D,
    block_hash: &EthHash,
) -> Option<EthBlockAndReceipts>
    where D: DatabaseInterface
{
    info!("✔ Maybe getting parent ETH block from db...");
    maybe_get_nth_ancestor_eth_block_and_receipts(db, block_hash, &1)
}

pub fn maybe_get_nth_ancestor_eth_block_and_receipts<D>(
    db: &D,
    block_hash: &EthHash,
    n: &u64,
) -> Option<EthBlockAndReceipts>
    where D: DatabaseInterface
{
    info!("✔ Getting {}th ancester ETH block from db...", n);
    match maybe_get_eth_block_and_receipts_from_db(db, block_hash) {
        None => None,
        Some(block_and_receipts) => match n {
            0 => Some(block_and_receipts),
            _ => maybe_get_nth_ancestor_eth_block_and_receipts(
                db,
                &block_and_receipts.block.parent_hash,
                &(n - 1),
            )
        }
    }
}

pub fn maybe_get_eth_block_and_receipts_from_db<D>(
    db: &D,
    block_hash: &EthHash,
) -> Option<EthBlockAndReceipts>
    where D: DatabaseInterface
{
    info!(
        "✔ Maybe getting ETH block and receipts from db under hash: {}",
        block_hash,
    );
    match db.get(convert_h256_to_bytes(*block_hash), None) {
        Err(_) => None,
        Ok(bytes) => {
            match decode_eth_block_and_receipts_from_json_bytes(bytes) {
                Ok(block_and_receipts) => {
                    info!("✔ Decoded eth block and receipts from db!");
                    Some(block_and_receipts)
                }
                Err(_) => {
                    info!("✘ Failed to decode eth block and receipts from db!");
                    None
                }
            }
        }
    }
}

pub fn get_eth_block_from_db<D>(
    db: &D,
    block_hash: &EthHash,
) -> Result<EthBlockAndReceipts>
    where D: DatabaseInterface
{
    trace!("✔ Getting ETH block and receipts from db...");
    db.get(convert_h256_to_bytes(*block_hash), None)
        .and_then(|bytes| decode_eth_block_and_receipts_from_json_bytes(bytes))
}

pub fn key_exists_in_db<D>(
    db: &D,
    key: &Bytes,
    sensitivity: DataSensitivity
) -> bool
    where D: DatabaseInterface
{
    trace!("✔ Checking for existence of key: {}", hex::encode(key));
    match db.get(key.to_vec(), sensitivity) {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub fn put_eth_gas_price_in_db<D>(
    db: &D,
    gas_price: &u64,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting ETH gas price of {} in db...", gas_price);
    db.put(
        ETH_GAS_PRICE_KEY.to_vec(),
        gas_price.to_le_bytes().to_vec(),
        None,
    )
}

pub fn get_eth_gas_price_from_db<D>(db: &D) -> Result<u64>
    where D: DatabaseInterface
{
    trace!("✔ Getting ETH gas price from db...");
    db.get(ETH_GAS_PRICE_KEY.to_vec(), None)
        .and_then(|bytes|
            match bytes.len() <= 8 {
                true => {
                    let mut array = [0; 8];
                    let bytes = &bytes[..array.len()];
                    array.copy_from_slice(bytes);
                    Ok(u64::from_le_bytes(array))
                },
                false => Err(AppError::Custom(
                    "✘ Too many bytes to convert to u64!".to_string()
                ))
            }
        )
}

pub fn get_eth_account_nonce_from_db<D>(
    db: &D
) -> Result<u64>
    where D: DatabaseInterface
{
    trace!("✔ Getting ETH account nonce from db...");
    get_u64_from_db(db, &ETH_ACCOUNT_NONCE_KEY.to_vec())
}

pub fn put_eth_account_nonce_in_db<D>(
    db: &D,
    nonce: &u64,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting ETH account nonce of {} in db...", nonce);
    put_u64_in_db(db, &ETH_ACCOUNT_NONCE_KEY.to_vec(), nonce)
}

pub fn increment_eth_account_nonce_in_db<D>(
    db: &D,
    amount_to_increment_by: &u64,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Incrementing ETH account nonce in db...");
    get_eth_account_nonce_from_db(db)
        .and_then(|nonce|
            put_eth_account_nonce_in_db(db, &(nonce + amount_to_increment_by))
        )
}

pub fn put_eth_chain_id_in_db<D>(
    db: &D,
    chain_id: &u8
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting ETH `chain_id` in db of {} in db...", chain_id);
    db.put(
        ETH_CHAIN_ID_KEY.to_vec(),
        chain_id.to_le_bytes().to_vec(),
        None,
    )
}

pub fn get_eth_chain_id_from_db<D>(db: &D) -> Result<u8>
    where D: DatabaseInterface
{
    trace!("✔ Getting ETH `chain_id` from db...");
    db.get(ETH_CHAIN_ID_KEY.to_vec(), None)
        .and_then(|bytes|
            match bytes.len() == 1 {
                true => {
                    let mut array = [0; 1];
                    let bytes = &bytes[..array.len()];
                    array.copy_from_slice(bytes);
                    Ok(u8::from_le_bytes(array))
                },
                false => Err(AppError::Custom(
                    "✘ Wrong number of bytes to convert to usize!".to_string()
                ))
            }
        )
}

pub fn put_eth_private_key_in_db<D>(
    db: &D,
    pk: &EthPrivateKey
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting ETH private key in db...");
    pk.write_to_database(db, &ETH_PRIVATE_KEY_DB_KEY.to_vec())
}

pub fn get_eth_private_key_from_db<D>(db: &D) -> Result<EthPrivateKey>
    where D: DatabaseInterface
{
    trace!("✔ Getting ETH private key from db...");
    db.get(ETH_PRIVATE_KEY_DB_KEY.to_vec(), Some(255))
        .and_then(|pk_bytes| {
            let mut array = [0; 32];
            array.copy_from_slice(&pk_bytes[..32]);
            EthPrivateKey::from_slice(array)
        })
}

pub fn get_eth_smart_contract_address_from_db<D>(db: &D) -> Result<EthAddress>
    where D: DatabaseInterface
{
    trace!("✔ Getting ETH smart-contract address from db...");
    db.get(ETH_SMART_CONTRACT_ADDRESS_KEY.to_vec(), None)
        .and_then(|address_bytes|
            Ok(EthAddress::from_slice(&address_bytes[..]))
        )
}

pub fn put_eth_smart_contract_address_in_db<D>(
    db: &D,
    smart_contract_address: &EthAddress,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting ETH smart-contract address in db...");
    put_eth_address_in_db(
        db,
        &ETH_SMART_CONTRACT_ADDRESS_KEY.to_vec(),
        smart_contract_address,
    )
}

pub fn get_public_eth_address_from_db<D>(db: &D) -> Result<EthAddress>
    where D: DatabaseInterface
{
    trace!("✔ Getting public ETH address from db...");
    db.get(ETH_ADDRESS_KEY.to_vec(), None)
        .map(|bytes| EthAddress::from_slice(&bytes))
}

pub fn put_public_eth_address_in_db<D>(
    db: &D,
    eth_address: &EthAddress
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting public ETH address in db...");
    db.put(ETH_ADDRESS_KEY.to_vec(), eth_address.as_bytes().to_vec(), None)
}

pub fn get_eth_address_from_db<D>(db: &D, key: &Bytes) -> Result<EthAddress>
    where D: DatabaseInterface
{
    db.get(key.to_vec(), None)
        .map(|bytes| EthAddress::from_slice(&bytes))
}

pub fn put_eth_address_in_db<D>(
    db: &D,
    key: &Bytes,
    eth_address: &EthAddress,
) -> Result<()>
    where D: DatabaseInterface
{
    db.put(key.to_vec(), eth_address.as_bytes().to_vec(), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::get_test_database,
        eth::eth_test_utils::{
            get_sample_eth_address,
            get_sample_eth_private_key,
            get_sample_contract_address,
            get_sample_eth_block_and_receipts_n,
            get_sequential_eth_blocks_and_receipts,
        },
    };

    #[test]
    fn non_existing_key_should_not_exist_in_db() {
        let db = get_test_database();
        let result = key_exists_in_db(
            &db,
            &ETH_ACCOUNT_NONCE_KEY.to_vec(),
            None
        );
        assert!(!result);
    }

    #[test]
    fn existing_key_should_exist_in_db() {
        let thing = vec![0xc0];
        let db = get_test_database();
        let key = ETH_ACCOUNT_NONCE_KEY;
        if let Err(e) = db.put(key.to_vec(), thing, None) {
            panic!("Error putting canon to tip len in db: {}", e);
        };
        let result = key_exists_in_db(
            &db,
            &ETH_ACCOUNT_NONCE_KEY.to_vec(),
            None,
        );
        assert!(result);
    }

    #[test]
    fn should_put_eth_gas_price_in_db() {
        let db = get_test_database();
        let gas_price = 20_000_000;
        if let Err(e) = put_eth_gas_price_in_db(&db, &gas_price) {
            panic!("Error putting gas price in db: {}", e);
        };
        match get_eth_gas_price_from_db(&db) {
            Ok(gas_price_from_db) => {
                assert!(gas_price_from_db == gas_price);
            }
            Err(e) => {
                panic!("Error getting gas price from db: {}", e);
            }
        }
    }

    #[test]
    fn should_put_chain_id_in_db() {
        let db = get_test_database();
        let chain_id = 6;
        if let Err(e) = put_eth_chain_id_in_db(&db, &chain_id) {
            panic!("Error putting chain id in db: {}", e);
        };
        match get_eth_chain_id_from_db(&db) {
            Ok(chain_id_from_db) => {
                assert!(chain_id_from_db == chain_id);
            }
            Err(e) => {
                panic!("Error getting chain id from db: {}", e);
            }
        }
    }

    #[test]
    fn should_save_nonce_to_db_and_get_nonce_from_db() {
        let db = get_test_database();
        let nonce = 1227;
        if let Err(e) = put_eth_account_nonce_in_db(&db, &nonce) {
            panic!("Error saving eth account nonce in db: {}", e);
        };
        match get_eth_account_nonce_from_db(&db) {
            Ok(nonce_from_db) => {
                assert!(nonce_from_db == nonce);
            }
            Err(e) => {
                panic!("Error getting nonce from db: {}", e)
            }
        }
    }

    #[test]
    fn should_get_eth_smart_contract_address_from_db() {
        let db = get_test_database();
        let contract_address = get_sample_eth_address();
        if let Err(e) = put_eth_smart_contract_address_in_db(
            &db,
            &contract_address,
        ) {
            panic!("Error putting eth address in db: {}", e);
        };
        let result = get_eth_smart_contract_address_from_db(&db)
            .unwrap();
        assert!(result == contract_address);
    }

    #[test]
    fn should_get_eth_pk_from_database() {
        let db = get_test_database();
        let eth_private_key = get_sample_eth_private_key();
        if let Err(e) = put_eth_private_key_in_db(&db, &eth_private_key) {
            panic!("Error putting eth private key in db: {}", e);
        }
        match get_eth_private_key_from_db(&db) {
            Ok(pk) => {
                assert!(pk == eth_private_key);
            }
            Err(e) => {
                panic!("Error getting eth private key from db: {}", e);
            }
        }
    }

    #[test]
    fn should_increment_eth_account_nonce_in_db() {
        let nonce = 666;
        let db = get_test_database();
        if let Err(e) = put_eth_account_nonce_in_db(&db, &nonce) {
            panic!("Error saving eth account nonce in db: {}", e);
        };
        let amount_to_increment_by: u64 = 671;
        if let Err(e) = increment_eth_account_nonce_in_db(
            &db,
            &amount_to_increment_by,
        ) {
            panic!("Error incrementing nonce in db: {}", e);
        };
        match get_eth_account_nonce_from_db(&db) {
            Ok(nonce_from_db) => {
                assert!(nonce_from_db == nonce + amount_to_increment_by);
            }
            Err(e) => {
                panic!("Error getting nonce from db: {}", e)
            }
        }
    }

    #[test]
    fn should_put_and_get_special_eth_hash_in_db() {
        let db = get_test_database();
        let hash_type = "linker";
        let hash = get_sample_eth_block_and_receipts_n(1)
            .unwrap()
            .block
            .hash
            .clone();
        if let Err(e) = put_special_eth_hash_in_db(&db, &hash_type, &hash) {
            panic!("Error putting ETH special hash in db: {}", e);
        };
        match get_special_eth_hash_from_db(&db, hash_type) {
            Err(e) => {
                panic!("Error getting ETH special hash from db: {}", e);
            }
            Ok(hash_from_db) => {
                assert!(hash_from_db == hash);
            }
        }
    }

    #[test]
    fn should_put_and_get_eth_hash_in_db() {
        let db = get_test_database();
        let hash_key = vec![6u8, 6u8, 6u8];
        let hash = get_sample_eth_block_and_receipts_n(1)
            .unwrap()
            .block
            .hash
            .clone();
        if let Err(e) = put_eth_hash_in_db(&db, &hash_key, &hash){
            panic!("Error putting ETH hash in db: {}", e);
        };
        match get_eth_hash_from_db(&db, &hash_key) {
            Err(e) => {
                panic!("Error getting ETH hash from db: {}", e);
            }
            Ok(hash_from_db) => {
                assert!(hash_from_db == hash);
            }
        }
    }

    #[test]
    fn should_put_and_get_special_eth_block_in_db() {
        let db = get_test_database();
        let block_type = "anchor";
        let block = get_sample_eth_block_and_receipts_n(1)
            .unwrap();
        if let Err(e) = put_special_eth_block_in_db(&db, &block, &block_type) {
            panic!("Error putting ETH special block in db: {}", e);
        };
        match get_special_eth_block_from_db(&db, block_type) {
            Err(e) => {
                panic!("Error getting ETH special block from db: {}", e);
            }
            Ok(block_from_db) => {
                assert!(block_from_db == block);
            }
        }
    }

    #[test]
    fn should_get_eth_block_from_db() {
        let db = get_test_database();
        let block = get_sample_eth_block_and_receipts_n(1)
            .unwrap();
        let block_hash = block.block.hash.clone();
        if let Err(e) = put_eth_block_and_receipts_in_db(&db, &block) {
            panic!("Error putting ETH block and receipts in db: {}", e);
        };
        match get_eth_block_from_db(&db, &block_hash) {
            Err(e) => {
                panic!("Error getting ETH block from db: {}", e);
            }
            Ok(block_from_db) => {
                assert!(block_from_db == block);
            }
        }
    }

    #[test]
    fn should_put_and_get_eth_address_in_db() {
        let db = get_test_database();
        let key = ETH_ADDRESS_KEY.to_vec();
        let eth_address = get_sample_contract_address();
        if let Err(e) = put_eth_address_in_db(&db, &key, &eth_address) {
            panic!("Error putting ETH address in db: {}", e);
        };
        match get_eth_address_from_db(&db, &key) {
            Err(e) => {
                panic!("Error getting ETH address from db: {}", e);
            }
            Ok(eth_address_from_db) => {
                assert!(eth_address_from_db == eth_address);
            }
        }
    }

    #[test]
    fn should_put_and_get_public_eth_address_in_db() {
        let db = get_test_database();
        let eth_address = get_sample_contract_address();
        if let Err(e) = put_public_eth_address_in_db(&db, &eth_address) {
            panic!("Error putting ETH address in db: {}", e);
        };
        match get_public_eth_address_from_db(&db) {
            Err(e) => {
                panic!("Error getting ETH address from db: {}", e);
            }
            Ok(eth_address_from_db) => {
                assert!(eth_address_from_db == eth_address);
            }
        }
    }

    #[test]
    fn maybe_get_block_should_be_none_if_block_not_extant() {
        let db = get_test_database();
        let block_hash = get_sample_eth_block_and_receipts_n(1)
            .unwrap()
            .block
            .hash
            .clone();
        if let Some(_) = maybe_get_eth_block_and_receipts_from_db(
            &db,
            &block_hash
        ) {
            panic!("Maybe getting none existing block should be 'None'");
        };
    }

    #[test]
    fn should_maybe_get_some_block_if_exists() {
        let db = get_test_database();
        let block = get_sample_eth_block_and_receipts_n(1)
            .unwrap();
        let block_hash = block.block.hash.clone();
        if let Err(e) = put_eth_block_and_receipts_in_db(&db, &block) {
            panic!("Error putting ETH block in db: {}", e);
        };
        match maybe_get_eth_block_and_receipts_from_db(&db, &block_hash) {
            None => {
                panic!("Block should exist in db!");
            }
            Some(block_from_db) => {
                assert!(block_from_db == block);
            }
        };
    }

    #[test]
    fn should_return_none_if_no_parent_block_exists() {
        let db = get_test_database();
        let block = get_sample_eth_block_and_receipts_n(1)
            .unwrap();
        let block_hash = block.block.hash.clone();
        if let Err(e) = put_eth_block_and_receipts_in_db(&db, &block) {
            panic!("Error putting ETH block in db: {}", e);
        };
        if let Some(_) = maybe_get_parent_eth_block_and_receipts(
            &db,
            &block_hash
        ) {
            panic!("Block should have no parent in the DB!");
        };
    }

    #[test]
    fn should_maybe_get_parent_block_if_it_exists() {
        let db = get_test_database();
        let blocks = get_sequential_eth_blocks_and_receipts();
        let block = blocks[1]
            .clone();
        let parent_block = blocks[0]
            .clone();
        let block_hash = block
            .block
            .hash
            .clone();
        if let Err(e) = put_eth_block_and_receipts_in_db(&db, &block) {
            panic!("Error putting ETH block in db: {}", e);
        };
        if let Err(e) = put_eth_block_and_receipts_in_db(&db, &parent_block) {
            panic!("Error putting ETH block in db: {}", e);
        };
        match maybe_get_parent_eth_block_and_receipts(&db, &block_hash) {
            None => {
                panic!("Block should have parent in the DB!");
            }
            Some(parent_block_from_db) => {
                assert!(parent_block_from_db == parent_block);
            }
        };
    }

    #[test]
    fn should_get_no_nth_ancestor_if_not_extant() {
        let db = get_test_database();
        let ancestor_number = 3;
        let block = get_sample_eth_block_and_receipts_n(1)
            .unwrap();
        let block_hash = block.block.hash.clone();
        if let Err(e) = put_eth_block_and_receipts_in_db(&db, &block) {
            panic!("Error putting ETH block in db: {}", e);
        };
        if let Some(_) = maybe_get_nth_ancestor_eth_block_and_receipts(
            &db,
            &block_hash,
            &ancestor_number,
        ) {
            panic!("Block should have no parent in the DB!");
        };
    }

    #[test]
    fn should_get_nth_ancestor_if_extant() {
        let db = get_test_database();
        let blocks = get_sequential_eth_blocks_and_receipts();
        let block_hash = blocks[blocks.len() - 1]
            .block
            .hash
            .clone();
        if let Err(e) = blocks
            .iter()
            .map(|block| put_eth_block_and_receipts_in_db(&db, block))
            .collect::<Result<()>>() {
                panic!("Error putting block in db: {}", e);
            };
        blocks
            .iter()
            .enumerate()
            .map(|(i, _)|
                match maybe_get_nth_ancestor_eth_block_and_receipts(
                    &db,
                    &block_hash,
                    &(i as u64),
                ) {
                    None => {
                        panic!("Ancestor number {} should exist!", i);
                    }
                    Some(ancestor) => {
                        assert!(ancestor == blocks[blocks.len() - i - 1]);
                    }
                }
             )
            .for_each(drop);
        if let Some(_) = maybe_get_nth_ancestor_eth_block_and_receipts(
            &db,
            &block_hash,
            &(blocks.len() as u64),
        ) {
            panic!("Shouldn't have ancestor #{} in db!", blocks.len());
        };
    }
}
