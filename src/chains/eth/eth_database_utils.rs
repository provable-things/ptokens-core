use ethereum_types::{
    H256 as EthHash,
    Address as EthAddress,
};
use crate::{
    errors::AppError,
    traits::DatabaseInterface,
    constants::MIN_DATA_SENSITIVITY_LEVEL,
    utils::{
        convert_bytes_to_u64,
        convert_u64_to_bytes,
    },
    types::{
        Byte,
        Result,
        DataSensitivity,
    },
    database_utils::{
        put_u64_in_db,
        get_u64_from_db,
    },
    chains::eth::{
        eth_crypto::eth_private_key::EthPrivateKey,
        eth_submission_material::EthSubmissionMaterial,
        eth_types::{
            EthSigningParams,
            AnySenderSigningParams,
        },
        eth_utils::{
            convert_h256_to_bytes,
            convert_bytes_to_h256,
        },
        eth_constants::{
            ETH_ADDRESS_KEY,
            ETH_CHAIN_ID_KEY,
            ETH_GAS_PRICE_KEY,
            ETH_LINKER_HASH_KEY,
            ANY_SENDER_NONCE_KEY,
            ETH_ACCOUNT_NONCE_KEY,
            ETH_PRIVATE_KEY_DB_KEY,
            ETH_TAIL_BLOCK_HASH_KEY,
            ETH_CANON_BLOCK_HASH_KEY,
            ETH_LATEST_BLOCK_HASH_KEY,
            ETH_ANCHOR_BLOCK_HASH_KEY,
            ETH_CANON_TO_TIP_LENGTH_KEY,
            ERC777_PROXY_CONTACT_ADDRESS_KEY,
            BTC_ON_ETH_SMART_CONTRACT_ADDRESS_KEY,
            ERC20_ON_EOS_SMART_CONTRACT_ADDRESS_KEY,
        },
    },
};

pub fn get_signing_params_from_db<D>(
    db: &D,
) -> Result<EthSigningParams>
    where D: DatabaseInterface
{
    trace!("✔ Getting signing params from db...");
    Ok(
        EthSigningParams {
            chain_id: get_eth_chain_id_from_db(db)?,
            gas_price: get_eth_gas_price_from_db(db)?,
            eth_private_key: get_eth_private_key_from_db(db)?,
            eth_account_nonce: get_eth_account_nonce_from_db(db)?,
            smart_contract_address: get_erc777_contract_address_from_db(db)?,
        }
    )
}

pub fn get_any_sender_signing_params_from_db<D>(
    db: &D,
) -> Result<AnySenderSigningParams>
    where D: DatabaseInterface
{
    trace!("✔ Getting AnySender signing params from db...");
    Ok(
        AnySenderSigningParams {
            chain_id: get_eth_chain_id_from_db(db)?,
            eth_private_key: get_eth_private_key_from_db(db)?,
            any_sender_nonce: get_any_sender_nonce_from_db(db)?,
            public_eth_address: get_public_eth_address_from_db(db)?,
            erc777_proxy_address: get_erc777_proxy_contract_address_from_db(db)?,
        }
    )
}

pub fn put_eth_canon_to_tip_length_in_db<D>(
    db: &D,
    length: u64,
) -> Result<()>
    where D: DatabaseInterface
{
    debug!("✔ Putting ETH canon-to-tip length of {} in db...", length);
    db.put(ETH_CANON_TO_TIP_LENGTH_KEY.to_vec(), convert_u64_to_bytes(length), MIN_DATA_SENSITIVITY_LEVEL)
}

pub fn get_eth_canon_to_tip_length_from_db<D>(db: &D) -> Result<u64>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH canon-to-tip length from db...");
    db.get(ETH_CANON_TO_TIP_LENGTH_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .and_then(|bytes| convert_bytes_to_u64(&bytes))
}

pub fn put_eth_canon_block_in_db<D>(
    db: &D,
    eth_submission_material: &EthSubmissionMaterial,
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Putting ETH canon block in db...");
    put_special_eth_block_in_db(db, eth_submission_material, "canon")
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
    eth_submission_material: &EthSubmissionMaterial,
    block_type: &str,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting ETH special block in db of type: {}", block_type);
    put_eth_submission_material_in_db(db, &eth_submission_material)
        .and_then(|_| put_special_eth_hash_in_db(db, &block_type, &eth_submission_material.get_block_hash()?))
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
        _ => Err(AppError::Custom(format!("✘ Cannot store special ETH hash of type: {}!", hash_type)))
    }?;
    put_eth_hash_in_db(db, &key, hash)
}

pub fn get_latest_eth_block_number<D>(db: &D) -> Result<usize>
    where D: DatabaseInterface
{
    info!("✔ Getting latest ETH block number from db...");
    match get_special_eth_block_from_db(db, "latest") {
        Ok(result) => Ok(result.get_block_number()?.as_usize()),
        Err(e) => Err(e)
    }
}

pub fn get_eth_tail_block_from_db<D>(db: &D) -> Result<EthSubmissionMaterial>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH tail block from db...");
    get_special_eth_block_from_db(db, "tail")
}

pub fn get_eth_latest_block_from_db<D>(db: &D) -> Result<EthSubmissionMaterial>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH latest block from db...");
    get_special_eth_block_from_db(db, "latest")
}

pub fn get_eth_anchor_block_from_db<D>(db: &D) -> Result<EthSubmissionMaterial>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH anchor block from db...");
    get_special_eth_block_from_db(db, "anchor")
}

pub fn get_eth_canon_block_from_db<D>(
    db: &D
) -> Result<EthSubmissionMaterial>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH canon block from db...");
    get_special_eth_block_from_db(db, "canon")
}

pub fn get_eth_anchor_block_hash_from_db<D>(db: &D) -> Result<EthHash>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH anchor block hash from db...");
    get_special_eth_hash_from_db(db, "anchor")
}

pub fn get_special_eth_hash_from_db<D>(
    db: &D,
    hash_type: &str,
) -> Result<EthHash>
    where D: DatabaseInterface
{
    let key = match hash_type {
        "linker" => Ok(ETH_LINKER_HASH_KEY.to_vec()),
        "canon" => Ok(ETH_CANON_BLOCK_HASH_KEY.to_vec()),
        "tail" => Ok(ETH_TAIL_BLOCK_HASH_KEY.to_vec()),
        "anchor" => Ok(ETH_ANCHOR_BLOCK_HASH_KEY.to_vec()),
        "latest" => Ok(ETH_LATEST_BLOCK_HASH_KEY.to_vec()),
        _ => Err(AppError::Custom(format!("✘ Cannot get ETH special hash of type: {}!", hash_type)))
    }?;
    trace!("✔ Getting special ETH hash from db of type: {}", hash_type);
    get_eth_hash_from_db(db, &key.to_vec())
}

pub fn get_eth_hash_from_db<D>(db: &D, key: &[Byte]) -> Result<EthHash>
    where D: DatabaseInterface
{
    trace!(
        "✔ Getting ETH hash from db under key: {}",
        hex::encode(&key)
    );

    db.get(key.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .map(|bytes| EthHash::from_slice(&bytes))
}

pub fn get_special_eth_block_from_db<D>(
    db: &D,
    block_type: &str,
) -> Result<EthSubmissionMaterial>
    where D: DatabaseInterface
{
    get_special_eth_hash_from_db(db, block_type)
        .and_then(|block_hash| get_submission_material_from_db(db, &block_hash))
}

pub fn put_eth_hash_in_db<D>(
    db: &D,
    key: &[Byte],
    eth_hash: &EthHash
) -> Result<()>
    where D: DatabaseInterface
{
    db.put(key.to_vec(), convert_h256_to_bytes(*eth_hash), MIN_DATA_SENSITIVITY_LEVEL)
}

pub fn eth_block_exists_in_db<D>(db: &D, block_hash: &EthHash) -> bool
    where D: DatabaseInterface
{
    info!("✔ Checking for existence of ETH block: {}", hex::encode(block_hash.as_bytes().to_vec()));
    key_exists_in_db(db, &block_hash.as_bytes().to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
}

pub fn get_hash_from_db_via_hash_key<D>(
    db: &D,
    hash_key: EthHash,
) -> Result<Option<EthHash>>
    where D: DatabaseInterface
{
    match db.get(convert_h256_to_bytes(hash_key), MIN_DATA_SENSITIVITY_LEVEL) {
        Ok(bytes) => Ok(Some(convert_bytes_to_h256(&bytes)?)),
        Err(_) => Ok(None),
    }
}

pub fn put_eth_submission_material_in_db<D>(
    db: &D,
    eth_submission_material: &EthSubmissionMaterial,
) -> Result<()>
    where D: DatabaseInterface
{
    let key = convert_h256_to_bytes(eth_submission_material.get_block_hash()?);
    trace!("✔ Adding block to database under key: {:?}", hex::encode(&key));
    db.put(key, eth_submission_material.remove_block().to_bytes()?, MIN_DATA_SENSITIVITY_LEVEL)
}

pub fn maybe_get_parent_eth_submission_material<D>(
    db: &D,
    block_hash: &EthHash,
) -> Option<EthSubmissionMaterial>
    where D: DatabaseInterface
{
    debug!("✔ Maybe getting parent ETH block from db...");
    maybe_get_nth_ancestor_eth_submission_material(db, block_hash, 1).ok()?
}

pub fn maybe_get_nth_ancestor_eth_submission_material<D>(
    db: &D,
    block_hash: &EthHash,
    n: u64,
) -> Result<Option<EthSubmissionMaterial>>
    where D: DatabaseInterface
{
    debug!("✔ Getting {}th ancestor ETH block from db...", n);
    match maybe_get_eth_submission_material_from_db(db, block_hash) {
        None => Ok(None),
        Some(block_and_receipts) => match n {
            0 => Ok(Some(block_and_receipts)),
            _ => maybe_get_nth_ancestor_eth_submission_material(db, &block_and_receipts.get_parent_hash()?, n - 1)
        }
    }
}

pub fn maybe_get_eth_submission_material_from_db<D>(
    db: &D,
    block_hash: &EthHash,
) -> Option<EthSubmissionMaterial>
    where D: DatabaseInterface
{
    trace!("✔ Maybe getting ETH block and receipts from db under hash: {}", block_hash);
    match db.get(convert_h256_to_bytes(*block_hash), MIN_DATA_SENSITIVITY_LEVEL) {
        Err(_) => None,
        Ok(bytes) => {
            match EthSubmissionMaterial::from_bytes(&bytes) {
                Ok(block_and_receipts) => {
                    trace!("✔ Decoded eth block and receipts from db!");
                    Some(block_and_receipts)
                }
                Err(_) => {
                    error!("✘ Failed to decode eth block and receipts from db!");
                    None
                }
            }
        }
    }
}

pub fn get_submission_material_from_db<D>(
    db: &D,
    block_hash: &EthHash,
) -> Result<EthSubmissionMaterial>
    where D: DatabaseInterface
{
    trace!("✔ Getting ETH block and receipts from db...");
    db
        .get(convert_h256_to_bytes(*block_hash), MIN_DATA_SENSITIVITY_LEVEL)
        .and_then(|bytes| EthSubmissionMaterial::from_bytes(&bytes))
}

pub fn key_exists_in_db<D>(
    db: &D,
    key: &[Byte],
    sensitivity: DataSensitivity
) -> bool
    where D: DatabaseInterface
{
    trace!("✔ Checking for existence of key: {}", hex::encode(key));
    db.get(key.to_vec(), sensitivity).is_ok()
}

pub fn put_eth_gas_price_in_db<D>(
    db: &D,
    gas_price: u64,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting ETH gas price of {} in db...", gas_price);
    db.put(ETH_GAS_PRICE_KEY.to_vec(), gas_price.to_le_bytes().to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
}

pub fn get_eth_gas_price_from_db<D>(db: &D) -> Result<u64>
    where D: DatabaseInterface
{
    trace!("✔ Getting ETH gas price from db...");
    db.get(ETH_GAS_PRICE_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .and_then(|bytes|
            match bytes.len() <= 8 {
                true => {
                    let mut array = [0; 8];
                    let bytes = &bytes[..array.len()];
                    array.copy_from_slice(bytes);
                    Ok(u64::from_le_bytes(array))
                },
                false => Err("✘ Too many bytes to convert to u64!".into())
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
    nonce: u64,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting ETH account nonce of {} in db...", nonce);
    put_u64_in_db(db, &ETH_ACCOUNT_NONCE_KEY.to_vec(), nonce)
}

pub fn increment_eth_account_nonce_in_db<D>(
    db: &D,
    amount_to_increment_by: u64,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Incrementing ETH account nonce in db...");
    get_eth_account_nonce_from_db(db)
        .and_then(|nonce|
            put_eth_account_nonce_in_db(db, nonce + amount_to_increment_by)
        )
}

pub fn put_eth_chain_id_in_db<D>(
    db: &D,
    chain_id: u8
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting ETH `chain_id` in db of {} in db...", chain_id);
    db.put(ETH_CHAIN_ID_KEY.to_vec(), chain_id.to_le_bytes().to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
}

pub fn get_eth_chain_id_from_db<D>(db: &D) -> Result<u8>
    where D: DatabaseInterface
{
    trace!("✔ Getting ETH `chain_id` from db...");
    db.get(ETH_CHAIN_ID_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .and_then(|bytes|
            match bytes.len() == 1 {
                true => {
                    let mut array = [0; 1];
                    let bytes = &bytes[..array.len()];
                    array.copy_from_slice(bytes);
                    Ok(u8::from_le_bytes(array))
                },
                false => Err("✘ Wrong number of bytes to convert to usize!".into())
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

pub fn get_erc777_contract_address_from_db<D>(db: &D) -> Result<EthAddress>
    where D: DatabaseInterface
{
    trace!("✔ Getting ETH smart-contract address from db...");
    db.get(BTC_ON_ETH_SMART_CONTRACT_ADDRESS_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .map(|address_bytes| EthAddress::from_slice(&address_bytes[..]))
}

pub fn get_erc20_on_eos_smart_contract_address_from_db<D>(db: &D) -> Result<EthAddress>
    where D: DatabaseInterface
{
    info!("✔ Getting `pERC20-on-EOS` smart-contract address from db...");
    get_eth_address_from_db(db, &*ERC20_ON_EOS_SMART_CONTRACT_ADDRESS_KEY)
}

fn get_eth_address_from_db<D>(db: &D, key: &[Byte]) -> Result<EthAddress> where D: DatabaseInterface {
    db.get(key.to_vec(), MIN_DATA_SENSITIVITY_LEVEL).map(|address_bytes| EthAddress::from_slice(&address_bytes[..]))
}

pub fn get_erc777_proxy_contract_address_from_db<D>(db: &D) -> Result<EthAddress>
    where D: DatabaseInterface
{
    trace!("✔ Getting ERC777 proxy contract address from db...");
    match db.get(ERC777_PROXY_CONTACT_ADDRESS_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL) {
        Ok(address_bytes) => Ok(EthAddress::from_slice(&address_bytes[..])),
        Err(_) => {
            debug!("✘ No ERC777 proxy address in db, defaulting to zero ETH address!");
            Ok(EthAddress::zero())
        }
    }
}

#[allow(dead_code)]
pub fn put_erc777_proxy_contract_address_in_db<D>(
    db: &D,
    proxy_contract_address: &EthAddress,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting ERC777 proxy contract address in db...");
    put_eth_address_in_db(db, &ERC777_PROXY_CONTACT_ADDRESS_KEY.to_vec(), proxy_contract_address)
}

pub fn put_btc_on_eth_smart_contract_address_in_db<D>(
    db: &D,
    smart_contract_address: &EthAddress,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting ETH smart-contract address in db...");
    put_eth_address_in_db(db, &*BTC_ON_ETH_SMART_CONTRACT_ADDRESS_KEY, smart_contract_address)
}

pub fn put_erc20_on_eos_smart_contract_address_in_db<D>(
    db: &D,
    smart_contract_address: &EthAddress,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting 'ERC20-on-EOS` smart-contract address in db...");
    put_eth_address_in_db(db, &ERC20_ON_EOS_SMART_CONTRACT_ADDRESS_KEY.to_vec(), smart_contract_address)
}

pub fn get_public_eth_address_from_db<D>(db: &D) -> Result<EthAddress>
    where D: DatabaseInterface
{
    trace!("✔ Getting public ETH address from db...");
    db.get(ETH_ADDRESS_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL).map(|bytes| EthAddress::from_slice(&bytes))
}

pub fn put_public_eth_address_in_db<D>(
    db: &D,
    eth_address: &EthAddress
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting public ETH address in db...");
    db.put(ETH_ADDRESS_KEY.to_vec(), eth_address.as_bytes().to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
}

pub fn put_eth_address_in_db<D>(
    db: &D,
    key: &[Byte],
    eth_address: &EthAddress,
) -> Result<()>
    where D: DatabaseInterface
{
    db.put(key.to_vec(), eth_address.as_bytes().to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
}

pub fn get_any_sender_nonce_from_db<D>(
    db: &D
) -> Result<u64>
    where D: DatabaseInterface
{
    trace!("✔ Getting AnySender nonce from db...");
    Ok(
        get_u64_from_db(db, &ANY_SENDER_NONCE_KEY.to_vec()).unwrap_or_else(|_| {
            info!("✘ Could not find `AnySender` nonce in db, defaulting to `0`");
            0
        })
    )
}

pub fn put_any_sender_nonce_in_db<D>(
    db: &D,
    nonce: u64,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting AnySender nonce of {} in db...", nonce);
    put_u64_in_db(db, &ANY_SENDER_NONCE_KEY.to_vec(), nonce)
}

pub fn increment_any_sender_nonce_in_db<D>(
    db: &D,
    amount_to_increment_by: u64,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Incrementing AnySender nonce in db...");
    get_any_sender_nonce_from_db(db)
        .and_then(|nonce| put_any_sender_nonce_in_db(db, nonce + amount_to_increment_by))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::get_test_database,
        btc_on_eth::eth::eth_test_utils::{
            get_sample_eth_address,
            get_sample_eth_private_key,
            get_sample_contract_address,
            get_sample_eth_submission_material,
            get_sample_eth_submission_material_n,
            get_sequential_eth_blocks_and_receipts,
        },
    };

    #[test]
    fn non_existing_key_should_not_exist_in_db() {
        let db = get_test_database();
        let result = key_exists_in_db(&db, &ETH_ACCOUNT_NONCE_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL);
        assert!(!result);
    }

    #[test]
    fn existing_key_should_exist_in_db() {
        let thing = vec![0xc0];
        let db = get_test_database();
        let key = *ETH_ACCOUNT_NONCE_KEY;
        db.put(key.to_vec(), thing, MIN_DATA_SENSITIVITY_LEVEL).unwrap();
        let result = key_exists_in_db(&db, &ETH_ACCOUNT_NONCE_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL);
        assert!(result);
    }

    #[test]
    fn should_put_eth_gas_price_in_db() {
        let db = get_test_database();
        let gas_price = 20_000_000;
        put_eth_gas_price_in_db(&db, gas_price).unwrap();
        match get_eth_gas_price_from_db(&db) {
            Ok(gas_price_from_db) => assert_eq!(gas_price_from_db, gas_price),
            Err(e) => panic!("Error getting gas price from db: {}", e),
        }
    }

    #[test]
    fn should_put_chain_id_in_db() {
        let db = get_test_database();
        let chain_id = 6;
        put_eth_chain_id_in_db(&db, chain_id).unwrap();
        let result = get_eth_chain_id_from_db(&db).unwrap();
        assert_eq!(result, chain_id);
    }

    #[test]
    fn should_save_nonce_to_db_and_get_nonce_from_db() {
        let db = get_test_database();
        let nonce = 1227;
        put_eth_account_nonce_in_db(&db, nonce).unwrap();
        match get_eth_account_nonce_from_db(&db) {
            Ok(nonce_from_db) => assert_eq!(nonce_from_db, nonce),
            Err(e) => panic!("Error getting nonce from db: {}", e),
        }
    }

    #[test]
    fn should_get_erc777_contract_address_from_db() {
        let db = get_test_database();
        let contract_address = get_sample_eth_address();
        put_btc_on_eth_smart_contract_address_in_db(&db, &contract_address).unwrap();
        let result = get_erc777_contract_address_from_db(&db).unwrap();
        assert_eq!(result, contract_address);
    }

    #[test]
    fn should_get_eth_pk_from_database() {
        let db = get_test_database();
        let eth_private_key = get_sample_eth_private_key();
        put_eth_private_key_in_db(&db, &eth_private_key).unwrap();
        match get_eth_private_key_from_db(&db) {
            Ok(pk) => assert_eq!(pk, eth_private_key),
            Err(e) => panic!("Error getting eth private key from db: {}", e),
        }
    }

    #[test]
    fn should_increment_eth_account_nonce_in_db() {
        let nonce = 666;
        let db = get_test_database();
        put_eth_account_nonce_in_db(&db, nonce).unwrap();
        let amount_to_increment_by: u64 = 671;
        increment_eth_account_nonce_in_db(&db, amount_to_increment_by).unwrap();
        match get_eth_account_nonce_from_db(&db) {
            Err(e) => panic!("Error getting nonce from db: {}", e),
            Ok(nonce_from_db) => assert_eq!(nonce_from_db, nonce + amount_to_increment_by),
        }
    }

    #[test]
    fn should_put_and_get_special_eth_hash_in_db() {
        let db = get_test_database();
        let hash_type = "linker";
        let hash = get_sample_eth_submission_material_n(1).unwrap().get_block_hash().unwrap();
        put_special_eth_hash_in_db(&db, &hash_type, &hash).unwrap();
        match get_special_eth_hash_from_db(&db, hash_type) {
            Ok(hash_from_db) => assert_eq!(hash_from_db, hash),
            Err(e) => panic!("Error getting ETH special hash from db: {}", e),
        }
    }

    #[test]
    fn should_put_and_get_eth_hash_in_db() {
        let db = get_test_database();
        let hash_key = vec![6u8, 6u8, 6u8];
        let hash = get_sample_eth_submission_material_n(1).unwrap().get_block_hash().unwrap();
        put_eth_hash_in_db(&db, &hash_key, &hash).unwrap();
        match get_eth_hash_from_db(&db, &hash_key) {
            Ok(hash_from_db) => assert_eq!(hash_from_db, hash),
            Err(e) => panic!("Error getting ETH hash from db: {}", e),
        }
    }

    #[test]
    fn should_put_and_get_special_eth_block_in_db() {
        let db = get_test_database();
        let block_type = "anchor";
        let submission_material = get_sample_eth_submission_material_n(1).unwrap();
        let expected_result = submission_material.remove_block();
        put_special_eth_block_in_db(&db, &submission_material, &block_type).unwrap();
        match get_special_eth_block_from_db(&db, block_type) {
            Ok(result) => assert_eq!(result, expected_result),
            Err(e) => panic!("Error getting ETH special submission_material from db: {}", e),
        }
    }

    #[test]
    fn should_get_submission_material_block_from_db() {
        let db = get_test_database();
        let submission_material = get_sample_eth_submission_material_n(1).unwrap();
        let expected_result = submission_material.remove_block();
        let block_hash = submission_material.get_block_hash().unwrap();
        put_eth_submission_material_in_db(&db, &submission_material).unwrap();
        match get_submission_material_from_db(&db, &block_hash) {
            Ok(result) => assert_eq!(result, expected_result),
            Err(e) => panic!("Error getting ETH submission_material from db: {}", e),
        }
    }

    #[test]
    fn should_put_eth_address_in_db() {
        let db = get_test_database();
        let key = ETH_ADDRESS_KEY.to_vec();
        let eth_address = get_sample_contract_address();
        let result = put_eth_address_in_db(&db, &key, &eth_address);
        assert!(result.is_ok());
    }

    #[test]
    fn should_put_and_get_public_eth_address_in_db() {
        let db = get_test_database();
        let eth_address = get_sample_contract_address();
        put_public_eth_address_in_db(&db, &eth_address).unwrap();
        match get_public_eth_address_from_db(&db) {
            Ok(eth_address_from_db) => assert_eq!(eth_address_from_db, eth_address),
            Err(e) => panic!("Error getting ETH address from db: {}", e),
        }
    }

    #[test]
    fn maybe_get_block_should_be_none_if_block_not_extant() {
        let db = get_test_database();
        let block_hash = get_sample_eth_submission_material_n(1).unwrap().get_block_hash().unwrap();
        if maybe_get_eth_submission_material_from_db(&db, &block_hash).is_some() {
            panic!("Maybe getting none existing block should be 'None'");
        };
    }

    #[test]
    fn should_maybe_get_some_block_if_exists() {
        let db = get_test_database();
        let submission_material = get_sample_eth_submission_material_n(1).unwrap();
        let expected_result = submission_material.remove_block();
        let block_hash = submission_material.get_block_hash().unwrap();
        put_eth_submission_material_in_db(&db, &submission_material).unwrap();
        match maybe_get_eth_submission_material_from_db(&db, &block_hash) {
            None => panic!("`submission_material` should exist in db!"),
            Some(result) => assert_eq!(result, expected_result),
        };
    }

    #[test]
    fn should_return_none_if_no_parent_block_exists() {
        let db = get_test_database();
        let block = get_sample_eth_submission_material_n(1).unwrap();
        let block_hash = block.get_block_hash().unwrap();
        put_eth_submission_material_in_db(&db, &block).unwrap();
        let result = maybe_get_parent_eth_submission_material(&db, &block_hash);
        assert!(result.is_none());
    }

    #[test]
    fn should_maybe_get_parent_block_if_it_exists() {
        let db = get_test_database();
        let blocks = get_sequential_eth_blocks_and_receipts();
        let block = blocks[1].clone();
        let parent_block = blocks[0].clone();
        let expected_result = parent_block.remove_block();
        let block_hash = block.get_block_hash().unwrap();
        put_eth_submission_material_in_db(&db, &block).unwrap();
        put_eth_submission_material_in_db(&db, &parent_block).unwrap();
        match maybe_get_parent_eth_submission_material(&db, &block_hash) {
            None => panic!("Block should have parent in the DB!"),
            Some(result) => assert_eq!(result, expected_result),
        };
    }

    #[test]
    fn should_get_no_nth_ancestor_if_not_extant() {
        let ancestor_number = 3;
        let db = get_test_database();
        let block = get_sample_eth_submission_material_n(1).unwrap();
        let block_hash = block.get_block_hash().unwrap();
        put_eth_submission_material_in_db(&db, &block).unwrap();
        let result = maybe_get_nth_ancestor_eth_submission_material(&db, &block_hash, ancestor_number).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn should_get_nth_ancestor_if_extant() {
        let db = get_test_database();
        let blocks = get_sequential_eth_blocks_and_receipts();
        let block_hash = blocks[blocks.len() - 1].get_block_hash().unwrap();
        blocks.iter().map(|block| put_eth_submission_material_in_db(&db, block)).collect::<Result<()>>().unwrap();
        blocks
            .iter()
            .enumerate()
            .map(|(i, _)|
                match maybe_get_nth_ancestor_eth_submission_material(&db, &block_hash, i as u64).unwrap() {
                    None => panic!("Ancestor number {} should exist!", i),
                    Some(ancestor) => assert_eq!(ancestor, blocks[blocks.len() - i - 1].remove_block()),
                }
             )
            .for_each(drop);
        let result =  maybe_get_nth_ancestor_eth_submission_material(&db, &block_hash, blocks.len() as u64).unwrap();
        assert!(result.is_none());

    }

    #[test]
    fn saving_submission_material_should_remove_block() {
        let db = get_test_database();
        let submission_material = get_sample_eth_submission_material();
        let db_key = submission_material.get_block_hash().unwrap();
        assert!(submission_material.block.is_some());
        put_eth_submission_material_in_db(&db, &submission_material).unwrap();
        let result = get_submission_material_from_db(&db, &db_key).unwrap();
        assert!(result.block.is_none());
    }

    #[test]
    fn should_save_submission_material_if_block_already_removed() {
        let db = get_test_database();
        let submission_material = get_sample_eth_submission_material().remove_block();
        let db_key = submission_material.get_block_hash().unwrap();
        put_eth_submission_material_in_db(&db, &submission_material).unwrap();
        let result = get_submission_material_from_db(&db, &db_key).unwrap();
        assert_eq!(result, submission_material);
    }
}
