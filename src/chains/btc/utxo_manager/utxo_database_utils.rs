use bitcoin_hashes::{sha256d, Hash};

use crate::{
    chains::btc::utxo_manager::{
        utxo_constants::{UTXO_BALANCE, UTXO_FIRST, UTXO_LAST, UTXO_NONCE},
        utxo_types::{BtcUtxoAndValue, BtcUtxosAndValues},
        utxo_utils::{deserialize_utxo_and_value, get_utxo_and_value_db_key, serialize_btc_utxo_and_value},
    },
    errors::AppError,
    traits::DatabaseInterface,
    types::{Byte, Bytes, Result},
    utils::{convert_bytes_to_u64, convert_u64_to_bytes},
};

pub fn get_x_utxos<D: DatabaseInterface>(db: &D, num_utxos_to_get: usize) -> Result<BtcUtxosAndValues> {
    let total_num_utxos = get_total_number_of_utxos_from_db(db);
    if total_num_utxos < num_utxos_to_get {
        return Err(format!(
            "Can't get {} UTXOS, there're only {} in the db!",
            num_utxos_to_get, total_num_utxos
        )
        .into());
    };
    fn get_utxos_recursively<D: DatabaseInterface>(
        db: &D,
        num_utxos_to_get: usize,
        mut utxos: Vec<BtcUtxoAndValue>,
    ) -> Result<BtcUtxosAndValues> {
        get_first_utxo_and_value(db).and_then(|utxo| {
            utxos.push(utxo);
            if utxos.len() == num_utxos_to_get {
                Ok(BtcUtxosAndValues::new(utxos))
            } else {
                get_utxos_recursively(db, num_utxos_to_get, utxos)
            }
        })
    }
    get_utxos_recursively(db, num_utxos_to_get, vec![])
}

fn remove_utxo_pointer(utxo: &BtcUtxoAndValue) -> BtcUtxoAndValue {
    let mut utxo_with_no_pointer = utxo.clone();
    utxo_with_no_pointer.maybe_pointer = None;
    utxo_with_no_pointer
}

pub fn get_utxo_with_tx_id_and_v_out<D: DatabaseInterface>(
    db: &D,
    v_out: u32,
    tx_id: &sha256d::Hash,
) -> Result<BtcUtxoAndValue> {
    fn find_utxo_recursively<D: DatabaseInterface>(
        db: &D,
        v_out: u32,
        tx_id: &sha256d::Hash,
        mut utxos: Vec<BtcUtxoAndValue>,
    ) -> Result<(Option<BtcUtxoAndValue>, BtcUtxosAndValues)> {
        match get_first_utxo_and_value(db) {
            Err(_) => Ok((None, BtcUtxosAndValues::new(utxos))),
            Ok(utxo) => {
                if utxo.get_v_out()? == v_out && &utxo.get_tx_id()? == tx_id {
                    Ok((Some(utxo), BtcUtxosAndValues::new(utxos)))
                } else {
                    utxos.push(remove_utxo_pointer(&utxo));
                    find_utxo_recursively(db, v_out, tx_id, utxos)
                }
            },
        }
    }
    find_utxo_recursively(db, v_out, tx_id, vec![]).and_then(|(maybe_utxo, utxos_to_save_in_db)| {
        save_utxos_to_db(db, &utxos_to_save_in_db)?;
        maybe_utxo.ok_or_else(|| {
            AppError::Custom(format!(
                "Could not find UTXO with v_out: {} & tx_id: {}",
                v_out,
                tx_id.to_string()
            ))
        })
    })
}

pub fn save_utxos_to_db<D>(db: &D, utxos_and_values: &BtcUtxosAndValues) -> Result<()>
where
    D: DatabaseInterface,
{
    debug!("✔ Saving {} `utxo_and_value`s...", utxos_and_values.len());
    utxos_and_values
        .0
        .iter()
        .try_for_each(|utxo_and_value| save_new_utxo_and_value(db, utxo_and_value))
}

pub fn get_all_utxo_db_keys<D>(db: &D) -> Vec<Bytes>
where
    D: DatabaseInterface,
{
    fn get_utxo_pointers_recursively<D>(db: &D, mut pointers: Vec<Bytes>) -> Vec<Bytes>
    where
        D: DatabaseInterface,
    {
        match maybe_get_next_utxo_pointer_from_utxo_pointer(db, &pointers[pointers.len() - 1]) {
            None => pointers,
            Some(next_pointer) => {
                pointers.push(next_pointer);
                get_utxo_pointers_recursively(db, pointers)
            },
        }
    }
    match get_first_utxo_pointer(db) {
        Ok(first_pointer) => get_utxo_pointers_recursively(db, vec![first_pointer]),
        _ => vec![],
    }
}

fn maybe_get_next_utxo_pointer_from_utxo_pointer<D>(db: &D, utxo_pointer: &[Byte]) -> Option<Bytes>
where
    D: DatabaseInterface,
{
    match maybe_get_utxo_from_db(db, &utxo_pointer) {
        None => None,
        Some(utxo) => utxo.maybe_pointer.map(|pointer| pointer.to_vec()),
    }
}

pub fn get_first_utxo_and_value<D>(db: &D) -> Result<BtcUtxoAndValue>
where
    D: DatabaseInterface,
{
    get_first_utxo_pointer(db)
        .and_then(|pointer| get_utxo_from_db(db, &pointer))
        .and_then(|utxo| match utxo.maybe_pointer {
            None => {
                debug!("✔ No next pointer ∴ must be last UTXO in db!");
                delete_utxo_balance_key(db)
                    .and_then(|_| delete_first_utxo(db))
                    .and_then(|_| delete_last_utxo_key(db))
                    .and_then(|_| delete_first_utxo_key(db))
                    .map(|_| utxo)
            },
            Some(pointer) => {
                debug!("✔ UTXO found, updating `UTXO_FIRST` pointer...");
                decrement_total_utxo_balance_in_db(db, utxo.value)
                    .and_then(|_| delete_first_utxo(db))
                    .and_then(|_| set_first_utxo_pointer(db, &pointer))
                    .map(|_| utxo)
            },
        })
}

pub fn save_new_utxo_and_value<D>(db: &D, utxo_and_value: &BtcUtxoAndValue) -> Result<()>
where
    D: DatabaseInterface,
{
    let value = utxo_and_value.value;
    let hash_vec = get_utxo_and_value_db_key(get_utxo_nonce_from_db(db)? + 1);
    let hash = sha256d::Hash::from_slice(&hash_vec)?;
    debug!("✔ Saving new UTXO in db under hash: {}", hex::encode(hash));
    match get_total_utxo_balance_from_db(db)? {
        0 => {
            debug!("✔ No UTXO balance ∴ setting `UTXO_FIRST` & `UTXO_LAST`...");
            set_first_utxo_pointer(db, &hash)
                .and_then(|_| increment_utxo_nonce_in_db(db))
                .and_then(|_| set_last_utxo_pointer(db, &hash))
                .and_then(|_| put_total_utxo_balance_in_db(db, value))
                .and_then(|_| put_utxo_in_db(db, &hash_vec, utxo_and_value))
        },
        _ => {
            debug!("✔ > 0 UTXO balance ∴ setting only `UTXO_LAST`...");
            update_pointer_in_last_utxo_in_db(db, hash)
                .and_then(|_| increment_utxo_nonce_in_db(db))
                .and_then(|_| set_last_utxo_pointer(db, &hash))
                .and_then(|_| put_utxo_in_db(db, &hash_vec, utxo_and_value))
                .and_then(|_| increment_total_utxo_balance_in_db(db, value))
        },
    }
}

pub fn delete_last_utxo_key<D>(db: &D) -> Result<()>
where
    D: DatabaseInterface,
{
    debug!("✔ Deleting `UTXO_LAST` key from db...");
    db.delete(UTXO_LAST.to_vec())
}

pub fn delete_first_utxo_key<D>(db: &D) -> Result<()>
where
    D: DatabaseInterface,
{
    debug!("✔ Deleting `UTXO_FIRST` key from db...");
    db.delete(UTXO_FIRST.to_vec())
}

pub fn delete_first_utxo<D>(db: &D) -> Result<()>
where
    D: DatabaseInterface,
{
    get_first_utxo_pointer(db).and_then(|pointer| {
        debug!("✔ Deleting UTXO under key: {}", hex::encode(&pointer));
        db.delete(pointer.to_vec())
    })
}

pub fn delete_utxo_balance_key<D>(db: &D) -> Result<()>
where
    D: DatabaseInterface,
{
    debug!("✔ Deleting `UTXO_BALANCE` key from db...");
    db.delete(UTXO_BALANCE.to_vec())
}

pub fn increment_total_utxo_balance_in_db<D>(db: &D, amount_to_increment_by: u64) -> Result<()>
where
    D: DatabaseInterface,
{
    get_total_utxo_balance_from_db(db).and_then(|balance| {
        debug!("✔ Incrementing UTXO total by: {}", amount_to_increment_by);
        put_total_utxo_balance_in_db(db, balance + amount_to_increment_by)
    })
}

pub fn decrement_total_utxo_balance_in_db<D>(db: &D, amount_to_decrement_by: u64) -> Result<()>
where
    D: DatabaseInterface,
{
    get_total_utxo_balance_from_db(db).and_then(|balance| match balance >= amount_to_decrement_by {
        true => {
            debug!("✔ Decrementing UTXO balance by {}", amount_to_decrement_by);
            put_total_utxo_balance_in_db(db, balance - amount_to_decrement_by)
        },
        false => Err("✘ Not decrementing UTXO total value ∵ it'll underflow!".into()),
    })
}

pub fn put_total_utxo_balance_in_db<D>(db: &D, balance: u64) -> Result<()>
where
    D: DatabaseInterface,
{
    debug!("✔ Setting total UTXO balance to: {}", balance);
    db.put(UTXO_BALANCE.to_vec(), convert_u64_to_bytes(balance), None)
}

pub fn get_total_utxo_balance_from_db<D>(db: &D) -> Result<u64>
where
    D: DatabaseInterface,
{
    debug!("✔ Getting total UTXO balance from db...");
    match db.get(UTXO_BALANCE.to_vec(), None) {
        Err(_) => Ok(0),
        Ok(bytes) => convert_bytes_to_u64(&bytes),
    }
}

pub fn update_pointer_in_last_utxo_in_db<D>(db: &D, new_pointer: sha256d::Hash) -> Result<()>
where
    D: DatabaseInterface,
{
    debug!("✔ Updating `UTXO_LAST` pointer in db to {}", new_pointer);
    get_last_utxo_pointer(db)
        .and_then(|pointer_to_utxo| update_pointer_in_utxo_in_db(db, &pointer_to_utxo, new_pointer))
}

pub fn update_pointer_in_utxo_in_db<D>(db: &D, db_key: &[Byte], new_pointer: sha256d::Hash) -> Result<()>
where
    D: DatabaseInterface,
{
    debug!(
        "✔ Updating UTXO pointer in db under key: {} to: {}",
        hex::encode(db_key),
        new_pointer
    );
    get_utxo_from_db(db, db_key)
        .map(|utxo| utxo.update_pointer(new_pointer))
        .and_then(|utxo| put_utxo_in_db(db, db_key, &utxo))
}

pub fn maybe_get_utxo_from_db<D>(db: &D, db_key: &[Byte]) -> Option<BtcUtxoAndValue>
where
    D: DatabaseInterface,
{
    debug!("✔ Maybe getting UTXO in db under key: {}", hex::encode(db_key));
    match db.get(db_key.to_vec(), None) {
        Err(_) => {
            debug!("✘ No UTXO exists in the database @ that key!");
            None
        },
        Ok(bytes) => match deserialize_utxo_and_value(&bytes) {
            Ok(utxo_and_value) => Some(utxo_and_value),
            Err(_) => {
                debug!("✘ Error deserializing UTXO & value!");
                None
            },
        },
    }
}

pub fn get_utxo_from_db<D>(db: &D, db_key: &[Byte]) -> Result<BtcUtxoAndValue>
where
    D: DatabaseInterface,
{
    debug!("✔ Getting UTXO in db under key: {}", hex::encode(db_key));
    db.get(db_key.to_vec(), None)
        .and_then(|bytes| deserialize_utxo_and_value(&bytes))
}

pub fn put_utxo_in_db<D>(db: &D, key: &[Byte], utxo: &BtcUtxoAndValue) -> Result<()>
where
    D: DatabaseInterface,
{
    debug!("✔ Putting UTXO in db under key: {}", sha256d::Hash::from_slice(key)?);
    db.put(key.to_vec(), serialize_btc_utxo_and_value(utxo)?, None)
}

pub fn set_last_utxo_pointer<D>(db: &D, hash: &sha256d::Hash) -> Result<()>
where
    D: DatabaseInterface,
{
    debug!("✔ Setting `UTXO_LAST` pointer to: {}", hash);
    db.put(UTXO_LAST.to_vec(), hash.to_vec(), None)
}

pub fn get_last_utxo_pointer<D>(db: &D) -> Result<Bytes>
where
    D: DatabaseInterface,
{
    debug!("✔ Getting `UTXO_LAST` pointer...");
    db.get(UTXO_LAST.to_vec(), None)
}

pub fn set_first_utxo_pointer<D>(db: &D, hash: &sha256d::Hash) -> Result<()>
where
    D: DatabaseInterface,
{
    debug!("✔ Setting `UTXO_FIRST` pointer to: {}", hex::encode(&hash));
    db.put(UTXO_FIRST.to_vec(), hash.to_vec(), None)
}

pub fn get_first_utxo_pointer<D>(db: &D) -> Result<Bytes>
where
    D: DatabaseInterface,
{
    debug!("✔ Getting `UTXO_FIRST` pointer...");
    db.get(UTXO_FIRST.to_vec(), None)
}

pub fn get_utxo_nonce_from_db<D>(db: &D) -> Result<u64>
where
    D: DatabaseInterface,
{
    debug!("✔ Getting UTXO nonce from db...");
    match db.get(UTXO_NONCE.to_vec(), None) {
        Err(_) => {
            debug!("✘ Error getting UTXO nonce!");
            Ok(0)
        },
        Ok(bytes) => {
            debug!("✔ Converting bytes to usize for UTXO nonce...");
            convert_bytes_to_u64(&bytes)
        },
    }
}

pub fn get_total_number_of_utxos_from_db<D: DatabaseInterface>(db: &D) -> usize {
    debug!("✔ Getting total number of UTXOs from db...");
    get_all_utxo_db_keys(db).len()
}

pub fn put_utxo_nonce_in_db<D>(db: &D, utxo_nonce: u64) -> Result<()>
where
    D: DatabaseInterface,
{
    debug!("✔ Setting UTXO nonce to: {}", utxo_nonce);
    db.put(UTXO_NONCE.to_vec(), convert_u64_to_bytes(utxo_nonce), None)
}

pub fn increment_utxo_nonce_in_db<D>(db: &D) -> Result<()>
where
    D: DatabaseInterface,
{
    debug!("✔ Incrementing UTXO nonce in db by 1...");
    get_utxo_nonce_from_db(db).and_then(|num| put_utxo_nonce_in_db(db, num + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::btc::{
            btc_database_utils::key_exists_in_db,
            btc_test_utils::{get_sample_p2pkh_utxo_and_value, get_sample_utxo_and_values},
        },
        errors::AppError,
        test_utils::get_test_database,
    };

    fn remove_utxo_pointers(utxos: &BtcUtxosAndValues) -> BtcUtxosAndValues {
        BtcUtxosAndValues::new(utxos.iter().map(|utxo| remove_utxo_pointer(&utxo)).collect())
    }

    fn get_all_utxos_without_removing_from_db<D: DatabaseInterface>(db: &D) -> Result<BtcUtxosAndValues> {
        Ok(BtcUtxosAndValues::new(
            get_all_utxo_db_keys(db)
                .iter()
                .map(|key| get_utxo_from_db(db, key))
                .collect::<Result<Vec<BtcUtxoAndValue>>>()
                .unwrap(),
        ))
    }

    #[test]
    fn should_be_zero_utxos_when_non_in_db() {
        let db = get_test_database();
        let result = get_utxo_nonce_from_db(&db);
        assert!(result.is_ok());
    }

    #[test]
    fn should_put_num_of_utxos_in_db() {
        let db = get_test_database();
        let num = 1337;
        put_utxo_nonce_in_db(&db, num).unwrap();
        let result = get_utxo_nonce_from_db(&db).unwrap();
        assert_eq!(result, num);
    }

    #[test]
    fn should_increment_num_of_utxos_in_db() {
        let db = get_test_database();
        let num = 1336;
        put_utxo_nonce_in_db(&db, num).unwrap();
        increment_utxo_nonce_in_db(&db).unwrap();
        let result = get_utxo_nonce_from_db(&db).unwrap();
        assert_eq!(result, num + 1);
    }

    #[test]
    fn should_set_and_get_last_utxo_pointer() {
        let db = get_test_database();
        let pointer = "pBTC last".to_string();
        let pointer_hash = sha256d::Hash::hash(pointer.as_bytes());
        set_last_utxo_pointer(&db, &pointer_hash).unwrap();
        let result = get_last_utxo_pointer(&db).unwrap();
        assert_eq!(result, pointer_hash.to_vec());
    }

    #[test]
    fn should_set_and_get_fist_utxo_pointer() {
        let db = get_test_database();
        let pointer = "pBTC first".to_string();
        let pointer_hash = sha256d::Hash::hash(pointer.as_bytes());
        set_first_utxo_pointer(&db, &pointer_hash).unwrap();
        let result = get_first_utxo_pointer(&db).unwrap();
        assert_eq!(result, pointer_hash.to_vec());
    }

    #[test]
    fn should_put_and_get_utxo_in_db() {
        let db = get_test_database();
        let utxo = get_sample_p2pkh_utxo_and_value();
        let key = get_utxo_and_value_db_key(1);
        put_utxo_in_db(&db, &key, &utxo).unwrap();
        let result = get_utxo_from_db(&db, &key).unwrap();
        assert_eq!(result, utxo);
    }

    #[test]
    fn should_update_pointer_in_utxo_in_db() {
        let db = get_test_database();
        let utxo = get_sample_p2pkh_utxo_and_value();
        let key = get_utxo_and_value_db_key(1);
        let pointer = sha256d::Hash::hash(&[6u8, 6u8, 6u8]);
        assert_eq!(utxo.maybe_pointer, None);
        put_utxo_in_db(&db, &key, &utxo).unwrap();
        update_pointer_in_utxo_in_db(&db, &key, pointer).unwrap();
        let result = get_utxo_from_db(&db, &key).unwrap();
        assert_eq!(result.maybe_pointer, Some(pointer));
    }

    #[test]
    fn should_be_zero_utxo_balance_when_non_in_db() {
        let db = get_test_database();
        let result = get_total_utxo_balance_from_db(&db).unwrap();
        assert_eq!(result, 0);
    }

    #[test]
    fn should_set_and_get_total_utxo_balance_from_db() {
        let num = 1337;
        let db = get_test_database();
        put_total_utxo_balance_in_db(&db, num).unwrap();
        let result = get_total_utxo_balance_from_db(&db).unwrap();
        assert_eq!(result, num);
    }

    #[test]
    fn should_increment_total_utxo_balance_in_db() {
        let db = get_test_database();
        let num = 666;
        let expected_total = 1337;
        let amount_to_increment = 671;
        put_total_utxo_balance_in_db(&db, num).unwrap();
        increment_total_utxo_balance_in_db(&db, amount_to_increment).unwrap();
        let result = get_total_utxo_balance_from_db(&db).unwrap();
        assert_eq!(result, expected_total);
    }

    #[test]
    fn should_decrement_total_utxo_balance_in_db() {
        let db = get_test_database();
        let num = 1337;
        let expected_total = 666;
        let amount_to_decrement_by = 671;
        put_total_utxo_balance_in_db(&db, num).unwrap();
        decrement_total_utxo_balance_in_db(&db, amount_to_decrement_by).unwrap();
        let result = get_total_utxo_balance_from_db(&db).unwrap();
        assert_eq!(result, expected_total);
    }

    #[test]
    fn should_err_when_decrementing_with_underflow() {
        let db = get_test_database();
        let num = 1337;
        let amount_to_decrement_by = num + 1;
        assert!(amount_to_decrement_by > num);
        let expected_error = "✘ Not decrementing UTXO total value ∵ it'll underflow!".to_string();
        put_total_utxo_balance_in_db(&db, num).unwrap();
        match decrement_total_utxo_balance_in_db(&db, amount_to_decrement_by) {
            Ok(_) => panic!("Decrementing balance of utxos should error!"),
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            Err(e) => panic!("Wrong error on decrement UTXO balance: {}", e),
        };
    }

    #[test]
    fn should_delete_balance_key() {
        let db = get_test_database();
        let balance = 1;
        put_total_utxo_balance_in_db(&db, balance).unwrap();
        delete_utxo_balance_key(&db).unwrap();
        assert!(!key_exists_in_db(&db, &UTXO_BALANCE.to_vec(), None));
    }

    #[test]
    fn should_delete_first_key() {
        let db = get_test_database();
        let hash = sha256d::Hash::hash(&[1u8]);
        set_first_utxo_pointer(&db, &hash).unwrap();
        delete_first_utxo_key(&db).unwrap();
        let result = key_exists_in_db(&db, &UTXO_FIRST.to_vec(), None);
        assert!(!result);
    }

    #[test]
    fn should_delete_last_key() {
        let db = get_test_database();
        let hash = sha256d::Hash::hash(&[1u8]);
        set_last_utxo_pointer(&db, &hash).unwrap();
        delete_last_utxo_key(&db).unwrap();
        let result = key_exists_in_db(&db, &UTXO_LAST.to_vec(), None);
        assert!(!result);
    }

    #[test]
    fn should_save_gt_one_utxo() {
        let db = get_test_database();
        let utxo1 = get_sample_p2pkh_utxo_and_value();
        let hash1 = get_utxo_and_value_db_key(1);
        let mut utxo2 = utxo1.clone();
        let hash2 = get_utxo_and_value_db_key(2);
        let hash = sha256d::Hash::hash(b"a hash");
        utxo2.maybe_pointer = Some(hash);
        assert!(utxo1 != utxo2);
        save_new_utxo_and_value(&db, &utxo1).unwrap();
        let utxo_nonce = get_utxo_nonce_from_db(&db).unwrap();
        assert_eq!(utxo_nonce, 1);
        let mut first_pointer = get_first_utxo_pointer(&db).unwrap();
        assert_eq!(first_pointer, hash1);
        let mut last_pointer = get_last_utxo_pointer(&db).unwrap();
        assert_eq!(last_pointer, hash1);
        save_new_utxo_and_value(&db, &utxo2).unwrap();
        first_pointer = get_first_utxo_pointer(&db).unwrap();
        assert_eq!(first_pointer, hash1);
        last_pointer = get_last_utxo_pointer(&db).unwrap();
        assert_eq!(last_pointer, hash2);
        let result = get_utxo_from_db(&db, &hash1).unwrap();
        let expected_pointer = Some(sha256d::Hash::from_slice(&hash2).unwrap());
        assert_eq!(result.value, utxo1.value);
        assert_eq!(result.maybe_pointer, expected_pointer);
        assert_eq!(result.serialized_utxo, utxo1.serialized_utxo);
    }

    #[test]
    fn should_remove_1_utxo_correctly_when_gt_1_exist() {
        let db = get_test_database();
        let utxo1 = get_sample_p2pkh_utxo_and_value();
        let hash1 = get_utxo_and_value_db_key(1);
        let mut utxo2 = utxo1.clone();
        let hash2 = get_utxo_and_value_db_key(2);
        let hash = sha256d::Hash::hash(b"a hash");
        utxo2.maybe_pointer = Some(hash);
        let mut expected_utxo1 = utxo1.clone();
        expected_utxo1.maybe_pointer = Some(sha256d::Hash::from_slice(&hash2).unwrap());
        assert!(utxo1 != utxo2);
        save_new_utxo_and_value(&db, &utxo1).unwrap();
        save_new_utxo_and_value(&db, &utxo2).unwrap();
        let nonce = get_utxo_nonce_from_db(&db).unwrap();
        assert_eq!(nonce, 2);
        let mut first_pointer = get_first_utxo_pointer(&db).unwrap();
        assert_eq!(first_pointer, hash1);
        let mut last_pointer = get_last_utxo_pointer(&db).unwrap();
        assert_eq!(last_pointer, hash2);
        let utxo = get_first_utxo_and_value(&db).unwrap();
        assert_eq!(utxo, expected_utxo1);
        first_pointer = get_first_utxo_pointer(&db).unwrap();
        assert_eq!(first_pointer, hash2);
        last_pointer = get_last_utxo_pointer(&db).unwrap();
        assert_eq!(last_pointer, hash2);
    }

    #[test]
    fn should_remove_last_utxo_correctly() {
        let db = get_test_database();
        let utxo1 = get_sample_p2pkh_utxo_and_value();
        save_new_utxo_and_value(&db, &utxo1).unwrap();
        let first_pointer_before = get_first_utxo_pointer(&db).unwrap();
        let last_pointer_before = get_last_utxo_pointer(&db).unwrap();
        let utxo_total_before = get_total_utxo_balance_from_db(&db).unwrap();
        get_first_utxo_and_value(&db).unwrap();
        let first_pointer_after = get_first_utxo_pointer(&db);
        let last_pointer_after = get_last_utxo_pointer(&db);
        let utxo_total_after = get_total_utxo_balance_from_db(&db).unwrap();
        assert_eq!(utxo_total_after, 0);
        assert!(last_pointer_after.is_err());
        assert!(first_pointer_after.is_err());
        assert_eq!(utxo_total_before, utxo1.value);
        assert!(utxo_total_after < utxo_total_before);
        assert_eq!(first_pointer_before, last_pointer_before);
    }

    #[test]
    fn should_delete_first_utxo_in_db() {
        let db = get_test_database();
        let utxos = get_sample_utxo_and_values();
        let first_utxo_db_key = get_utxo_and_value_db_key(1);
        save_utxos_to_db(&db, &utxos).unwrap();
        assert!(key_exists_in_db(&db, &first_utxo_db_key, None));
        delete_first_utxo(&db).unwrap();
        assert!(!key_exists_in_db(&db, &first_utxo_db_key, None));
    }

    #[test]
    fn removed_utxos_should_no_longer_be_in_db() {
        let db = get_test_database();
        let utxos = get_sample_utxo_and_values();
        save_utxos_to_db(&db, &utxos).unwrap();
        utxos
            .0
            .iter()
            .enumerate()
            .for_each(|(i, _)| assert!(key_exists_in_db(&db, &get_utxo_and_value_db_key((i + 1) as u64), None)));
        assert_eq!(get_utxo_nonce_from_db(&db).unwrap(), utxos.len() as u64);
        assert_eq!(get_first_utxo_pointer(&db).unwrap(), get_utxo_and_value_db_key(1));
        get_first_utxo_and_value(&db).unwrap();
        assert_eq!(get_first_utxo_pointer(&db).unwrap(), get_utxo_and_value_db_key(2));
        assert!(!key_exists_in_db(&db, &get_utxo_and_value_db_key(1), None));
    }

    #[test]
    fn should_get_all_utxos_from_db_without_removing_them() {
        let db = get_test_database();
        let utxos = get_sample_utxo_and_values();
        save_utxos_to_db(&db, &utxos).unwrap();
        let utxos_from_db = get_all_utxos_without_removing_from_db(&db).unwrap();
        let result = remove_utxo_pointers(&utxos_from_db);
        assert_eq!(result, utxos);
    }

    fn should_get_utxo_with_tx_id_and_v_out_correctly(utxos: BtcUtxosAndValues, utxo_to_find_index: usize) {
        assert!(utxo_to_find_index <= utxos.len());
        let db = get_test_database();
        let utxo_to_find = utxos[utxo_to_find_index].clone();
        let v_out = utxo_to_find.get_v_out().unwrap();
        let tx_id = utxo_to_find.get_tx_id().unwrap();
        let mut expected_utxos_from_db_after = utxos.clone();
        expected_utxos_from_db_after.remove(utxo_to_find_index);
        save_utxos_to_db(&db, &utxos).unwrap();
        let utxos_from_db_before = get_all_utxos_without_removing_from_db(&db).unwrap();
        assert_eq!(utxos_from_db_before.len(), utxos.len());
        let result = get_utxo_with_tx_id_and_v_out(&db, v_out, &tx_id).unwrap();
        assert_eq!(remove_utxo_pointer(&result), utxo_to_find);
        let utxos_from_db_after = get_all_utxos_without_removing_from_db(&db).unwrap();
        assert_eq!(utxos_from_db_after.len(), utxos.len() - 1);
        assert!(!remove_utxo_pointers(&utxos_from_db_after).contains(&remove_utxo_pointer(&utxo_to_find)));
        remove_utxo_pointers(&utxos).iter().enumerate().for_each(|(i, utxo)| {
            if i != utxo_to_find_index {
                assert!(remove_utxo_pointers(&utxos_from_db_after).contains(utxo))
            }
        });
    }

    #[test]
    fn should_get_utxos_with_tx_id_and_v_out_correctly() {
        let utxos = get_sample_utxo_and_values();
        utxos
            .iter()
            .enumerate()
            .for_each(|(i, _)| should_get_utxo_with_tx_id_and_v_out_correctly(utxos.clone(), i));
    }

    #[test]
    fn should_fail_to_find_non_existent_utxo_correctly() {
        let db = get_test_database();
        let utxo_to_find_index = 3;
        let utxos = get_sample_utxo_and_values();
        let utxo_to_find = utxos[utxo_to_find_index].clone();
        let non_existent_v_out = utxo_to_find.get_v_out().unwrap() + 1;
        let tx_id = utxo_to_find.get_tx_id().unwrap();
        let mut expected_utxos_from_db_after = utxos.clone();
        expected_utxos_from_db_after.remove(utxo_to_find_index);
        save_utxos_to_db(&db, &utxos).unwrap();
        let utxos_from_db_before = get_all_utxos_without_removing_from_db(&db).unwrap();
        assert_eq!(utxos_from_db_before.len(), utxos.len());
        let expected_err = format!(
            "Could not find UTXO with v_out: {} & tx_id: {}",
            non_existent_v_out, tx_id
        );
        match get_utxo_with_tx_id_and_v_out(&db, non_existent_v_out, &tx_id) {
            Ok(_) => panic!("Should not have found utxo!"),
            Err(AppError::Custom(err)) => assert_eq!(err, expected_err),
            Err(_) => panic!("Wrong error when finding non-existent utxo"),
        };
        let utxos_from_db_after = get_all_utxos_without_removing_from_db(&db).unwrap();
        assert_eq!(utxos_from_db_after.len(), utxos.len());
        remove_utxo_pointers(&utxos_from_db_after)
            .iter()
            .for_each(|utxo| assert!(remove_utxo_pointers(&utxos).contains(&utxo)));
    }

    #[test]
    fn should_get_total_number_of_utxos_from_db() {
        let db = get_test_database();
        let utxos = get_sample_utxo_and_values();
        save_utxos_to_db(&db, &utxos).unwrap();
        let expected_result = utxos.len();
        let result = get_total_number_of_utxos_from_db(&db);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_x_utxos() {
        let num_utxos_to_get = 4;
        let db = get_test_database();
        let utxos = get_sample_utxo_and_values();
        save_utxos_to_db(&db, &utxos).unwrap();
        let result = get_x_utxos(&db, num_utxos_to_get).unwrap();
        assert_eq!(result.len(), num_utxos_to_get);
        let num_utxos_remaining = get_total_number_of_utxos_from_db(&db);
        assert_eq!(num_utxos_remaining, utxos.len() - num_utxos_to_get);
    }

    #[test]
    fn should_fail_to_get_x_utxos_correctly() {
        let db = get_test_database();
        let utxos = get_sample_utxo_and_values();
        let num_utxos_to_get = utxos.len() + 1;
        save_utxos_to_db(&db, &utxos).unwrap();
        let expected_err = format!(
            "Can't get {} UTXOS, there're only {} in the db!",
            num_utxos_to_get,
            utxos.len()
        );
        match get_x_utxos(&db, num_utxos_to_get) {
            Err(AppError::Custom(err)) => assert_eq!(err, expected_err),
            Err(_) => panic!("Wrong error receieved!"),
            Ok(_) => panic!("Should not have succeeded!"),
        };
    }
}
