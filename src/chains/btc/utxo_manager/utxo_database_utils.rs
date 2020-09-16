use bitcoin_hashes::{
    Hash,
    sha256d,
};
use crate::{
    traits::DatabaseInterface,
    types::{
        Byte,
        Bytes,
        Result,
    },
    utils::{
        convert_u64_to_bytes,
        convert_bytes_to_u64,
    },
    chains::btc::utxo_manager::{
        utxo_types::BtcUtxoAndValue,
        utxo_constants::{
            UTXO_LAST,
            UTXO_FIRST,
            UTXO_NONCE,
            UTXO_BALANCE,
        },
        utxo_utils::{
            get_utxo_and_value_db_key,
            deserialize_utxo_and_value,
            serialize_btc_utxo_and_value,
        },
    },
};

pub fn save_utxos_to_db<D>(
    db: &D,
    utxos_and_values: &[BtcUtxoAndValue]
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Saving {} `utxo_and_value`s...", utxos_and_values.len());
    utxos_and_values
        .iter()
        .map(|utxo_and_value| save_new_utxo_and_value(db, utxo_and_value))
        .collect::<Result<()>>()
}

pub fn get_all_utxo_db_keys<D>(db: &D) -> Vec<Bytes>
    where D: DatabaseInterface
{
    fn get_utxo_pointers_recursively<D>(
        db: &D,
        mut pointers: Vec<Bytes>
    ) -> Vec<Bytes>
        where D: DatabaseInterface
    {
        match maybe_get_next_utxo_pointer_from_utxo_pointer(
            db,
            &pointers[pointers.len() - 1]
        ) {
            Some(next_pointer) => {
                pointers.push(next_pointer);
                get_utxo_pointers_recursively(db, pointers)
            }
            None => pointers
        }
    }
    match get_first_utxo_pointer(db) {
        Ok(first_pointer) => get_utxo_pointers_recursively(
            db,
            vec![first_pointer]
        ),
        _ => vec![]
    }
}

fn maybe_get_next_utxo_pointer_from_utxo_pointer<D>(
    db: &D,
    utxo_pointer: &[Byte]
) -> Option<Bytes>
    where D: DatabaseInterface
{
    match maybe_get_utxo_from_db(db, &utxo_pointer) {
        None => None,
        Some(utxo) => match utxo.maybe_pointer {
            Some(pointer) => Some(pointer.to_vec()),
            None => None,
        }
    }
}

pub fn get_utxo_and_value<D>(db: &D) -> Result<BtcUtxoAndValue>
    where D: DatabaseInterface
{
    get_first_utxo_pointer(db)
        .and_then(|pointer| get_utxo_from_db(db, &pointer))
        .and_then(|utxo|
            match utxo.maybe_pointer {
                None => {
                    trace!("✔ No next pointer ∴ must be last UTXO in db!");
                    delete_utxo_balance_key(db)
                        .and_then(|_| delete_first_utxo(db))
                        .and_then(|_| delete_last_utxo_key(db))
                        .and_then(|_| delete_first_utxo_key(db))
                        .map(|_| utxo)
                }
                Some(pointer) => {
                    trace!("✔ UTXO found, updating `UTXO_FIRST` pointer...");
                    decrement_total_utxo_balance_in_db(db, utxo.value)
                        .and_then(|_| delete_first_utxo(db))
                        .and_then(|_| set_first_utxo_pointer(db, &pointer))
                        .map(|_| utxo)
                }
            }
        )
}

pub fn save_new_utxo_and_value<D>(
    db: &D,
    utxo_and_value: &BtcUtxoAndValue
) -> Result<()>
    where D: DatabaseInterface
{
    let value = utxo_and_value.value;
    let hash_vec = get_utxo_and_value_db_key(get_utxo_nonce_from_db(db)? + 1);
    let hash = sha256d::Hash::from_slice(&hash_vec)?;
    trace!("✔ Saving new UTXO in db under hash: {}", hash);
    match get_total_utxo_balance_from_db(db)? {
        0 => {
            trace!("✔ No UTXO balance ∴ setting `UTXO_FIRST` & `UTXO_LAST`...");
            set_first_utxo_pointer(db, &hash)
                .and_then(|_| increment_utxo_nonce_in_db(db))
                .and_then(|_| set_last_utxo_pointer(db, &hash))
                .and_then(|_| put_total_utxo_balance_in_db(db, value))
                .and_then(|_| put_utxo_in_db(db, &hash_vec, utxo_and_value))
        }
        _ => {
            trace!("✔ > 0 UTXO balance ∴ setting only `UTXO_LAST`...");
            update_pointer_in_last_utxo_in_db(db, hash)
                .and_then(|_| increment_utxo_nonce_in_db(db))
                .and_then(|_| set_last_utxo_pointer(db, &hash))
                .and_then(|_| put_utxo_in_db(db, &hash_vec, utxo_and_value))
                .and_then(|_| increment_total_utxo_balance_in_db(db, value))
        }
    }
}

pub fn delete_last_utxo_key<D>(db: &D) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Deleting `UTXO_LAST` key from db...");
    db.delete(UTXO_LAST.to_vec())
}

pub fn delete_first_utxo_key<D>(db: &D) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Deleting `UTXO_FIRST` key from db...");
    db.delete(UTXO_FIRST.to_vec())
}

pub fn delete_first_utxo<D>(db: &D) -> Result<()>
    where D: DatabaseInterface
{
    get_first_utxo_pointer(db)
        .and_then(|pointer| {
            trace!("✔ Deleting UTXO under key: {}", hex::encode(&pointer));
            db.delete(pointer.to_vec())
        })
}

pub fn delete_utxo_balance_key<D>(db: &D) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Deleting `UTXO_BALANCE` key from db...");
    db.delete(UTXO_BALANCE.to_vec())
}

pub fn increment_total_utxo_balance_in_db<D>(
    db: &D,
    amount_to_increment_by: u64,
) -> Result<()>
    where D: DatabaseInterface
{
    get_total_utxo_balance_from_db(db)
        .and_then(|balance| {
            trace!("✔ Incrementing UTXO total by: {}", amount_to_increment_by);
            put_total_utxo_balance_in_db(
                db,
                balance + amount_to_increment_by
            )
        })
}

pub fn decrement_total_utxo_balance_in_db<D>(
    db: &D,
    amount_to_decrement_by: u64,
) -> Result<()>
    where D: DatabaseInterface
{
    get_total_utxo_balance_from_db(db)
        .and_then(|balance|
            match balance >= amount_to_decrement_by {
                true => {
                    trace!(
                        "✔ Decrementing UTXO balance by {}",
                        amount_to_decrement_by
                    );
                    put_total_utxo_balance_in_db(
                        db,
                        balance - amount_to_decrement_by
                    )
                }
                false => Err("✘ Not decrementing UTXO total value ∵ it'll underflow!".into())
            }
        )
}

pub fn put_total_utxo_balance_in_db<D>(
    db: &D,
    balance: u64,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Setting total UTXO balance to: {}", balance);
    db.put(
        UTXO_BALANCE.to_vec(),
        convert_u64_to_bytes(balance),
        None,
    )
}

pub fn get_total_utxo_balance_from_db<D>(db: &D) -> Result<u64>
    where D: DatabaseInterface
{
    trace!("✔ Getting total UTXO balance from db...");
    match db.get(UTXO_BALANCE.to_vec(), None) {
        Err(_) => Ok(0),
        Ok(bytes) => convert_bytes_to_u64(&bytes),
    }
}

pub fn update_pointer_in_last_utxo_in_db<D>(
    db: &D,
    new_pointer: sha256d::Hash,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Updating `UTXO_LAST` pointer in db to {}", new_pointer);
    get_last_utxo_pointer(db)
        .and_then(|pointer_to_utxo|
            update_pointer_in_utxo_in_db(db, &pointer_to_utxo, new_pointer)
        )
}

pub fn update_pointer_in_utxo_in_db<D>(
    db: &D,
    db_key: &[Byte],
    new_pointer: sha256d::Hash,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!(
        "✔ Updating UTXO pointer in db under key: {} to: {}",
        hex::encode(db_key),
        new_pointer,
    );
    get_utxo_from_db(db, db_key)
        .map(|utxo| utxo.update_pointer(new_pointer))
        .and_then(|utxo| put_utxo_in_db(db, db_key, &utxo))
}

pub fn maybe_get_utxo_from_db<D>(
    db: &D,
    db_key: &[Byte]
) -> Option<BtcUtxoAndValue>
    where D: DatabaseInterface
{
    trace!("✔ Maybe getting UTXO in db under key: {}", hex::encode(db_key));
    match db.get(db_key.to_vec(), None) {
        Err(_) => {
            trace!("✘ No UTXO exists in the database @ that key!");
            None
        }
        Ok(bytes) => match deserialize_utxo_and_value(&bytes) {
            Ok(utxo_and_value) => Some(utxo_and_value),
            Err(_) => {
                trace!("✘ Error deserializing UTXO & value!");
                None
            }
        }
    }
}

pub fn get_utxo_from_db<D>(db: &D, db_key: &[Byte]) -> Result<BtcUtxoAndValue>
    where D: DatabaseInterface
{
    trace!(
        "✔ Getting UTXO in db under key: {}",
        hex::encode(db_key),
    );
    db.get(db_key.to_vec(), None)
        .and_then(|bytes| deserialize_utxo_and_value(&bytes))
}

pub fn put_utxo_in_db<D>(
    db: &D,
    key: &[Byte],
    utxo: &BtcUtxoAndValue,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!(
        "✔ Putting UTXO in db under key: {}",
        sha256d::Hash::from_slice(key)?
    );
    db.put(
        key.to_vec(),
        serialize_btc_utxo_and_value(utxo)?,
        None,
    )
}

pub fn set_last_utxo_pointer<D>(
    db: &D,
    hash: &sha256d::Hash
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Setting `UTXO_LAST` pointer to: {}", hash);
    db.put(UTXO_LAST.to_vec(), hash.to_vec(), None)
}

pub fn get_last_utxo_pointer<D>(db: &D) -> Result<Bytes>
    where D: DatabaseInterface
{
    trace!("✔ Getting `UTXO_LAST` pointer...");
    db.get(UTXO_LAST.to_vec(), None)
}

pub fn set_first_utxo_pointer<D>(
    db: &D,
    hash: &sha256d::Hash
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Setting `UTXO_FIRST` pointer to: {}", hash);
    db.put(UTXO_FIRST.to_vec(), hash.to_vec(), None)
}

pub fn get_first_utxo_pointer<D>(db: &D) -> Result<Bytes>
    where D: DatabaseInterface
{
    trace!("✔ Getting `UTXO_FIRST` pointer...");
    db.get(UTXO_FIRST.to_vec(), None)
}

pub fn get_utxo_nonce_from_db<D>(db: &D) -> Result<u64>
    where D: DatabaseInterface
{
    trace!("✔ Getting UTXO nonce from db...");
    match db.get(UTXO_NONCE.to_vec(), None) {
        Err(_) => {
            trace!("✘ Error getting UTXO nonce!");
            Ok(0)
        }
        Ok(bytes) => {
            trace!("✔ Converting bytes to usize for UTXO nonce...");
            convert_bytes_to_u64(&bytes)
        }
    }
}

pub fn get_total_number_of_utxos_from_db<D>(db: &D) -> Result<u64>
    where D: DatabaseInterface
{
    trace!("✔ Getting total number of UTXOs from db...");
    Ok(get_all_utxo_db_keys(db).len() as u64)
}

pub fn put_utxo_nonce_in_db<D>(
    db: &D,
    utxo_nonce: u64,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Setting UTXO nonce to: {}", utxo_nonce);
    db.put(
        UTXO_NONCE.to_vec(),
        convert_u64_to_bytes(utxo_nonce),
        None,
    )
}

pub fn increment_utxo_nonce_in_db<D>(db: &D) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Incrementing UTXO nonce in db by 1...");
    get_utxo_nonce_from_db(db)
        .and_then(|num| put_utxo_nonce_in_db(db, num + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    // FIXME Use generic versions of these, not the BTC ones!
    use crate::{
        errors::AppError,
        test_utils::get_test_database,
        btc_on_eth::btc::{
            btc_database_utils::key_exists_in_db,
            btc_test_utils::{
                get_sample_utxo_and_values,
                get_sample_op_return_utxo_and_value,
            },
        },
    };

    #[test]
    fn should_be_zero_utxos_when_non_in_db() {
        let db = get_test_database();
        if let Err(e) = get_utxo_nonce_from_db(&db) {
            panic!("Error getting num of utxos from db: {}", e);
        }
    }

    #[test]
    fn should_put_num_of_utxos_in_db() {
        let db = get_test_database();
        let num = 1337;
        if let Err(e) = put_utxo_nonce_in_db(&db, num) {
            panic!("Error putting num of utxos in database: {}", e);
        };
        match get_utxo_nonce_from_db(&db) {
            Err(e) => {
                panic!("Error getting num of utxos from db: {}", e);
            }
            Ok(num_from_db) => {
                assert_eq!(num_from_db, num);
            }
        }
    }

    #[test]
    fn should_increment_num_of_utxos_in_db() {
        let db = get_test_database();
        let num = 1336;
        if let Err(e) = put_utxo_nonce_in_db(&db, num) {
            panic!("Error putting num of utxos in database: {}", e);
        };
        if let Err(e) = increment_utxo_nonce_in_db(&db) {
            panic!("Error incrementing num utxos in db: {}", e);
        }
        match get_utxo_nonce_from_db(&db) {
            Err(e) => {
                panic!("Error getting num of utxos from db: {}", e);
            }
            Ok(num_from_db) => {
                assert_eq!(num_from_db, num + 1);
            }
        }
    }

    #[test]
    fn should_set_and_get_last_utxo_pointer() {
        let db = get_test_database();
        let pointer = "pBTC last".to_string();
        let pointer_hash = sha256d::Hash::hash(pointer.as_bytes());
        if let Err(e) = set_last_utxo_pointer(&db, &pointer_hash) {
            panic!("Error setting last utxo pointer: {}", e);
        }
        match get_last_utxo_pointer(&db) {
            Err(e) => {
                panic!("Error getting last utxo pointer: {}", e);
            }
            Ok(pointer_from_db) => {
                assert_eq!(pointer_from_db, pointer_hash.to_vec());
            }
        }
    }

    #[test]
    fn should_set_and_get_fist_utxo_pointer() {
        let db = get_test_database();
        let pointer = "pBTC first".to_string();
        let pointer_hash = sha256d::Hash::hash(pointer.as_bytes());
        if let Err(e) = set_first_utxo_pointer(&db, &pointer_hash) {
            panic!("Error setting last utxo pointer: {}", e);
        }
        match get_first_utxo_pointer(&db) {
            Err(e) => {
                panic!("Error getting last utxo pointer: {}", e);
            }
            Ok(pointer_from_db) => {
                assert_eq!(pointer_from_db, pointer_hash.to_vec());
            }
        }
    }

    #[test]
    fn should_put_and_get_utxo_in_db() {
        let db = get_test_database();
        let utxo = get_sample_op_return_utxo_and_value();
        let key = get_utxo_and_value_db_key(1);
        if let Err(e) = put_utxo_in_db(&db, &key, &utxo) {
            panic!("Error putting utxo in db: {}", e);
        };
        match get_utxo_from_db(&db, &key) {
            Err(e) => {
                panic!("Error getting utxo from db: {}", e);
            },
            Ok(utxo_from_db) => {
                assert_eq!(utxo_from_db, utxo);
            }
        };
    }

    #[test]
    fn should_update_pointer_in_utxo_in_db() {
        let db = get_test_database();
        let utxo = get_sample_op_return_utxo_and_value();
        let key = get_utxo_and_value_db_key(1);
        let pointer = sha256d::Hash::hash(&[6u8, 6u8, 6u8]);
        assert_eq!(utxo.maybe_pointer, None);
        if let Err(e) = put_utxo_in_db(&db, &key, &utxo) {
            panic!("Error putting utxo in db: {}", e);
        };
        if let Err(e) = update_pointer_in_utxo_in_db(&db, &key, pointer) {
            panic!("Error updating pointer in utxo in db: {}", e);
        };
        match get_utxo_from_db(&db, &key) {
            Err(e) => {
                panic!("Error getting utxo from db: {}", e);
            },
            Ok(utxo_from_db) => {
                assert_eq!(utxo_from_db.maybe_pointer, Some(pointer));
            }
        };
    }

    #[test]
    fn should_be_zero_utxo_balance_when_non_in_db() {
        let db = get_test_database();
        if let Err(e) = get_total_utxo_balance_from_db(&db) {
            panic!("Error getting num of utxos from db: {}", e);
        }
    }

    #[test]
    fn should_set_and_get_total_utxo_balance_from_db() {
        let db = get_test_database();
        let num = 1337;
        if let Err(e) = put_total_utxo_balance_in_db(&db, num) {
            panic!("Error putting num of utxos in database: {}", e);
        };
        match get_total_utxo_balance_from_db(&db) {
            Err(e) => {
                panic!("Error getting num of utxos from db: {}", e);
            }
            Ok(num_from_db) => {
                assert_eq!(num_from_db, num);
            }
        }
    }

    #[test]
    fn should_increment_total_utxo_balance_in_db() {
        let db = get_test_database();
        let num = 666;
        let amount_to_increment = 671;
        let expected_total = 1337;
        if let Err(e) = put_total_utxo_balance_in_db(&db, num) {
            panic!("Error putting num of utxos in database: {}", e);
        };
        if let Err(e) = increment_total_utxo_balance_in_db(
            &db,
            amount_to_increment,
        ) {
            panic!("Error incrementing num of utxos in database: {}", e);
        };
        match get_total_utxo_balance_from_db(&db) {
            Err(e) => {
                panic!("Error getting num of utxos from db: {}", e);
            }
            Ok(num_from_db) => {
                assert_eq!(num_from_db, expected_total);
            }
        }
    }

    #[test]
    fn should_decrement_total_utxo_balance_in_db() {
        let db = get_test_database();
        let num = 1337;
        let amount_to_decrement_by = 671;
        let expected_total = 666;
        if let Err(e) = put_total_utxo_balance_in_db(&db, num) {
            panic!("Error putting total of utxos in database: {}", e);
        };
        if let Err(e) = decrement_total_utxo_balance_in_db(
            &db,
            amount_to_decrement_by,
        ) {
            panic!("Error decrementing utxo balance in database: {}", e);
        };
        match get_total_utxo_balance_from_db(&db) {
            Err(e) => {
                panic!("Error getting balance of utxos from db: {}", e);
            }
            Ok(num_from_db) => {
                assert_eq!(num_from_db, expected_total);
            }
        }
    }

    #[test]
    fn should_err_when_decrementing_with_underflow() {
        let db = get_test_database();
        let num = 1337;
        let amount_to_decrement_by = num + 1;
        assert!(amount_to_decrement_by > num);
        let expected_error =
            "✘ Not decrementing UTXO total value ∵ it'll underflow!"
            .to_string();
        if let Err(e) = put_total_utxo_balance_in_db(&db, num) {
            panic!("Error putting num of utxos in database: {}", e);
        };
        match decrement_total_utxo_balance_in_db(
            &db,
            amount_to_decrement_by,
        ) {
            Ok(_) => {
                panic!("Decrementing balance of utxos should error!");
            }
            Err(AppError::Custom(e)) => {
                assert_eq!(e, expected_error);
            }
            Err(e) => {
                panic!("Wrong error on decrement UTXO balance: {}", e);
            }
        };
    }

    #[test]
    fn should_delete_balance_key() {
        let db = get_test_database();
        let balance = 1;
        if let Err(e) = put_total_utxo_balance_in_db(&db, balance) {
            panic!("Error setting `UTXO_BALANCE` in db: {}", e);
        };
        if let Err(e) = delete_utxo_balance_key(&db) {
            panic!("Error deleting `UTXO_BALANCE` key: {}", e);
        };
        assert!(!key_exists_in_db(&db, &UTXO_BALANCE.to_vec(), None));
    }

    #[test]
    fn should_delete_first_key() {
        let db = get_test_database();
        let hash = sha256d::Hash::hash(&[1u8]);
        if let Err(e) = set_first_utxo_pointer(&db, &hash) {
            panic!("Error setting `UTXO_FIRST` in db: {}", e);
        };
        if let Err(e) = delete_first_utxo_key(&db) {
            panic!("Error deleting `UTXO_FIRST` key: {}", e);
        };
        if key_exists_in_db(&db, &UTXO_FIRST.to_vec(), None) {
            panic!("`UTXO_FIRST` key should not exist!");
        }
    }

    #[test]
    fn should_delete_last_key() {
        let db = get_test_database();
        let hash = sha256d::Hash::hash(&[1u8]);
        if let Err(e) = set_last_utxo_pointer(&db, &hash) {
            panic!("Error setting `UTXO_LAST` in db: {}", e);
        };
        if let Err(e) = delete_last_utxo_key(&db) {
            panic!("Error deleting `UTXO_LAST` key: {}", e);
        };
        if key_exists_in_db(&db, &UTXO_LAST.to_vec(), None) {
            panic!("`UTXO_LAST` key should not exist!");
        }
    }

    #[test]
    fn should_save_gt_one_utxo() {
        let db = get_test_database();
        let utxo1 = get_sample_op_return_utxo_and_value();
        let hash1 = get_utxo_and_value_db_key(1);
        let mut utxo2 = utxo1.clone();
        let hash2 = get_utxo_and_value_db_key(2);
        let hash = sha256d::Hash::hash(b"a hash");
        utxo2.maybe_pointer = Some(hash);
        assert!(utxo1 != utxo2);
        if let Err(e) = save_new_utxo_and_value(&db, &utxo1) {
            panic!("Error saving utxo: {}", e);
        };
        match get_utxo_nonce_from_db(&db) {
            Ok(n) => assert_eq!(n, 1),
            Err(e) => {
                panic!("Error getting utxo nonce: {}", e);
            }
        };
        match get_first_utxo_pointer(&db) {
            Ok(ptr) => assert_eq!(ptr, hash1),
            Err(e) => {
                panic!("Error getting last utxo pointer from db: {}", e);
            }
        };
        match get_last_utxo_pointer(&db) {
            Ok(ptr) => assert_eq!(ptr, hash1),
            Err(e) => {
                panic!("Error getting last utxo pointer from db: {}", e);
            }
        };
        if let Err(e) = save_new_utxo_and_value(&db, &utxo2) {
            panic!("Error saving utxo: {}", e);
        };
        match get_first_utxo_pointer(&db) {
            Ok(ptr) => assert_eq!(ptr, hash1),
            Err(e) => {
                panic!("Error getting last utxo pointer from db: {}", e);
            }
        };
        match get_last_utxo_pointer(&db) {
            Ok(ptr) => assert_eq!(ptr, hash2),
            Err(e) => {
                panic!("Error getting last utxo pointer from db: {}", e);
            }
        };
        match get_utxo_from_db(&db, &hash1) {
            Ok(utxo1_from_db) => {
                let expected_pointer = Some(
                    sha256d::Hash::from_slice(&hash2).unwrap()
                );
                assert_eq!(utxo1_from_db.value, utxo1.value);
                assert_eq!(utxo1_from_db.maybe_pointer, expected_pointer);
                assert_eq!(utxo1_from_db.serialized_utxo, utxo1.serialized_utxo);
            }
            Err(e) => {
                panic!("Error getting utxo from db: {}", e);
            }
        };
    }

    #[test]
    fn should_remove_1_utxo_correctly_when_gt_1_exist() {
        let db = get_test_database();
        let utxo1 = get_sample_op_return_utxo_and_value();
        let hash1 = get_utxo_and_value_db_key(1);
        let mut utxo2 = utxo1.clone();
        let hash2 = get_utxo_and_value_db_key(2);
        let hash = sha256d::Hash::hash(b"a hash");
        utxo2.maybe_pointer = Some(hash);
        let mut expected_utxo1 = utxo1.clone();
        expected_utxo1.maybe_pointer = Some(
            sha256d::Hash::from_slice(&hash2)
                .unwrap()
        );
        assert!(utxo1 != utxo2);
        if let Err(e) = save_new_utxo_and_value(&db, &utxo1) {
            panic!("Error saving utxo: {}", e);
        };
        if let Err(e) = save_new_utxo_and_value(&db, &utxo2) {
            panic!("Error saving utxo: {}", e);
        };
        match get_utxo_nonce_from_db(&db) {
            Ok(n) => assert_eq!(n, 2),
            Err(e) => {
                panic!("Error getting utxo nonce: {}", e);
            }
        };
        match get_first_utxo_pointer(&db) {
            Ok(ptr) => assert_eq!(ptr, hash1),
            Err(e) => {
                panic!("Error getting last utxo pointer from db: {}", e);
            }
        };
        match get_last_utxo_pointer(&db) {
            Ok(ptr) => assert_eq!(ptr, hash2),
            Err(e) => {
                panic!("Error getting last utxo pointer from db: {}", e);
            }
        };
        match get_utxo_and_value(&db) {
            Ok(utxo) => assert_eq!(utxo, expected_utxo1),
            Err(e) => {
                panic!("Error getting utxo from db: {}", e);
            }
        };
        match get_first_utxo_pointer(&db) {
            Ok(ptr) => assert_eq!(ptr, hash2),
            Err(e) => {
                panic!("Error getting last utxo pointer from db: {}", e);
            }
        };
        match get_last_utxo_pointer(&db) {
            Ok(ptr) => assert_eq!(ptr, hash2),
            Err(e) => {
                panic!("Error getting last utxo pointer from db: {}", e);
            }
        };
    }

    #[test]
    fn should_remove_last_utxo_correctly() {
        let db = get_test_database();
        let utxo1 = get_sample_op_return_utxo_and_value();
        if let Err(e) = save_new_utxo_and_value(&db, &utxo1) {
            panic!("Error saving utxo: {}", e);
        };
        let first_pointer_before = get_first_utxo_pointer(&db)
            .unwrap();
        let last_pointer_before = get_last_utxo_pointer(&db)
            .unwrap();
        let utxo_total_before = get_total_utxo_balance_from_db(&db)
            .unwrap();
        if let Err(e) = get_utxo_and_value(&db) {
            panic!("Error getting UTXO from db: {}", e);
        };
        let first_pointer_after = get_first_utxo_pointer(&db);
        let last_pointer_after = get_last_utxo_pointer(&db);
        let utxo_total_after = get_total_utxo_balance_from_db(&db)
            .unwrap();
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
        if let Err(e) = save_utxos_to_db(&db, &utxos) {
            panic!("Error saving utxos to db: {}", e);
        }
        assert!(key_exists_in_db(&db, &first_utxo_db_key, None));
        if let Err(e) = delete_first_utxo(&db) {
            panic!("Error deleting first UTXO from db: {}", e);
        }
        assert!(!key_exists_in_db(&db, &first_utxo_db_key, None));
    }

    #[test]
    fn removed_utxos_should_no_longer_be_in_db() {
        let db = get_test_database();
        let utxos = get_sample_utxo_and_values();
        if let Err(e) = save_utxos_to_db(&db, &utxos) {
            panic!("Error saving utxos to db: {}", e);
        }
        utxos
            .iter()
            .enumerate()
            .map(|(i, _)|
                 assert!(
                     key_exists_in_db(
                         &db,
                         &get_utxo_and_value_db_key((i + 1) as u64),
                         None,
                     )
                 )
             )
            .for_each(drop);
        assert_eq!(
            get_utxo_nonce_from_db(&db).unwrap(),
            utxos.len() as u64
        );
        assert_eq!(
            get_first_utxo_pointer(&db).unwrap(),
            get_utxo_and_value_db_key(1)
        );
        if let Err(e) = get_utxo_and_value(&db) {
            panic!("Error getting utxo and value from db: {}", e);
        }
        assert_eq!(
            get_first_utxo_pointer(&db).unwrap(),
            get_utxo_and_value_db_key(2)
        );
        assert!(
            !key_exists_in_db(
                 &db,
                &get_utxo_and_value_db_key(1),
                None,
            )
        );
    }
}
