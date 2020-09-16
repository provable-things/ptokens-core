#![allow(dead_code)] // TODO rm me!
use serde_json::{
    json,
    Value as JsonValue,
};
use bitcoin_hashes::{
    Hash,
    sha256d,
};
use bitcoin::{
    blockdata::transaction::TxIn as BtcUtxo,
    consensus::encode::deserialize as btc_deserialize,
};
use crate::{
    types::{
        Byte,
        Bytes,
        Result,
    },
    traits::DatabaseInterface,
    constants::MIN_DATA_SENSITIVITY_LEVEL,
    chains::btc::utxo_manager::{
        utxo_types::BtcUtxoAndValue,
        utxo_database_utils::{
            get_utxo_from_db,
            get_all_utxo_db_keys,
        },
    },
    errors::AppError,
};

pub fn get_utxo_and_value_db_key(
    utxo_number: u64,
) -> Bytes {
    sha256d::Hash::hash(
        format!("utxo-number-{}", utxo_number).as_bytes()
    ).to_vec()
}

pub fn serialize_btc_utxo_and_value(
    btc_utxo_and_value: &BtcUtxoAndValue
) -> Result<Bytes> {
    Ok(serde_json::to_vec(btc_utxo_and_value)?)
}

pub fn deserialize_utxo_and_value(
    bytes: &[Byte]
) -> Result<BtcUtxoAndValue> {
    Ok(serde_json::from_slice(bytes)?)
}

pub fn get_all_utxos_as_json_string<D>(
    db: D
) -> Result<String>
    where D: DatabaseInterface
{
    #[derive(Serialize, Deserialize)]
    struct UtxoDetails {
        pub db_key: String,
        pub db_value: String,
        pub utxo_and_value: JsonValue,
    }

    Ok(
        serde_json::to_string(
            &get_all_utxo_db_keys(&db)
                .iter()
                .map(|db_key| {
                    Ok::<UtxoDetails, AppError>(
                        UtxoDetails {
                            db_key: hex::encode(db_key.to_vec()),
                            db_value: hex::encode(db.get(db_key.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)?),
                            utxo_and_value: get_utxo_from_db(&db, &db_key.to_vec())
                                .map(|utxo_and_value|
                                    json!({
                                        "value": utxo_and_value.value,
                                        "maybe_pointer": utxo_and_value.maybe_pointer,
                                        "maybe_extra_data": utxo_and_value.maybe_extra_data,
                                        "serialized_utxo": hex::encode(utxo_and_value.serialized_utxo),
                                        "maybe_deposit_info_json": utxo_and_value.maybe_deposit_info_json,
                                    })
                                )?,
                        }
                    )
                })
                .flatten()
                .collect::<Vec<UtxoDetails>>()
        )?
    )
}

fn get_all_utxos_from_db<D: DatabaseInterface>(db: &D) -> Result<Vec<BtcUtxoAndValue>> {
    get_all_utxo_db_keys(db).iter().map(|db_key| get_utxo_from_db(db, &db_key.to_vec())) .collect()
}

fn get_btc_utxos_from_utxo_and_values(utxo_and_values: Vec<BtcUtxoAndValue>) -> Result<Vec<BtcUtxo>> {
    utxo_and_values
        .iter()
        .map(|utxo_and_value| Ok(btc_deserialize(&utxo_and_value.serialized_utxo)?))
        .collect::<Result<Vec<BtcUtxo>>>()
}

pub fn utxo_exists_in_db<D: DatabaseInterface>(db: &D, utxo_to_check: &BtcUtxoAndValue) -> Result<bool> {
    debug!("✔ Checking if UTXO exists in db...");
    get_all_utxos_from_db(db)
        .and_then(get_btc_utxos_from_utxo_and_values)
        .and_then(|btc_utxos_from_db| {
            Ok(btc_utxos_from_db.contains(&btc_deserialize(&utxo_to_check.serialized_utxo)?))
        })
}

pub fn utxos_exist_in_db<D: DatabaseInterface>(db: &D, utxos_to_check: &[BtcUtxoAndValue]) -> Result<Vec<bool>> {
    debug!("✔ Checking if UTXOs exist in db...");
    get_all_utxos_from_db(db)
        .and_then(get_btc_utxos_from_utxo_and_values)
        .and_then(|btc_utxos_from_db|
             utxos_to_check
                .iter()
                .map(|utxo_and_value| -> Result<BtcUtxo> { Ok(btc_deserialize(&utxo_and_value.serialized_utxo)?) })
                .map(|utxo| -> Result<bool> { Ok(btc_utxos_from_db.contains(&utxo?))})
                .collect()
         )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::get_test_database,
        chains::btc::utxo_manager::utxo_database_utils::save_new_utxo_and_value,
        btc_on_eth::btc::btc_test_utils::{
            get_sample_p2sh_utxo_and_value,
            get_sample_op_return_utxo_and_value,
        },
    };

    #[test]
    fn should_serde_op_return_btc_utxo_and_value() {
        let utxo = get_sample_op_return_utxo_and_value();
        let serialized_utxo = serialize_btc_utxo_and_value(&utxo).unwrap();
        let result = deserialize_utxo_and_value(&serialized_utxo).unwrap();
        assert_eq!(result, utxo);
    }

    #[test]
    fn should_serde_p2sh_btc_utxo_and_value() {
        let utxo = get_sample_p2sh_utxo_and_value().unwrap();
        let serialized_utxo = serialize_btc_utxo_and_value(&utxo).unwrap();
        let result = deserialize_utxo_and_value(&serialized_utxo).unwrap();
        assert_eq!(result, utxo);
    }

    #[test]
    fn should_get_utxo_db_key() {
        let expected_result = "b783e877488797a385ffd73089fc7d051db72ea1cf4290ee0d3a65efa712e29c";
        let num = 1;
        let result = get_utxo_and_value_db_key(num);
        assert_eq!(hex::encode(result), expected_result);
    }

    #[test]
    fn should_serde_utxo_and_value_with_something_in_the_maybe_pointer() {
        let mut utxo = get_sample_op_return_utxo_and_value();
        let pointer_hash = sha256d::Hash::hash(b"pointer hash");
        utxo.maybe_pointer = Some(pointer_hash);
        let serialized_utxo = serialize_btc_utxo_and_value(&utxo).unwrap();
        let result = deserialize_utxo_and_value(&serialized_utxo).unwrap();
        assert_eq!(result, utxo);
    }

    #[test]
    fn should_return_false_if_utxo_exists_in_db() {
        let expected_result = false;
        let db = get_test_database();
        let utxo_and_value = get_sample_p2sh_utxo_and_value().unwrap();
        let result = utxo_exists_in_db(&db, &utxo_and_value).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_return_true_if_utxo_exists_in_db() {
        let db = get_test_database();
        let utxo_and_value = get_sample_p2sh_utxo_and_value().unwrap();
        save_new_utxo_and_value(&db, &utxo_and_value).unwrap();
        let result = utxo_exists_in_db(&db, &utxo_and_value).unwrap();
        assert!(result);
    }

    #[test]
    fn should_return_correct_bool_array_when_checking_it_multiple_utxos_exist_in_db() {
        let expected_result = vec![false, true];
        let db = get_test_database();
        let utxo_and_value_1 = get_sample_p2sh_utxo_and_value().unwrap();
        let utxo_and_value_2 = get_sample_op_return_utxo_and_value();
        save_new_utxo_and_value(&db, &utxo_and_value_2).unwrap();
        let result = utxos_exist_in_db(&db, &[utxo_and_value_1, utxo_and_value_2]).unwrap();
        assert_eq!(result, expected_result);
    }
}
