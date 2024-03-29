use serde_json::json;

use crate::{
    chains::btc::{
        btc_database_utils::{get_btc_address_from_db, get_btc_fee_from_db, get_btc_private_key_from_db},
        btc_transaction::create_signed_raw_btc_tx_for_n_input_n_outputs,
        btc_utils::{get_btc_tx_id_from_str, get_hex_tx_from_signed_btc_tx, get_pay_to_pub_key_hash_script},
        extract_utxos_from_p2pkh_txs::extract_utxos_from_txs,
        utxo_manager::{
            utxo_database_utils::{
                delete_first_utxo_key,
                delete_last_utxo_key,
                get_all_utxo_db_keys,
                get_total_number_of_utxos_from_db,
                get_utxo_with_tx_id_and_v_out,
                get_x_utxos,
                put_total_utxo_balance_in_db,
                save_new_utxo_and_value,
                save_utxos_to_db,
            },
            utxo_types::BtcUtxosAndValues,
            utxo_utils::utxo_exists_in_db,
        },
    },
    check_debug_mode::check_debug_mode,
    constants::SUCCESS_JSON,
    traits::DatabaseInterface,
    types::Result,
};

pub fn clear_all_utxos<D: DatabaseInterface>(db: &D) -> Result<String> {
    db.start_transaction()?;
    Ok(get_all_utxo_db_keys(db).to_vec())
        .and_then(|db_keys| {
            db_keys
                .iter()
                .map(|db_key| db.delete(db_key.to_vec()))
                .collect::<Result<Vec<()>>>()
        })
        .and_then(|_| delete_last_utxo_key(db))
        .and_then(|_| delete_first_utxo_key(db))
        .and_then(|_| put_total_utxo_balance_in_db(db, 0))
        .and_then(|_| db.end_transaction())
        .map(|_| SUCCESS_JSON.to_string())
}

pub fn remove_utxo<D: DatabaseInterface>(db: D, tx_id: &str, v_out: u32) -> Result<String> {
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| get_btc_tx_id_from_str(tx_id))
        .and_then(|id| get_utxo_with_tx_id_and_v_out(&db, v_out, &id))
        .and_then(|_| db.end_transaction())
        .map(|_| json!({ "v_out_of_removed_utxo": v_out, "tx_id_of_removed_utxo": tx_id }).to_string())
}

pub fn consolidate_utxos<D: DatabaseInterface>(db: D, fee: u64, num_utxos: usize) -> Result<String> {
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| get_x_utxos(&db, num_utxos))
        .and_then(|utxos| {
            if num_utxos < 1 {
                return Err("Cannot consolidate 0 UTXOs!".into());
            };
            let btc_address = get_btc_address_from_db(&db)?;
            let target_script = get_pay_to_pub_key_hash_script(&btc_address)?;
            let btc_tx = create_signed_raw_btc_tx_for_n_input_n_outputs(
                fee,
                vec![],
                &btc_address,
                get_btc_private_key_from_db(&db)?,
                utxos,
            )?;
            let change_utxos = extract_utxos_from_txs(&target_script, &[btc_tx.clone()]);
            save_utxos_to_db(&db, &change_utxos)?;
            Ok(btc_tx)
        })
        .and_then(|btc_tx| {
            let output = json!({
                "fee": fee,
                "num_utxos_spent": num_utxos,
                "btc_tx_hash": btc_tx.txid().to_string(),
                "btc_tx_hex": get_hex_tx_from_signed_btc_tx(&btc_tx),
                "num_utxos_remaining": get_total_number_of_utxos_from_db(&db),
            })
            .to_string();
            db.end_transaction()?;
            Ok(output)
        })
}

pub fn get_child_pays_for_parent_btc_tx<D: DatabaseInterface>(
    db: D,
    fee: u64,
    tx_id: &str,
    v_out: u32,
) -> Result<String> {
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| get_btc_tx_id_from_str(tx_id))
        .and_then(|id| get_utxo_with_tx_id_and_v_out(&db, v_out, &id))
        .and_then(|utxo| {
            const MAX_FEE_MULTIPLE: u64 = 10;
            let fee_from_db = get_btc_fee_from_db(&db)?;
            let btc_address = get_btc_address_from_db(&db)?;
            let target_script = get_pay_to_pub_key_hash_script(&btc_address)?;
            if fee > fee_from_db * MAX_FEE_MULTIPLE {
                return Err("Passed in fee is > 10x the fee saved in the db!".into());
            };
            let btc_tx = create_signed_raw_btc_tx_for_n_input_n_outputs(
                fee,
                vec![],
                &btc_address,
                get_btc_private_key_from_db(&db)?,
                BtcUtxosAndValues::new(vec![utxo]),
            )?;
            let change_utxos = extract_utxos_from_txs(&target_script, &[btc_tx.clone()]);
            save_utxos_to_db(&db, &change_utxos)?;
            db.end_transaction()?;
            Ok(btc_tx)
        })
        .map(|btc_tx| {
            json!({
                "fee": fee,
                "v_out_of_spent_utxo": v_out,
                "tx_id_of_spent_utxo": tx_id,
                "btc_tx_hash": btc_tx.txid().to_string(),
                "btc_tx_hex": get_hex_tx_from_signed_btc_tx(&btc_tx),
            })
            .to_string()
        })
}

pub fn add_multiple_utxos<D: DatabaseInterface>(db: &D, json_str: &str) -> Result<String> {
    BtcUtxosAndValues::from_str(json_str)
        .and_then(|utxos| {
            utxos
                .iter()
                .map(|utxo| utxo_exists_in_db(db, utxo))
                .collect::<Result<Vec<bool>>>()?
                .iter()
                .zip(utxos.iter())
                .filter_map(|(exists, utxo)| {
                    if *exists {
                        warn!("Not adding UTXO because it already exists!");
                        None
                    } else {
                        Some(utxo)
                    }
                })
                .map(|utxo| save_new_utxo_and_value(db, utxo))
                .collect::<Result<Vec<()>>>()
        })
        .map(|_| SUCCESS_JSON.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::btc::{
            btc_test_utils::get_sample_utxo_and_values,
            utxo_manager::{
                utxo_database_utils::{get_total_utxo_balance_from_db, save_utxos_to_db},
                utxo_utils::get_all_utxos_as_json_string,
            },
        },
        test_utils::get_test_database,
    };

    #[test]
    fn should_clear_all_utxos() {
        let db = get_test_database();
        let utxos = get_sample_utxo_and_values();
        let expected_balance = utxos.sum();
        save_utxos_to_db(&db, &utxos).unwrap();
        let mut balance = get_total_utxo_balance_from_db(&db).unwrap();
        assert_eq!(expected_balance, balance);
        clear_all_utxos(&db).unwrap();
        balance = get_total_utxo_balance_from_db(&db).unwrap();
        assert_eq!(0, balance);
    }

    #[test]
    fn should_insert_multiple_utxos() {
        let db = get_test_database();
        let utxos = get_sample_utxo_and_values();
        let expected_balance = utxos.sum();
        save_utxos_to_db(&db, &utxos).unwrap();
        let mut balance = get_total_utxo_balance_from_db(&db).unwrap();
        assert_eq!(expected_balance, balance);
        let json = get_all_utxos_as_json_string(&db).unwrap();
        clear_all_utxos(&db).unwrap();
        balance = get_total_utxo_balance_from_db(&db).unwrap();
        assert_eq!(0, balance);
        add_multiple_utxos(&db, &json).unwrap();
        balance = get_total_utxo_balance_from_db(&db).unwrap();
        assert_eq!(expected_balance, balance);
    }
}
