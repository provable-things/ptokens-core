use std::str::FromStr;

use bitcoin::{blockdata::transaction::Transaction as BtcTransaction, util::address::Address as BtcAddress};

use crate::{
    chains::btc::{
        btc_database_utils::{get_btc_address_from_db, get_btc_fee_from_db, get_btc_private_key_from_db},
        btc_transaction::create_signed_raw_btc_tx_for_n_input_n_outputs,
        btc_types::BtcRecipientAndAmount,
        utxo_manager::{utxo_types::BtcUtxosAndValues, utxo_utils::get_enough_utxos_to_cover_total},
    },
    core_type::CoreType,
    fees::fee_database_utils::FeeDatabaseUtils,
    traits::DatabaseInterface,
    types::Result,
    utils::get_unix_timestamp,
};

pub fn get_fee_withdrawal_btc_tx_for_core_type<D: DatabaseInterface>(
    core_type: &CoreType,
    db: &D,
    btc_address: &str,
) -> Result<BtcTransaction> {
    let fee_db_utils = FeeDatabaseUtils::new_for_core_type(core_type)?;
    let withdrawal_amount = fee_db_utils.get_accrued_fees_from_db(db)?;
    if withdrawal_amount == 0 {
        Err(format!(
            "Cannot get `{}` withdrawal tx - there are no fees to withdraw!",
            core_type
        )
        .into())
    } else {
        let fee = get_btc_fee_from_db(db)?;
        let recipients_and_amounts = vec![BtcRecipientAndAmount {
            recipient: BtcAddress::from_str(btc_address)?,
            amount: withdrawal_amount,
        }];
        fee_db_utils
            .put_last_fee_withdrawal_timestamp_in_db(db, get_unix_timestamp()?)
            .and_then(|_| {
                get_enough_utxos_to_cover_total(
                    db,
                    withdrawal_amount,
                    recipients_and_amounts.len(),
                    fee,
                    BtcUtxosAndValues::new(vec![]),
                )
            })
            .and_then(|utxos| {
                create_signed_raw_btc_tx_for_n_input_n_outputs(
                    fee,
                    recipients_and_amounts,
                    &get_btc_address_from_db(db)?,
                    get_btc_private_key_from_db(db)?,
                    utxos,
                )
            })
            .and_then(|signed_btc_tx| {
                fee_db_utils.reset_accrued_fees(db)?;
                Ok(signed_btc_tx)
            })
    }
}

pub fn get_btc_on_eth_fee_withdrawal_tx<D: DatabaseInterface>(db: &D, btc_address: &str) -> Result<BtcTransaction> {
    get_fee_withdrawal_btc_tx_for_core_type(&CoreType::BtcOnEth, db, btc_address)
}

pub fn get_btc_on_eos_fee_withdrawal_tx<D: DatabaseInterface>(db: &D, btc_address: &str) -> Result<BtcTransaction> {
    get_fee_withdrawal_btc_tx_for_core_type(&CoreType::BtcOnEos, db, btc_address)
}

#[cfg(test)]
mod tests {
    use bitcoin::network::constants::Network as BtcNetwork;

    use super::*;
    use crate::{
        chains::btc::{
            btc_database_utils::{
                put_btc_address_in_db,
                put_btc_fee_in_db,
                put_btc_network_in_db,
                put_btc_private_key_in_db,
            },
            btc_test_utils::{get_sample_btc_private_key, get_sample_utxo_and_values},
            utxo_manager::utxo_database_utils::save_utxos_to_db,
        },
        errors::AppError,
        test_utils::get_test_database,
    };

    #[test]
    fn should_get_btc_on_eth_accrued_fees_from_db() {
        let btc_fee = 20;
        let accrued_fees = 1;
        let db = get_test_database();
        let utxos = get_sample_utxo_and_values();
        let change_address = "mwbtrpDGLWiMiq1TB7DhnrEN14B5Hydp28";
        let pk = get_sample_btc_private_key();
        save_utxos_to_db(&db, &utxos).unwrap();
        FeeDatabaseUtils::new_for_btc_on_eth()
            .increment_accrued_fees(&db, accrued_fees)
            .unwrap();
        put_btc_fee_in_db(&db, btc_fee).unwrap();
        put_btc_address_in_db(&db, change_address).unwrap();
        put_btc_network_in_db(&db, BtcNetwork::Testnet).unwrap();
        put_btc_private_key_in_db(&db, &pk).unwrap();
        let accrued_fees_before = FeeDatabaseUtils::new_for_btc_on_eth()
            .get_accrued_fees_from_db(&db)
            .unwrap();
        assert_eq!(accrued_fees_before, accrued_fees);
        let recipient_address = "msgbp2MiwL6M1qkhZx9N46ipPn12tzLzZ7";
        let result = get_btc_on_eth_fee_withdrawal_tx(&db, recipient_address).unwrap();
        let accrued_fees_after = FeeDatabaseUtils::new_for_btc_on_eth()
            .get_accrued_fees_from_db(&db)
            .unwrap();
        assert_eq!(accrued_fees_after, 0);
        assert_eq!(result.output[0].value, accrued_fees);
    }

    #[test]
    fn get_btc_on_eth_accrued_fees_from_db_should_err_if_no_fees_to_withdraw() {
        let db = get_test_database();
        let expected_err = "Cannot get `BTC_ON_ETH` withdrawal tx - there are no fees to withdraw!".to_string();
        let recipient_address = "msgbp2MiwL6M1qkhZx9N46ipPn12tzLzZ7";
        match get_btc_on_eth_fee_withdrawal_tx(&db, recipient_address) {
            Err(AppError::Custom(err)) => assert_eq!(err, expected_err),
            Ok(_) => panic!("Should not have succeeded!"),
            Err(_) => panic!("Wrong error received!"),
        }
    }
}
