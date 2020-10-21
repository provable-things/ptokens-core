use bitcoin::blockdata::script::Script as BtcScript;
use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::{
        btc_utils::{
            create_unsigned_utxo_from_tx,
            get_pay_to_pub_key_hash_script,
        },
        utxo_manager::utxo_types::{
            BtcUtxoAndValue,
            BtcUtxosAndValues,
        },
    },
    btc_on_eth::btc::{
        btc_state::BtcState,
        btc_types::BtcTransaction,
        btc_database_utils::get_btc_address_from_db,
    },
};

pub fn extract_utxos_from_txs(
    target_script: &BtcScript,
    txs: &[BtcTransaction]
) -> BtcUtxosAndValues {
    info!("✔ Extracting UTXOs from {} `op_return` txs...", txs.len());
    BtcUtxosAndValues::new(
        txs
            .iter()
            .map(|tx_data|
                tx_data
                    .output
                    .iter()
                    .enumerate()
                    .filter(|(_, output)| &output.script_pubkey == target_script)
                    .map(|(index, output)|
                        BtcUtxoAndValue::new(
                            output.value,
                            &create_unsigned_utxo_from_tx(tx_data, index as u32),
                            None,
                            None,
                        )
                    )
                    .collect::<Vec<BtcUtxoAndValue>>()
            )
            .flatten()
            .collect::<Vec<BtcUtxoAndValue>>()
    )
}

pub fn maybe_extract_utxos_from_op_return_txs_and_put_in_state<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe extracting UTXOs from `op_return` txs...");
    get_btc_address_from_db(&state.db)
        .and_then(|btc_address| get_pay_to_pub_key_hash_script(&btc_address))
        .and_then(|target_script|
            Ok(
                extract_utxos_from_txs(
                    &target_script,
                    state.get_op_return_deposit_txs()?,
                )
            )
        )
        .and_then(|utxos| {
            debug!("✔ Extracted UTXOs: {:?}", utxos);
            info!("✔ Extracted {} `op_return` UTXOs", utxos.len());
            state.add_utxos_and_values(utxos)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_on_eth::btc::btc_test_utils::{
        get_sample_btc_tx,
        get_sample_btc_utxo,
        SAMPLE_OUTPUT_INDEX_OF_UTXO,
        get_sample_testnet_block_and_txs,
        get_sample_op_return_utxo_and_value,
        get_sample_pay_to_pub_key_hash_script,
    };

    #[test]
    fn should_create_unsigned_utxo_from_tx_output() {
        let tx = get_sample_btc_tx();
        let result = create_unsigned_utxo_from_tx(
            &tx,
            SAMPLE_OUTPUT_INDEX_OF_UTXO,
        );
        let expected_result = get_sample_btc_utxo();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_extract_utxos_from_relevant_txs() {
        let expected_num_utxos = 1;
        let expected_utxo_and_value = get_sample_op_return_utxo_and_value();
        let txs = get_sample_testnet_block_and_txs()
            .unwrap()
            .block
            .txdata;
        let target_script = get_sample_pay_to_pub_key_hash_script();
        let result = extract_utxos_from_txs(&target_script, &txs);
        assert_eq!(result.len(), expected_num_utxos);
        assert_eq!(result, BtcUtxosAndValues::new(vec![expected_utxo_and_value]));
    }
}
