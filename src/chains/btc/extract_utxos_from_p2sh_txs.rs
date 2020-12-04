use crate::{
    chains::btc::{
        btc_database_utils::get_btc_network_from_db,
        btc_state::BtcState,
        btc_utils::create_unsigned_utxo_from_tx,
        deposit_address_info::DepositInfoHashMap,
        utxo_manager::utxo_types::{BtcUtxoAndValue, BtcUtxosAndValues},
    },
    traits::DatabaseInterface,
    types::Result,
};
use bitcoin::{
    blockdata::transaction::{Transaction as BtcTransaction, TxOut as BtcTxOut},
    network::constants::Network as BtcNetwork,
    util::address::Address as BtcAddress,
};

fn maybe_extract_p2sh_utxo(
    output_index: u32,
    tx_output: &BtcTxOut,
    full_tx: &BtcTransaction,
    btc_network: BtcNetwork,
    deposit_info_hash_map: &DepositInfoHashMap,
) -> Option<BtcUtxoAndValue> {
    info!("✔ Extracting UTXOs from single `p2sh` transaction...");
    match tx_output.script_pubkey.is_p2sh() {
        false => None,
        true => match BtcAddress::from_script(&tx_output.script_pubkey, btc_network) {
            None => {
                info!("✘ Could not derive BTC address from tx outout: {:?}", tx_output);
                None
            },
            Some(btc_address) => {
                info!("✔ BTC address extracted from `tx_out`: {}", btc_address);
                match deposit_info_hash_map.get(&btc_address) {
                    None => {
                        info!(
                            "✘ BTC address {} not in deposit hash map ∴ NOT extracting UTXO!",
                            btc_address
                        );
                        None
                    },
                    Some(deposit_info) => {
                        info!("✔ Deposit info extracted from hash map: {:?}", deposit_info);
                        Some(BtcUtxoAndValue::new(
                            tx_output.value,
                            &create_unsigned_utxo_from_tx(full_tx, output_index),
                            Some(deposit_info.to_json()),
                            None,
                        ))
                    },
                }
            },
        },
    }
}

pub fn extract_p2sh_utxos_from_txs(
    transactions: &[BtcTransaction],
    deposit_info_hash_map: &DepositInfoHashMap,
    btc_network: BtcNetwork,
) -> Result<BtcUtxosAndValues> {
    info!("✔ Extracting UTXOs from `p2sh` transactions...");
    Ok(BtcUtxosAndValues::new(
        transactions
            .iter()
            .map(|full_tx| {
                full_tx
                    .output
                    .iter()
                    .enumerate()
                    .filter_map(|(i, tx_output)| {
                        maybe_extract_p2sh_utxo(i as u32, tx_output, full_tx, btc_network, deposit_info_hash_map)
                    })
                    .collect::<Vec<BtcUtxoAndValue>>()
            })
            .flatten()
            .collect::<Vec<BtcUtxoAndValue>>(),
    ))
}

pub fn maybe_extract_utxos_from_p2sh_txs_and_put_in_state<D>(state: BtcState<D>) -> Result<BtcState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Maybe extracting UTXOs from `p2sh` txs...");
    extract_p2sh_utxos_from_txs(
        state.get_p2sh_deposit_txs()?,
        state.get_deposit_info_hash_map()?,
        get_btc_network_from_db(&state.db)?,
    )
    .and_then(|utxos| {
        debug!("✔ Extracted `p2sh` UTXOs: {:?}", utxos);
        info!("✔ Extracted {} `p2sh` UTXOs", utxos.len());
        state.add_utxos_and_values(utxos)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::btc::{
        btc_test_utils::{get_sample_btc_block_n, get_sample_btc_pub_key_slice, get_sample_p2sh_utxo_and_value},
        btc_utils::convert_bytes_to_btc_pub_key_slice,
        filter_p2sh_deposit_txs::filter_p2sh_deposit_txs,
        get_deposit_info_hash_map::create_hash_map_from_deposit_info_list,
    };
    use std::str::FromStr;

    #[test]
    fn should_maybe_extract_p2sh_utxo() {
        let pub_key_slice = get_sample_btc_pub_key_slice();
        let output_index: u32 = 0;
        let expected_result = get_sample_p2sh_utxo_and_value().unwrap();
        let btc_network = BtcNetwork::Testnet;
        let block_and_id = get_sample_btc_block_n(5).unwrap();
        let deposit_address_list = block_and_id.deposit_address_list.clone();
        let txs = block_and_id.block.txdata;
        let hash_map = create_hash_map_from_deposit_info_list(&deposit_address_list).unwrap();
        let tx = filter_p2sh_deposit_txs(&hash_map, &pub_key_slice, &txs, btc_network).unwrap()[0].clone();
        let output = tx.output[output_index as usize].clone();
        let result = maybe_extract_p2sh_utxo(output_index, &output, &tx, btc_network, &hash_map).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_extract_p2sh_utxos_from_txs() {
        let pub_key_slice = get_sample_btc_pub_key_slice();
        let expected_result = get_sample_p2sh_utxo_and_value().unwrap();
        let expected_num_utxos = 1;
        let btc_network = BtcNetwork::Testnet;
        let block_and_id = get_sample_btc_block_n(5).unwrap();
        let deposit_address_list = block_and_id.deposit_address_list.clone();
        let txs = block_and_id.block.txdata;
        let hash_map = create_hash_map_from_deposit_info_list(&deposit_address_list).unwrap();
        let filtered_txs = filter_p2sh_deposit_txs(&hash_map, &pub_key_slice, &txs, btc_network).unwrap();
        let result = extract_p2sh_utxos_from_txs(&filtered_txs, &hash_map, btc_network).unwrap();
        assert_eq!(result.len(), expected_num_utxos);
        assert_eq!(result.0[0], expected_result);
    }

    #[test]
    fn should_extract_p2sh_utxos_from_txs_with_gt_1_p2sh_output_correctly() {
        let expected_num_results = 2;
        let expected_value_1 = 314159;
        let expected_value_2 = 1000000;
        let expected_btc_address_1 = BtcAddress::from_str("2NCfNHvNAecRyXPBDaAkfgMLL7NjvPrC6GU").unwrap();
        let expected_btc_address_2 = BtcAddress::from_str("2N6DgNSaX3D5rUYXuMM3b5Ujgw4sPrddSHp").unwrap();
        let pub_key_bytes = convert_bytes_to_btc_pub_key_slice(
            &hex::decode("03a3bea6d8d15a38d9c96074d994c788bc1286d557ef5bdbb548741ddf265637ce").unwrap(),
        )
        .unwrap();
        let btc_network = BtcNetwork::Testnet;
        let block_and_id = get_sample_btc_block_n(6).unwrap();
        let deposit_address_list = block_and_id.deposit_address_list.clone();
        let txs = block_and_id.block.txdata;
        let hash_map = create_hash_map_from_deposit_info_list(&deposit_address_list).unwrap();
        let expected_deposit_info_1 = Some(hash_map.get(&expected_btc_address_1).unwrap().to_json());
        let expected_deposit_info_2 = Some(hash_map.get(&expected_btc_address_2).unwrap().to_json());
        let filtered_txs = filter_p2sh_deposit_txs(&hash_map, &pub_key_bytes, &txs, btc_network).unwrap();
        let result = extract_p2sh_utxos_from_txs(&filtered_txs, &hash_map, btc_network).unwrap();
        let result_1 = result.0[0].clone();
        let result_2 = result.0[1].clone();
        assert_eq!(result.len(), expected_num_results);
        assert_eq!(result_1.value, expected_value_1);
        assert_eq!(result_2.value, expected_value_2);
        assert_eq!(result_1.maybe_deposit_info_json, expected_deposit_info_1);
        assert_eq!(result_2.maybe_deposit_info_json, expected_deposit_info_2);
    }
}
