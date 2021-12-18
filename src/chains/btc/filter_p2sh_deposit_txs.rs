use bitcoin::{
    blockdata::transaction::TxOut as BtcTxOut,
    network::constants::Network as BtcNetwork,
    util::address::Address as BtcAddress,
};

use crate::{
    chains::btc::{
        btc_database_utils::{get_btc_network_from_db, get_btc_public_key_slice_from_db},
        btc_state::BtcState,
        btc_types::{BtcPubKeySlice, BtcTransaction, BtcTransactions},
        btc_utils::get_p2sh_redeem_script_sig,
        deposit_address_info::DepositInfoHashMap,
    },
    traits::DatabaseInterface,
    types::Result,
};

fn is_address_locked_to_pub_key(
    btc_network: BtcNetwork,
    enclave_public_key_slice: &BtcPubKeySlice,
    address_from_utxo: &BtcAddress,
    deposit_info: &DepositInfoHashMap,
) -> bool {
    trace!("✔ Checking if address is locked to enclave's public key...");
    match deposit_info.get(address_from_utxo) {
        None => {
            trace!("✘ Address {} is NOT in hash map!", address_from_utxo);
            false
        },
        Some(deposit_info) => {
            let address_from_script = BtcAddress::p2sh(
                &get_p2sh_redeem_script_sig(enclave_public_key_slice, &deposit_info.commitment_hash),
                btc_network,
            );
            debug!("Deposit info: {:?}", deposit_info);
            debug!("Address from UTXO  : {}", address_from_utxo);
            debug!("Address from script: {}", address_from_script);
            match &address_from_script == address_from_utxo {
                true => {
                    info!("✔ UTXO IS locked to the enclave!");
                    true
                },
                false => {
                    trace!("✘ UTXO is NOT locked to the enclave!");
                    false
                },
            }
        },
    }
}

fn is_output_address_locked_to_pub_key(
    tx_output: &BtcTxOut,
    btc_network: BtcNetwork,
    enclave_public_key_slice: &BtcPubKeySlice,
    deposit_info: &DepositInfoHashMap,
) -> bool {
    match BtcAddress::from_script(&tx_output.script_pubkey, btc_network) {
        None => false,
        Some(address_from_utxo) => {
            is_address_locked_to_pub_key(btc_network, enclave_public_key_slice, &address_from_utxo, deposit_info)
        },
    }
}

fn is_output_address_in_hash_map(
    tx_output: &BtcTxOut,
    deposit_info: &DepositInfoHashMap,
    btc_network: BtcNetwork,
) -> bool {
    info!("✔ Checking if output address is in hash map...");
    match BtcAddress::from_script(&tx_output.script_pubkey, btc_network) {
        None => false,
        Some(address) => match deposit_info.contains_key(&address) {
            true => {
                info!("✔ Output address {} IS in hash map!", address);
                true
            },
            false => {
                trace!("✘ Output address {} is NOT in hash map!", address);
                false
            },
        },
    }
}

pub fn filter_p2sh_deposit_txs(
    deposit_info: &DepositInfoHashMap,
    enclave_public_key_slice: &BtcPubKeySlice,
    transactions: &[BtcTransaction],
    btc_network: BtcNetwork,
) -> Result<BtcTransactions> {
    Ok(transactions
        .iter()
        .filter(|txdata| {
            txdata
                .output
                .iter()
                .filter(|tx_out| tx_out.script_pubkey.is_p2sh())
                .filter(|tx_out| is_output_address_in_hash_map(tx_out, deposit_info, btc_network))
                .any(|tx_out| {
                    is_output_address_locked_to_pub_key(tx_out, btc_network, enclave_public_key_slice, deposit_info)
                })
        })
        .cloned()
        .collect::<BtcTransactions>())
}

pub fn filter_p2sh_deposit_txs_and_add_to_state<D>(state: BtcState<D>) -> Result<BtcState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Filtering out `p2sh` deposits & adding to state...");
    filter_p2sh_deposit_txs(
        state.get_deposit_info_hash_map()?,
        &get_btc_public_key_slice_from_db(&state.db)?,
        &state.get_btc_block_and_id()?.block.txdata,
        get_btc_network_from_db(&state.db)?,
    )
    .and_then(|txs| {
        info!("✔ Found {} txs containing `p2sh` deposits", txs.len());
        state.add_p2sh_deposit_txs(txs)
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{
        blockdata::transaction::{Transaction as BtcTransaction, TxOut as BtcTxOut},
        util::address::Address as BtcAddress,
    };

    use super::*;
    use crate::chains::btc::{
        btc_block::BtcBlockAndId,
        btc_test_utils::{get_sample_btc_block_n, get_sample_btc_pub_key_slice, SAMPLE_TARGET_BTC_ADDRESS},
        get_deposit_info_hash_map::create_hash_map_from_deposit_info_list,
    };

    fn get_sample_btc_deposit_address() -> BtcAddress {
        BtcAddress::from_str("2N2LHYbt8K1KDBogd6XUG9VBv5YM6xefdM2").unwrap()
    }

    fn get_wrong_sample_btc_deposit_address() -> BtcAddress {
        BtcAddress::from_str(SAMPLE_TARGET_BTC_ADDRESS).unwrap()
    }

    fn get_sample_btc_block_with_p2sh_deposit() -> BtcBlockAndId {
        get_sample_btc_block_n(5).unwrap()
    }

    fn get_sample_tx_with_p2sh_deposit() -> BtcTransaction {
        get_sample_btc_block_with_p2sh_deposit().block.txdata[1].clone()
    }

    fn get_sample_tx_output_with_p2sh_deposit() -> BtcTxOut {
        get_sample_tx_with_p2sh_deposit().output[0].clone()
    }

    fn get_wrong_sample_tx_output() -> BtcTxOut {
        get_sample_tx_with_p2sh_deposit().output[1].clone()
    }

    #[test]
    fn address_should_be_locked_to_pub_key() {
        let enclave_public_key_slice = get_sample_btc_pub_key_slice();
        let btc_network = BtcNetwork::Testnet;
        let deposit_address_list = get_sample_btc_block_with_p2sh_deposit().deposit_address_list;
        let deposit_info = create_hash_map_from_deposit_info_list(&deposit_address_list).unwrap();
        let address_from_utxo = get_sample_btc_deposit_address();
        let result = is_address_locked_to_pub_key(
            btc_network,
            &enclave_public_key_slice,
            &address_from_utxo,
            &deposit_info,
        );
        assert!(result);
    }

    #[test]
    fn wrong_address_should_not_be_locked_to_pub_key() {
        let enclave_public_key_slice = get_sample_btc_pub_key_slice();
        let btc_network = BtcNetwork::Testnet;
        let deposit_address_list = get_sample_btc_block_with_p2sh_deposit().deposit_address_list;
        let deposit_info = create_hash_map_from_deposit_info_list(&deposit_address_list).unwrap();
        let address_not_from_utxo = get_wrong_sample_btc_deposit_address();
        let result = is_address_locked_to_pub_key(
            btc_network,
            &enclave_public_key_slice,
            &address_not_from_utxo,
            &deposit_info,
        );
        assert!(!result);
    }

    #[test]
    fn address_from_output_should_be_locked_to_pub_key() {
        let enclave_public_key_slice = get_sample_btc_pub_key_slice();
        let btc_network = BtcNetwork::Testnet;
        let deposit_address_list = get_sample_btc_block_with_p2sh_deposit().deposit_address_list;
        let deposit_info = create_hash_map_from_deposit_info_list(&deposit_address_list).unwrap();
        let tx_output = get_sample_tx_output_with_p2sh_deposit();
        let result =
            is_output_address_locked_to_pub_key(&tx_output, btc_network, &enclave_public_key_slice, &deposit_info);
        assert!(result);
    }

    #[test]
    fn address_from_wrong_output_should_not_be_locked_to_pub_key() {
        let enclave_public_key_slice = get_sample_btc_pub_key_slice();
        let btc_network = BtcNetwork::Testnet;
        let deposit_address_list = get_sample_btc_block_with_p2sh_deposit().deposit_address_list;
        let deposit_info = create_hash_map_from_deposit_info_list(&deposit_address_list).unwrap();
        let tx_output = get_wrong_sample_tx_output();
        let result =
            is_output_address_locked_to_pub_key(&tx_output, btc_network, &enclave_public_key_slice, &deposit_info);
        assert!(!result);
    }

    #[test]
    fn outputs_address_should_be_in_hash_map() {
        let btc_network = BtcNetwork::Testnet;
        let deposit_address_list = get_sample_btc_block_with_p2sh_deposit().deposit_address_list;
        let deposit_info = create_hash_map_from_deposit_info_list(&deposit_address_list).unwrap();
        let tx_output = get_sample_tx_output_with_p2sh_deposit();
        let result = is_output_address_in_hash_map(&tx_output, &deposit_info, btc_network);
        assert!(result);
    }

    #[test]
    fn wrong_outputs_address_should_not_be_in_hash_map() {
        let btc_network = BtcNetwork::Testnet;
        let deposit_address_list = get_sample_btc_block_with_p2sh_deposit().deposit_address_list;
        let deposit_info = create_hash_map_from_deposit_info_list(&deposit_address_list).unwrap();
        let tx_output = get_wrong_sample_tx_output();
        let result = is_output_address_in_hash_map(&tx_output, &deposit_info, btc_network);
        assert!(!result);
    }

    #[test]
    fn should_filter_txs_for_outputs_to_addresses_in_hash_map() {
        let pub_key_slice = get_sample_btc_pub_key_slice();
        let expected_num_txs = 1;
        let expected_tx_hash = "4d19fed40e7d1944c8590a8a2e21d1f16f65c060244277a3d207770d1c848352";
        let btc_network = BtcNetwork::Testnet;
        let block_and_id = get_sample_btc_block_with_p2sh_deposit();
        let deposit_address_list = block_and_id.deposit_address_list.clone();
        let txs = block_and_id.block.txdata;
        let num_txs_before = txs.len();
        let hash_map = create_hash_map_from_deposit_info_list(&deposit_address_list).unwrap();
        let result = filter_p2sh_deposit_txs(&hash_map, &pub_key_slice, &txs, btc_network).unwrap();
        let num_txs_after = result.len();
        assert!(num_txs_before != num_txs_after);
        assert_eq!(num_txs_after, expected_num_txs);
        let tx_hash = result[0].txid();
        assert_eq!(tx_hash.to_string(), expected_tx_hash);
    }
}
