use bitcoin::{
    consensus::encode::serialize as btc_serialize,
    blockdata::{
        script::Script as BtcScript,
        transaction::{
            TxIn as BtcTxIn,
            TxOut as BtcTxOut,
            Transaction as BtcTransaction,
        },
    },
};
use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc::{
        btc_state::BtcState,
        btc_types::BtcTransactions,
        btc_utils::get_pay_to_pub_key_hash_script,
        btc_crypto::btc_private_key::BtcPrivateKey,
        btc_database_utils::get_btc_private_key_from_db,
    },
};

fn sig_script_contains_pub_key(
    script_sig: &BtcScript,
    btc_pub_key_slice: &[u8],
) -> bool {
    hex::encode(btc_serialize(script_sig))
        .contains(&hex::encode(btc_pub_key_slice))
}

fn tx_has_input_locked_to_pub_key(
    tx: &BtcTransaction,
    btc_pub_key_slice: &[u8],
) -> bool {
    tx
        .input // NOTE: Why they didn't pluralise this I'll never know.
        .iter()
        .filter(|input|
            sig_script_contains_pub_key(&input.script_sig, &btc_pub_key_slice)
        )
        .cloned()
        .collect::<Vec<BtcTxIn>>()
        .len() > 0
}

fn tx_has_output_with_target_script(
    tx: &BtcTransaction,
    target_script: &BtcScript,
) -> bool {
    tx
        .output // NOTE: Ibid.
        .iter()
        .filter(|output| &output.script_pubkey == target_script)
        .collect::<Vec<&BtcTxOut>>()
        .len() > 0
}

pub fn filter_txs_for_op_return_deposits(
    btc_private_key: &BtcPrivateKey,
    transactions: &BtcTransactions,
) -> Result<BtcTransactions> {
    info!(
        "✔ Filtering `p2pkh` deposits that are NOT {}",
        "enclave's own change outputs..."
    );
    let btc_address = btc_private_key.to_p2pkh_btc_address();
    let pub_key_slice = btc_private_key.to_public_key_slice();
    let target_script = get_pay_to_pub_key_hash_script(&btc_address)?;
    Ok(
        transactions
            .iter()
            .filter(|tx| !tx_has_input_locked_to_pub_key(tx, &pub_key_slice))
            .filter(|tx| tx_has_output_with_target_script(tx, &target_script))
            .cloned()
            .collect::<BtcTransactions>()
    )
}

pub fn filter_op_return_deposit_txs_and_add_to_state<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Filtering `p2pkh || OP_RETURN` deposits & adding to state...");
    filter_txs_for_op_return_deposits(
        &get_btc_private_key_from_db(&state.db)?,
        &state.get_btc_block_and_id()?.block.txdata,
    )
        .and_then(|txs| {
            info!("✔ Found {} `p2pkh || OP_RETURN` deposits", txs.len());
            state.add_op_return_deposit_txs(txs)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use bitcoin::hashes::{
        Hash,
        sha256d,
    };
    use crate::btc::{
        btc_types::BtcBlockAndId,
        btc_utils::get_script_sig,
        btc_test_utils::{
            get_sample_btc_block_n,
            SAMPLE_TARGET_BTC_ADDRESS,
            get_sample_btc_private_key,
            get_sample_testnet_block_and_txs,
        },
    };

    fn get_block_with_external_p2pkh_deposit_tx() -> BtcBlockAndId {
        get_sample_testnet_block_and_txs().unwrap()
    }

    fn get_block_with_internal_p2pkh_deposit() -> BtcBlockAndId {
        get_sample_btc_block_n(7).unwrap()
    }

    fn get_tx_with_internal_p2pkh_deposit() -> BtcTransaction {
        get_block_with_internal_p2pkh_deposit()
            .block
            .txdata[12]
            .clone()
    }

    fn get_tx_with_external_p2pkh_deposit() -> BtcTransaction {
        get_block_with_external_p2pkh_deposit_tx()
            .block
            .txdata[1]
            .clone()
    }

    #[test]
    fn script_sig_should_contain_pub_key() {
        let hash_type = 1;
        let hash = sha256d::Hash::hash(b"a message");
        let btc_pk = get_sample_btc_private_key();
        let signature = btc_pk
            .sign_hash_and_append_btc_hash_type(hash.to_vec(), hash_type)
            .unwrap();
        let btc_pub_key_slice = btc_pk.to_public_key_slice();
        let sig_script = get_script_sig(&signature, &btc_pub_key_slice);
        let result = sig_script_contains_pub_key(
            &sig_script,
            &btc_pub_key_slice
        );
        assert!(result);
    }

    #[test]
    fn should_not_filter_out_external_p2pkh_deposits() {
        let expected_prev_id = sha256d::Hash::from_str(
            "65c5ea468d8a51e6f9120076ff0f5717b8fd1547e6311d5f89f85b21291da96f"
        ).unwrap();
        let expected_num_txs = 1;
        let block_and_id = get_block_with_external_p2pkh_deposit_tx();
        let filtered_txs = filter_txs_for_op_return_deposits(
            &get_sample_btc_private_key(),
            &block_and_id.block.txdata,
        ).unwrap();
        let prev_id = filtered_txs[0].input[0].previous_output.txid;
        assert!(prev_id == expected_prev_id);
        assert!(filtered_txs.len() == expected_num_txs);
    }

    #[test]
    fn should_filter_out_internal_p2pkh_deposits() {
        let expected_num_txs = 0;
        let block_and_id = get_block_with_internal_p2pkh_deposit();
        let filtered_txs = filter_txs_for_op_return_deposits(
            &get_sample_btc_private_key(),
            &block_and_id.block.txdata,
        ).unwrap();
        assert!(filtered_txs.len() == expected_num_txs);
    }

    #[test]
    fn external_p2pkh_tx_should_have_output_with_target_script() {
        let tx =  get_tx_with_external_p2pkh_deposit();
        let target_script = get_pay_to_pub_key_hash_script(
            &SAMPLE_TARGET_BTC_ADDRESS
        ).unwrap();
        let result = tx_has_output_with_target_script(&tx, &target_script);
        assert!(result);
    }

    #[test]
    fn internal_p2pkh_tx_should_have_output_with_target_script() {
        let tx =  get_tx_with_internal_p2pkh_deposit();
        let target_script = get_pay_to_pub_key_hash_script(
            &SAMPLE_TARGET_BTC_ADDRESS
        ).unwrap();
        let result = tx_has_output_with_target_script(&tx, &target_script);
        assert!(result);
    }

    #[test]
    fn external_p2pkh_tx_should_not_have_input_locked_to_pub_key() {
        let tx = get_tx_with_external_p2pkh_deposit();
        let pub_key_slice = get_sample_btc_private_key()
            .to_public_key_slice();
        let result = tx_has_input_locked_to_pub_key(&tx, &pub_key_slice);
        assert!(!result);
    }

    #[test]
    fn internal_p2pkh_tx_should_have_input_locked_to_pub_key() {
        let tx = get_tx_with_internal_p2pkh_deposit();
        let pub_key_slice = get_sample_btc_private_key()
            .to_public_key_slice();
        let result = tx_has_input_locked_to_pub_key(&tx, &pub_key_slice);
        assert!(result);
    }
}
