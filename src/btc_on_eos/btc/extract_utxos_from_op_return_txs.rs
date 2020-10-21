use bitcoin::blockdata::script::Script as BtcScript;
use crate::{
    chains::btc::utxo_manager::utxo_types::{
        BtcUtxoAndValue,
        BtcUtxosAndValues,
    },
    btc_on_eos::btc::{
        btc_utils::create_unsigned_utxo_from_tx,
        btc_types::BtcTransaction,
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
