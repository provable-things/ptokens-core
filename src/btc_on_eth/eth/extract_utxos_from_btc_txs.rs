use crate::{
    chains::{
        btc::{
            btc_database_utils::get_btc_address_from_db,
            btc_utils::get_pay_to_pub_key_hash_script,
            extract_utxos_from_p2pkh_txs::extract_utxos_from_txs,
        },
        eth::eth_state::EthState,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn maybe_extract_btc_utxo_from_btc_tx_in_state<D>(state: EthState<D>) -> Result<EthState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Maybe extracting UTXOs from BTC txs in state...");
    match &state.btc_transactions {
        None => {
            info!("✔ No BTC txs in state ∴ no UTXOs to extract...");
            Ok(state)
        },
        Some(btc_txs) => {
            info!("✔ Extracting BTC UTXOs...");
            get_btc_address_from_db(&state.db)
                .and_then(|address| get_pay_to_pub_key_hash_script(&address))
                .map(|target_script| extract_utxos_from_txs(&target_script, &btc_txs))
                .and_then(|utxos| state.add_btc_utxos_and_values(utxos))
        },
    }
}
