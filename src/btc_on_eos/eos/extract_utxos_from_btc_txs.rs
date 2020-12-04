use crate::{
    chains::eos::{eos_state::EosState, extract_utxos_from_btc_txs::extract_btc_utxo_from_btc_tx},
    traits::DatabaseInterface,
    types::Result,
};

pub fn maybe_extract_btc_utxo_from_btc_tx_in_state<D>(state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Maybe extracting UTXOs from BTC txs in state...");
    match state.btc_on_eos_signed_txs.len() {
        0 => {
            info!("✔ No BTC txs in state ∴ no UTXOs to extract...");
            Ok(state)
        },
        _ => {
            info!("✔ Extracting BTC UTXOs...");
            extract_btc_utxo_from_btc_tx(&state.db, &state.btc_on_eos_signed_txs)
                .and_then(|utxos| state.add_btc_utxos_and_values(utxos))
        },
    }
}
