use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::{
        eos::eos_state::EosState,
        btc::{
            btc_utils::get_pay_to_pub_key_hash_script,
            btc_database_utils::get_btc_address_from_db,
            extract_utxos_from_op_return_txs::extract_utxos_from_txs,
        },
    },
};

pub fn maybe_extract_btc_utxo_from_btc_tx_in_state<D>(
    state: EosState<D>
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe extracting UTXOs from BTC txs in state...");
    match &state.signed_txs.len() {
        0 => {
            info!("✔ No BTC txs in state ∴ no UTXOs to extract...");
            Ok(state)
        }
        _ => {
            info!("✔ Extracting BTC UTXOs...");
            get_btc_address_from_db(&state.db)
                .and_then(|address| get_pay_to_pub_key_hash_script(&address))
                .map(|target_script| extract_utxos_from_txs(&target_script, &state.signed_txs))
                .and_then(|utxos| state.add_btc_utxos_and_values(utxos))
        }
    }
}
