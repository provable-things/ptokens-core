use crate::{
    types::Result,
    eth::eth_state::EthState,
    traits::DatabaseInterface,
    utxo_manager::utxo_database_utils::save_utxos_to_db,
};

pub fn maybe_save_btc_utxos_to_db<D>(state: EthState<D>) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe saving BTC UTXOs...");
    match &state.btc_utxos_and_values {
        None => {
            info!("✔ No BTC UTXOs in state to save!");
            Ok(state)
        }
        Some(utxos) => {
            save_utxos_to_db(&state.db, &utxos)
                .and_then(|_| Ok(state))
        }
    }
}
