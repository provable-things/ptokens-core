use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::btc::btc_state::BtcState,
    chains::btc::utxo_manager::utxo_database_utils::save_utxos_to_db,
};

pub fn maybe_save_utxos_to_db<D>(state: BtcState<D>) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe saving UTXOs...");
    match &state.utxos_and_values.len() {
        0 => {
            info!("✔ No UTXOs in state to save!");
            Ok(state)
        }
        _ => {
            save_utxos_to_db(&state.db, &state.utxos_and_values).map(|_| state)
        }
    }
}
