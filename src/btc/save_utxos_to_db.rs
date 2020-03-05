use crate::{
    types::Result,
    btc::btc_state::BtcState,
    traits::DatabaseInterface,
    utxo_manager::utxo_database_utils::save_utxos_to_db,
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
            save_utxos_to_db(&state.db, &state.utxos_and_values)
                .and_then(|_| Ok(state))
        }
    }
}
