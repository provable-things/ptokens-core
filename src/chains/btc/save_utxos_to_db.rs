use crate::{
    chains::btc::{btc_state::BtcState, utxo_manager::utxo_database_utils::save_utxos_to_db},
    traits::DatabaseInterface,
    types::Result,
};

pub fn maybe_save_utxos_to_db<D: DatabaseInterface>(state: BtcState<D>) -> Result<BtcState<D>> {
    info!("✔ Maybe saving UTXOs...");
    match &state.utxos_and_values.len() {
        0 => {
            info!("✔ No UTXOs in state to save!");
            Ok(state)
        },
        _ => save_utxos_to_db(&state.db, &state.utxos_and_values).and(Ok(state)),
    }
}
