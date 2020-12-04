use crate::{
    chains::{btc::utxo_manager::utxo_database_utils::save_utxos_to_db, eos::eos_state::EosState},
    traits::DatabaseInterface,
    types::Result,
};

pub fn maybe_save_btc_utxos_to_db<D>(state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Maybe saving BTC UTXOs...");
    match &state.btc_utxos_and_values {
        None => {
            info!("✔ No BTC UTXOs in state to save!");
            Ok(state)
        },
        Some(utxos) => save_utxos_to_db(&state.db, &utxos).map(|_| state),
    }
}
