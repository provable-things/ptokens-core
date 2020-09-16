use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::eos::{
        eos_state::EosState,
        eos_database_utils::get_eos_enabled_protocol_features_from_db,
    },
};

pub fn get_enabled_protocol_features_and_add_to_state<D>(
    state: EosState<D>,
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    info!("✔ Getting enabled EOS protocol features and adding to state...");
    get_eos_enabled_protocol_features_from_db(&state.db)
        .and_then(|schedule| state.add_enabled_protocol_features(schedule))
}
