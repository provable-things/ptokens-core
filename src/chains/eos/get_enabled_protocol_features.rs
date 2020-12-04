use crate::{
    chains::eos::{eos_database_utils::get_eos_enabled_protocol_features_from_db, eos_state::EosState},
    traits::DatabaseInterface,
    types::Result,
};

pub fn get_enabled_protocol_features_and_add_to_state<D>(state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Getting enabled EOS protocol features and adding to state...");
    get_eos_enabled_protocol_features_from_db(&state.db)
        .and_then(|schedule| state.add_enabled_protocol_features(schedule))
}
