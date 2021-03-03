use crate::{
    chains::eos::{
        core_initialization::check_eos_core_is_initialized::check_eos_core_is_initialized,
        eos_database_transactions::{
            end_eos_db_transaction_and_return_state,
            start_eos_db_transaction_and_return_state,
        },
        eos_database_utils::put_eos_enabled_protocol_features_in_db,
        eos_state::EosState,
        get_enabled_protocol_features::get_enabled_protocol_features_and_add_to_state,
        protocol_features::{EnabledFeatures, AVAILABLE_FEATURES},
    },
    traits::DatabaseInterface,
    types::{Byte, Result},
};

pub fn disable_protocol_feature<D: DatabaseInterface>(
    db: &D,
    feature_hash: &[Byte],
    enabled_features: &EnabledFeatures,
) -> Result<()> {
    AVAILABLE_FEATURES.check_contains(feature_hash).and_then(|_| {
        if enabled_features.is_not_enabled(feature_hash) {
            return Err("✘ Feature not enabled, doing nothing!".into());
        }
        info!("✔ Disabling feature: {}", hex::encode(feature_hash));
        enabled_features
            .clone()
            .remove(feature_hash)
            .and_then(|new_features| put_eos_enabled_protocol_features_in_db(db, &new_features))
    })
}

fn disable_feature_and_return_state<D: DatabaseInterface>(state: EosState<D>, hash: &[Byte]) -> Result<EosState<D>> {
    disable_protocol_feature(&state.db, hash, &state.enabled_protocol_features).and(Ok(state))
}

pub fn disable_eos_protocol_feature<D: DatabaseInterface>(db: D, feature_hash: &str) -> Result<String> {
    info!("✔ Maybe disabling EOS protocol feature w/ hash: {}", feature_hash);
    let hash = hex::decode(feature_hash)?;
    check_eos_core_is_initialized(&db)
        .and_then(|_| start_eos_db_transaction_and_return_state(EosState::init(db)))
        .and_then(get_enabled_protocol_features_and_add_to_state)
        .and_then(|state| disable_feature_and_return_state(state, &hash))
        .and_then(end_eos_db_transaction_and_return_state)
        .map(|_| "{feature_disabled_success:true}".to_string())
}
