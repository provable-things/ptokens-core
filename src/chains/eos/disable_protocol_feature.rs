use crate::{
    traits::DatabaseInterface,
    types::{
        Byte,
        Result,
    },
    chains::eos::{
        eos_database_utils::put_eos_enabled_protocol_features_in_db,
        protocol_features::{
            EnabledFeatures,
            AVAILABLE_FEATURES,
        },
    },
};

pub fn disable_protocol_feature<D>(
    db: &D,
    feature_hash: &[Byte],
    enabled_features: &EnabledFeatures,
) -> Result<()>
    where D: DatabaseInterface
{
    AVAILABLE_FEATURES
        .check_contains(feature_hash)
        .and_then(|_| {
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
