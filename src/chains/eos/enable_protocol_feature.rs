use crate::{
    traits::DatabaseInterface,
    types::{Byte, Result},
    chains::eos::{
        protocol_features::{EnabledFeatures, AVAILABLE_FEATURES},
        eos_database_utils::put_eos_enabled_protocol_features_in_db,
    },
};

pub fn enable_protocol_feature<D>(
    db: &D,
    feature_hash: &[Byte],
    enabled_features: &EnabledFeatures,
) -> Result<()>
    where D: DatabaseInterface
{
    AVAILABLE_FEATURES
        .check_contains(feature_hash)
        .and_then(|_| {
            if enabled_features.is_enabled(feature_hash) {
                return Err("✘ Feature already enabled, doing nothing!".into())
            }
            info!("✔ Enabling new feature: {}", hex::encode(feature_hash));
            enabled_features
                .clone()
                .add(feature_hash)
                .and_then(|new_features|
                    put_eos_enabled_protocol_features_in_db(db, &new_features)
                )
        })
}
