use crate::{
    traits::DatabaseInterface,
    chains::eos::eos_database_utils::put_eos_enabled_protocol_features_in_db,
    types::{
        Byte,
        Bytes,
        NoneError,
        Result,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolFeature {
    feature_name: String,
    feature_hash: String,
}

impl ProtocolFeature {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(&self)?)
    }

    pub fn new(name: &str, feature_hash: String) -> Self {
        ProtocolFeature {
            feature_name: name.to_string(),
            feature_hash,
        }
    }

    pub fn default() -> Self {
        ProtocolFeature {
            feature_hash: "1337".to_string(),
            feature_name: "Default".to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnabledFeatures(Vec<ProtocolFeature>);

impl EnabledFeatures {
    pub fn init() -> Self {
        EnabledFeatures(vec![])
    }

    pub fn remove(mut self, feature_hash: &[Byte]) -> Result<Self>{
        if self.does_not_contain(feature_hash) {
            return Ok(self)
        };
        AVAILABLE_FEATURES
            .get_feature_from_hash(feature_hash)
            .and_then(|feature| {
                self.0.remove(self.0.iter().position(|x| x == &feature)
                    .ok_or(NoneError("Could not unwrap EOS protocol feature while removing!"))?
                );
                Ok(self)
            })
    }

    pub fn add(mut self, feature_hash: &[Byte]) -> Result<Self> {
        AVAILABLE_FEATURES
            .check_contains(feature_hash)
            .and_then(|_| AVAILABLE_FEATURES.get_feature_from_hash(feature_hash))
            .and_then(|feature| {
                info!("✔ Adding feature: {}", feature.to_json()?);
                self.0.push(feature);
                Ok(self)
            })
    }

    pub fn add_multi(mut self, feature_hashes: &mut Vec<Bytes>) -> Result<Self> {
        info!("✔ Adding multiple features...");
        feature_hashes.sort();
        feature_hashes.dedup();
        feature_hashes
            .iter()
            .map(|hash| AVAILABLE_FEATURES.maybe_get_feature_from_hash(&hash))
            .filter(|maybe_feature| maybe_feature.is_some())
            .map(|feature| -> Result<()> {
                info!("✔ Adding feature: {}", feature.clone()
                    .ok_or(NoneError("Could not unwrap EOS protocol feature while adding!"))?
                    .to_json()?
                );
                self.0.push(feature.ok_or(NoneError("Could not unwrap EOS protocol feature while adding!"))?);
                Ok(())
            })
            .for_each(drop);
        Ok(self)
    }

    pub fn contains(&self, feature_hash: &[Byte]) -> bool {
        let hash = hex::encode(feature_hash);
        self
            .0
            .iter()
            .any(|e| e.feature_hash == hash)
    }

    pub fn does_not_contain(&self, feature_hash: &[Byte]) -> bool {
        !self.contains(feature_hash)
    }

    pub fn is_enabled(&self, feature_hash: &[Byte]) -> bool {
        AVAILABLE_FEATURES.contains(feature_hash) && self.contains(feature_hash)
    }

    pub fn is_not_enabled(&self, feature_hash: &[Byte]) -> bool {
        !self.is_enabled(feature_hash)
    }

    pub fn enable_multi<D>(
        self,
        db: &D,
        feature_hashes: &mut Vec<Bytes>
    ) -> Result<Self>
        where D: DatabaseInterface
    {
        self.add_multi(feature_hashes)
            .and_then(|updated_self| {
                put_eos_enabled_protocol_features_in_db(db, &updated_self)?;
                Ok(updated_self)
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailableFeatures(Vec<ProtocolFeature>);

impl AvailableFeatures {
    pub fn new(available_features: Vec<ProtocolFeature>) -> Self {
        AvailableFeatures(available_features)
    }

    pub fn contains(&self, feature_hash: &[Byte]) -> bool {
        let hash = hex::encode(feature_hash);
        self
            .0
            .iter()
            .any(|e| e.feature_hash == hash)
    }

    pub fn check_contains(&self, feature_hash: &[Byte]) -> Result<()> {
        info!(
            "✔ Checking available features for feature hash {}",
            hex::encode(feature_hash)
        );
        match AVAILABLE_FEATURES.contains(feature_hash) {
            true => {
                info!("✔ Feature hash exists in available features!");
                Ok(())
            }
            false => Err(format!(
                "✘ Unrecognised feature hash: {}",
                hex::encode(feature_hash),
            ).into())
        }
    }


    fn get_known_feature_from_hash(
        &self,
        feature_hash: &[Byte],
    ) -> ProtocolFeature {
        self
            .0
            .iter()
            .fold(
                ProtocolFeature::default(),
                |mut acc, protocol_feature| {
                    if protocol_feature.feature_hash == hex::encode(feature_hash) {
                        acc = protocol_feature.clone();
                    };
                    acc
                }
            )
    }

    pub fn maybe_get_feature_from_hash(
        &self,
        feature_hash: &[Byte],
    ) -> Option<ProtocolFeature> {
        match self.contains(feature_hash) {
            true => Some(self.get_known_feature_from_hash(feature_hash)),
            false => {
                info!("✘ Unrecognised feature hash: {}", hex::encode(feature_hash));
                None
            }
        }
    }

    pub fn get_feature_from_hash(
        &self,
        feature_hash: &[Byte],
    ) -> Result<ProtocolFeature> {
        self.check_contains(feature_hash)
            .map(|_| self.get_known_feature_from_hash(feature_hash))
    }
}

lazy_static! {
    pub static ref AVAILABLE_FEATURES: AvailableFeatures = {
        AvailableFeatures::new(
            vec![
                ProtocolFeature::new(
                    "WTMSIG_BLOCK_SIGNATURE",
                    hex::encode(WTMSIG_BLOCK_SIGNATURE_FEATURE_HASH),
                ),
            ]
        )
    };
}

// NOTE: 299dcb6af692324b899b39f16d5a530a33062804e41f09dc97e9f156b4476707
pub static WTMSIG_BLOCK_SIGNATURE_FEATURE_HASH: [u8; 32] = [
    41, 157, 203, 106, 246, 146, 50, 75,
    137, 155, 57, 241, 109, 90, 83, 10,
    51, 6, 40, 4, 228, 31, 9, 220,
    151, 233, 241, 86, 180, 71, 103, 7
];
