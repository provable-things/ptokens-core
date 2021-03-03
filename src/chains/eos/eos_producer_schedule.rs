use core::default::Default;

use eos_primitives::{Checksum256, NumBytes, Read, Write};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

use crate::chains::eos::eos_producer_key::{EosProducerKeyV1, EosProducerKeyV2};

#[derive(Read, Write, NumBytes, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[eosio_core_root_path = "eos_primitives"]
#[repr(C)]
pub struct EosProducerScheduleV2 {
    pub version: u32,
    pub producers: Vec<EosProducerKeyV2>,
}

impl EosProducerScheduleV2 {
    pub fn schedule_hash(&self) -> crate::Result<Checksum256> {
        Ok(Checksum256::hash(self.clone())?)
    }
}

impl Default for EosProducerScheduleV2 {
    fn default() -> Self {
        Self {
            version: 0,
            producers: vec![],
        }
    }
}

#[derive(Deserialize, Serialize, Read, Write, NumBytes, Clone, Default, Debug, PartialEq)]
#[eosio_core_root_path = "eos_primitives"]
pub struct EosProducerScheduleV1 {
    pub version: u32,
    pub producers: Vec<EosProducerKeyV1>,
}
impl EosProducerScheduleV1 {
    pub fn new(version: u32, producers: Vec<EosProducerKeyV1>) -> Self {
        Self { version, producers }
    }

    pub fn schedule_hash(&self) -> crate::Result<Checksum256> {
        Ok(Checksum256::hash(self.clone())?)
    }
}
