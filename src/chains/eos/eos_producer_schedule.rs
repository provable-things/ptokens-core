use core::default::Default;
use std::str::FromStr;

use eos_chain::{AccountName as EosAccountName, Checksum256, NumBytes, PublicKey as EosPublicKey, Read, Write};
use serde::{Deserialize, Serialize};

use crate::{
    chains::eos::eos_producer_key::{EosKey, EosKeysAndThreshold, EosProducerKeyV1, EosProducerKeyV2},
    errors::AppError,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EosProducerScheduleJsonV1 {
    pub version: u32,
    pub producers: Vec<ProducerKeyJsonV1>,
}

impl EosProducerScheduleJsonV1 {
    pub fn from(schedule_string: &str) -> crate::Result<Self> {
        serde_json::from_str(schedule_string).map_err(AppError::SerdeJsonError)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProducerKeyJsonV1 {
    pub producer_name: String,
    pub block_signing_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EosProducerScheduleJsonV2 {
    pub version: u32,
    pub producers: Vec<FullProducerKeyJsonV2>,
}

impl EosProducerScheduleJsonV2 {
    pub fn from(schedule_string: &str) -> crate::Result<Self> {
        serde_json::from_str(schedule_string).map_err(AppError::SerdeJsonError)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FullProducerKeyJsonV2 {
    pub producer_name: String,
    pub authority: (u8, AuthorityJson),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityJson {
    pub threshold: u32,
    pub keys: Vec<ProducerKeyJsonV2>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProducerKeyJsonV2 {
    weight: u16,
    key: String,
}

#[derive(Read, Write, NumBytes, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[eosio_core_root_path = "eos_chain"]
#[repr(C)]
pub struct EosProducerScheduleV2 {
    pub version: u32,
    pub producers: Vec<EosProducerKeyV2>,
}

impl EosProducerScheduleV2 {
    pub fn schedule_hash(&self) -> crate::Result<Checksum256> {
        Ok(Checksum256::hash(self.clone())?)
    }

    /// # Maybe deserialize `EosProducerScheduleV2` from JSON string
    ///
    /// This function deserializes `EosProducerScheduleV2` from JSON string.
    /// It also accepts JSON representation of `EosProducerScheduleV1`
    /// and implicitly converts it into `EosProducerScheduleV2`.
    pub fn from_json(json_string: &str) -> crate::Result<Self> {
        EosProducerScheduleJsonV2::from(json_string)
            .and_then(|json| Self::from_schedule_json(&json))
            .or_else(|_| EosProducerScheduleV1::from_json(json_string).map(EosProducerScheduleV2::from))
    }

    pub fn from_schedule_json(json: &EosProducerScheduleJsonV2) -> crate::Result<Self> {
        Ok(Self {
            version: json.version,
            producers: convert_v2_producer_key_jsons_to_v2_producer_keys(&json.producers)?,
        })
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

impl From<EosProducerScheduleV1> for EosProducerScheduleV2 {
    fn from(v1_schedule: EosProducerScheduleV1) -> Self {
        Self {
            version: v1_schedule.version,
            producers: v1_schedule
                .producers
                .iter()
                .map(|producer| EosProducerKeyV2 {
                    producer_name: producer.producer_name,
                    authority: (0, EosKeysAndThreshold {
                        threshold: 0,
                        keys: vec![EosKey {
                            weight: 0,
                            key: producer.block_signing_key.clone(),
                        }],
                    }),
                })
                .collect::<Vec<EosProducerKeyV2>>(),
        }
    }
}

#[derive(Deserialize, Serialize, Read, Write, NumBytes, Clone, Default, Debug, PartialEq)]
#[eosio_core_root_path = "eos_chain"]
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

    pub fn from_json(json_string: &str) -> crate::Result<Self> {
        EosProducerScheduleJsonV1::from(json_string).and_then(|json| Self::from_schedule_json(&json))
    }

    pub fn from_schedule_json(json: &EosProducerScheduleJsonV1) -> crate::Result<Self> {
        Ok(Self {
            version: json.version,
            producers: convert_v1_producer_key_jsons_to_v1_producer_keys(&json.producers)?,
        })
    }
}

fn convert_v2_producer_key_jsons_to_v2_producer_keys(
    json: &[FullProducerKeyJsonV2],
) -> crate::Result<Vec<EosProducerKeyV2>> {
    json.iter()
        .map(convert_full_producer_key_json_to_v2_producer_key)
        .collect()
}

fn convert_full_producer_key_json_to_v2_producer_key(json: &FullProducerKeyJsonV2) -> crate::Result<EosProducerKeyV2> {
    Ok(EosProducerKeyV2 {
        producer_name: EosAccountName::from_str(&json.producer_name)?,
        authority: (
            json.authority.0,
            convert_authority_json_to_eos_keys_and_threshold(&json.authority.1)?,
        ),
    })
}

fn convert_v1_producer_key_jsons_to_v1_producer_keys(
    json: &[ProducerKeyJsonV1],
) -> crate::Result<Vec<EosProducerKeyV1>> {
    json.iter()
        .map(convert_v1_producer_key_json_to_v1_producer_key)
        .collect()
}

fn convert_v1_producer_key_json_to_v1_producer_key(json: &ProducerKeyJsonV1) -> crate::Result<EosProducerKeyV1> {
    Ok(EosProducerKeyV1::new(
        EosAccountName::from_str(&json.producer_name)?,
        EosPublicKey::from_str(&json.block_signing_key)?,
    ))
}

fn convert_authority_json_to_eos_keys_and_threshold(json: &AuthorityJson) -> crate::Result<EosKeysAndThreshold> {
    Ok(EosKeysAndThreshold {
        threshold: json.threshold,
        keys: convert_keys_json_to_vec_of_eos_keys(&json.keys)?,
    })
}

fn convert_keys_json_to_vec_of_eos_keys(keys_json: &[ProducerKeyJsonV2]) -> crate::Result<Vec<EosKey>> {
    keys_json.iter().map(convert_key_json_to_eos_key).collect()
}

fn convert_key_json_to_eos_key(key_json: &ProducerKeyJsonV2) -> crate::Result<EosKey> {
    Ok(EosKey {
        weight: key_json.weight,
        key: EosPublicKey::from_str(&key_json.key)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::eos::eos_test_utils::{
        get_sample_v1_schedule,
        get_sample_v1_schedule_json,
        get_sample_v1_schedule_json_string,
        get_sample_v2_schedule_json,
        get_sample_v2_schedule_json_string,
    };

    #[test]
    fn should_parse_v2_schedule_string_to_v2_schedule() {
        let schedule_string = get_sample_v2_schedule_json_string().unwrap();
        if let Err(e) = EosProducerScheduleV2::from_json(&schedule_string) {
            panic!("Error parseing schedule: {}", e);
        }
    }

    #[test]
    fn should_parse_v1_schedule_string_to_v2_schedule() {
        let schedule_string = get_sample_v1_schedule_json_string().unwrap();
        if let Err(e) = EosProducerScheduleV2::from_json(&schedule_string) {
            panic!("Error parseing schedule: {}", e);
        }
    }

    #[test]
    fn should_convert_v2_schedule_json_to_v2_schedule() {
        let schedule_json = get_sample_v2_schedule_json().unwrap();
        if let Err(e) = EosProducerScheduleV2::from_schedule_json(&schedule_json) {
            panic!("Error converting producer key json: {}", e);
        }
    }

    #[test]
    fn should_convert_v1_schedule_to_v2() {
        let v1_schedule = get_sample_v1_schedule().unwrap();
        EosProducerScheduleV2::from(v1_schedule);
    }

    #[test]
    fn should_parse_v1_schedule_string_to_json() {
        let schedule_string = get_sample_v1_schedule_json_string().unwrap();
        if let Err(e) = EosProducerScheduleJsonV1::from(&schedule_string) {
            panic!("Could not parse EOS schedule json V1: {}", e);
        }
    }

    #[test]
    fn should_convert_v1_schedule_json_to_v1_schedule() {
        let schedule_json = get_sample_v1_schedule_json().unwrap();
        if let Err(e) = EosProducerScheduleV1::from_schedule_json(&schedule_json) {
            panic!("Error converting v1 schedule json to schedule: {}", e);
        }
    }

    #[test]
    fn should_convert_full_producer_key_json_to_producer_key_v2() {
        let producer_key_json = get_sample_v2_schedule_json().unwrap().producers[0].clone();
        if let Err(e) = convert_full_producer_key_json_to_v2_producer_key(&producer_key_json) {
            panic!("Error converting producer key json: {}", e);
        }
    }
}
