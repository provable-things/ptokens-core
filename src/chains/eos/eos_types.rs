use std::fmt;

use eos_primitives::{Checksum256, PermissionLevel as EosPermissionLevel};
use serde_json::Value as JsonValue;

pub type PermissionLevels = Vec<EosPermissionLevel>;

use crate::{
    chains::eos::{eos_producer_key::EosProducerKeyV1, eos_utils::get_eos_schedule_db_key},
    types::Bytes,
};

pub type MerkleProof = Vec<String>;
pub type Checksum256s = Vec<Checksum256>;
pub type ProducerKeys = Vec<EosProducerKeyV1>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EosKnownSchedules(Vec<EosKnownSchedule>);

impl EosKnownSchedules {
    pub fn new(version: u32) -> Self {
        EosKnownSchedules(vec![EosKnownSchedule::new(version)])
    }

    pub fn add(mut self, version: u32) -> Self {
        let new_sched = EosKnownSchedule::new(version);
        if !self.0.contains(&new_sched) {
            self.0.push(new_sched);
        };
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EosKnownSchedule {
    pub schedule_db_key: Bytes,
    pub schedule_version: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EosKnownSchedulesJsons(Vec<EosKnownScheduleJson>);

impl EosKnownSchedulesJsons {
    pub fn from_schedules(scheds: EosKnownSchedules) -> EosKnownSchedulesJsons {
        EosKnownSchedulesJsons(
            scheds
                .0
                .iter()
                .map(|sched| EosKnownScheduleJson::from_schedule(sched))
                .collect::<Vec<EosKnownScheduleJson>>(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EosKnownScheduleJson {
    pub schedule_db_key: String,
    pub schedule_version: u32,
}

impl EosKnownScheduleJson {
    pub fn from_schedule(sched: &EosKnownSchedule) -> Self {
        EosKnownScheduleJson {
            schedule_version: sched.schedule_version,
            schedule_db_key: hex::encode(sched.schedule_db_key.clone()),
        }
    }
}

impl EosKnownSchedule {
    pub fn new(schedule_version: u32) -> Self {
        EosKnownSchedule {
            schedule_version,
            schedule_db_key: get_eos_schedule_db_key(schedule_version),
        }
    }
}

impl fmt::Display for EosKnownSchedules {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EosKnownSchedule:")?;
        for v in &self.0 {
            write!(f, "{}", v)?;
        }
        Ok(())
    }
}

impl fmt::Display for EosKnownSchedule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "\tschedule_version: {},\n\tdb_key: {}",
            self.schedule_version,
            hex::encode(&self.schedule_db_key)
        )
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum EosNetwork {
    Mainnet,
    Testnet,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EosBlockHeaderJson {
    pub block_num: u64,
    pub confirmed: u16,
    pub producer: String,
    pub previous: String,
    pub block_id: String,
    pub timestamp: String,
    pub action_mroot: String,
    pub schedule_version: u32,
    pub transaction_mroot: String,
    pub producer_signature: String,
    pub new_producers: Option<JsonValue>,
    pub new_producer_schedule: Option<JsonValue>,
    pub header_extension: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProducerSchedule {
    pub version: u32,
    pub producers: ProducerKeys,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProducerKeyJsonV2 {
    pub producer_name: String,
    pub block_signing_key: String,
}

#[derive(Debug)]
pub struct EosRawTxData {
    pub sender: String,
    pub mint_nonce: u64,
    pub receiver: String,
    pub asset_amount: u64,
    pub asset_name: String,
    pub eth_address: String,
}
