use eos_primitives::{AccountName as EosAccountName, NumBytes, PublicKey as EosPublicKey, Read, Write};

pub type Authority = (u8, EosKeysAndThreshold);

#[derive(Deserialize, Serialize, Read, Write, NumBytes, Clone, Default, Debug, PartialEq)]
#[eosio_core_root_path = "eos_primitives"]
pub struct EosProducerKeyV1 {
    pub producer_name: EosAccountName,
    pub block_signing_key: EosPublicKey,
}

impl EosProducerKeyV1 {
    pub fn new(producer_name: EosAccountName, block_signing_key: EosPublicKey) -> Self {
        EosProducerKeyV1 {
            producer_name,
            block_signing_key,
        }
    }
}

#[derive(Deserialize, Serialize, Read, Write, NumBytes, Clone, Default, Debug, PartialEq)]
#[eosio_core_root_path = "eos_primitives"]
pub struct EosProducerKeyV2 {
    pub producer_name: EosAccountName,
    pub authority: Authority,
}

#[derive(Read, Write, NumBytes, Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
#[eosio_core_root_path = "eos_primitives"]
pub struct EosKeysAndThreshold {
    pub threshold: u32,
    pub keys: Vec<EosKey>,
}

#[derive(Read, Write, NumBytes, Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
#[eosio_core_root_path = "eos_primitives"]
pub struct EosKey {
    pub key: EosPublicKey,
    pub weight: u16,
}
