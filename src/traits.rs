//! # pToken-specific traits.
use ethereum_types::H256 as KeccakHash;

use crate::types::{Bytes, Result};

pub trait DatabaseInterface {
    fn end_transaction(&self) -> Result<()>;

    fn start_transaction(&self) -> Result<()>;

    fn delete(&self, key: Bytes) -> Result<()>;

    fn get(&self, key: Bytes, data_sensitivity: Option<u8>) -> Result<Bytes>;

    fn put(&self, key: Bytes, value: Bytes, data_sensitivity: Option<u8>) -> Result<()>;
}

pub trait ChainId {
    fn keccak_hash(&self) -> Result<KeccakHash>;
}
