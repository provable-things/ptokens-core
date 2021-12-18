use ethereum_types::H256 as EthHash;

use crate::{
    chains::eth::{any_sender::relay_transaction::RelayTransaction, eth_types::EthSignature},
    crypto_utils::keccak_hash_bytes,
    types::{Byte, Bytes, Result},
};

pub trait EthTxInfoCompatible {
    fn is_any_sender(&self) -> bool;
    fn any_sender_tx(&self) -> Option<RelayTransaction>;
    fn eth_tx_hex(&self) -> Option<String>;
    fn serialize_bytes(&self) -> Bytes;
    fn get_tx_hash(&self) -> String {
        hex::encode(keccak_hash_bytes(&self.serialize_bytes()))
    }
}

pub trait EthSigningCapabilities {
    fn sign_hash(&self, hash: EthHash) -> Result<EthSignature>;
    fn sign_message_bytes(&self, message: &[Byte]) -> Result<EthSignature>;
    fn sign_eth_prefixed_msg_bytes(&self, message: &[Byte]) -> Result<EthSignature>;
}

pub trait EthLogCompatible {
    fn get_data(&self) -> Bytes;
    fn get_topics(&self) -> Vec<EthHash>;

    fn check_has_x_topics(&self, x: usize) -> Result<()> {
        if self.get_topics().len() >= x {
            Ok(())
        } else {
            Err(format!("Log does not have {} topics!", x).into())
        }
    }
}
