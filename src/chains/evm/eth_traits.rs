use crate::{
    chains::eth::any_sender::relay_transaction::RelayTransaction,
    crypto_utils::keccak_hash_bytes,
    types::Bytes,
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
