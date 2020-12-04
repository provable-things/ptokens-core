use crate::{
    chains::btc::{
        btc_utils::{deserialize_btc_utxo, serialize_btc_utxo},
        deposit_address_info::DepositAddressInfoJson,
    },
    types::{Bytes, Result},
};
use bitcoin::{blockdata::transaction::TxIn as BtcUtxo, hashes::sha256d};
use derive_more::{Constructor, Deref, DerefMut, From, Into, IntoIterator};

#[derive(
    Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Constructor, Deref, DerefMut, From, Into, IntoIterator,
)]
pub struct BtcUtxosAndValues(pub Vec<BtcUtxoAndValue>);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BtcUtxoAndValue {
    pub value: u64,
    pub serialized_utxo: Bytes,
    pub maybe_extra_data: Option<Bytes>,
    pub maybe_pointer: Option<sha256d::Hash>,
    pub maybe_deposit_info_json: Option<DepositAddressInfoJson>,
}

impl BtcUtxoAndValue {
    pub fn new(
        value: u64,
        utxo: &BtcUtxo,
        maybe_deposit_info_json: Option<DepositAddressInfoJson>,
        maybe_extra_data: Option<Bytes>,
    ) -> Self {
        BtcUtxoAndValue {
            value,
            maybe_extra_data,
            maybe_pointer: None,
            maybe_deposit_info_json,
            serialized_utxo: serialize_btc_utxo(utxo),
        }
    }

    pub fn get_utxo(&self) -> Result<BtcUtxo> {
        deserialize_btc_utxo(&self.serialized_utxo)
    }

    pub fn update_pointer(mut self, hash: sha256d::Hash) -> Self {
        self.maybe_pointer = Some(hash);
        self
    }

    pub fn get_tx_id(&self) -> Result<sha256d::Hash> {
        Ok(self.get_utxo()?.previous_output.txid)
    }

    pub fn get_v_out(&self) -> Result<u32> {
        Ok(self.get_utxo()?.previous_output.vout)
    }
}
