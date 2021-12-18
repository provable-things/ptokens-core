use bitcoin::{
    blockdata::transaction::TxIn as BtcUtxo,
    hash_types::Txid,
    hashes::{sha256d, Hash},
};
use derive_more::{Constructor, Deref, DerefMut, From, Into, IntoIterator};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    chains::btc::{
        btc_utils::{deserialize_btc_utxo, serialize_btc_utxo},
        deposit_address_info::DepositAddressInfoJson,
    },
    types::{Bytes, Result},
};

#[derive(
    Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Constructor, Deref, DerefMut, From, Into, IntoIterator,
)]
pub struct BtcUtxosAndValues(pub Vec<BtcUtxoAndValue>);

impl BtcUtxosAndValues {
    pub fn to_string(&self) -> Result<String> {
        Ok(json!(self
            .iter()
            .map(|utxo| utxo.to_json())
            .collect::<Result<Vec<BtcUtxoAndValueJson>>>()?)
        .to_string())
    }

    pub fn from_str(s: &str) -> Result<Self> {
        let jsons: Vec<BtcUtxoAndValueJson> = serde_json::from_str(s)?;
        let structs = jsons
            .iter()
            .map(|json| BtcUtxoAndValue::from_json(json))
            .collect::<Result<Vec<BtcUtxoAndValue>>>()?;
        Ok(Self::new(structs))
    }

    #[cfg(test)]
    pub fn sum(&self) -> u64 {
        self.iter().map(|utxo| utxo.value).sum()
    }
}

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

    pub fn get_tx_id(&self) -> Result<Txid> {
        Ok(self.get_utxo()?.previous_output.txid)
    }

    pub fn get_v_out(&self) -> Result<u32> {
        Ok(self.get_utxo()?.previous_output.vout)
    }

    pub fn to_json(&self) -> Result<BtcUtxoAndValueJson> {
        Ok(BtcUtxoAndValueJson {
            value: self.value,
            v_out: Some(self.get_v_out()?),
            tx_id: Some(self.get_tx_id()?.to_string()),
            serialized_utxo: hex::encode(self.serialized_utxo.clone()),
            maybe_deposit_info_json: self.maybe_deposit_info_json.clone(),
            maybe_pointer: self.maybe_pointer.as_ref().map(|hash| hex::encode(&hash)),
            maybe_extra_data: self.maybe_extra_data.as_ref().map(|bytes| hex::encode(&bytes)),
        })
    }

    pub fn from_json(json: &BtcUtxoAndValueJson) -> Result<Self> {
        Ok(Self {
            value: json.value,
            maybe_pointer: json.get_maybe_pointer()?,
            maybe_extra_data: json.get_maybe_extra_data()?,
            serialized_utxo: hex::decode(&json.serialized_utxo)?,
            maybe_deposit_info_json: json.maybe_deposit_info_json.clone(),
        })
    }

    pub fn from_str(s: &str) -> Result<Self> {
        BtcUtxoAndValueJson::from_str(s).and_then(|json| Self::from_json(&json))
    }

    pub fn to_string(&self) -> Result<String> {
        self.to_json().and_then(|json| json.to_string())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BtcUtxoAndValueJson {
    pub value: u64,
    pub serialized_utxo: String,
    pub maybe_extra_data: Option<String>,
    pub maybe_pointer: Option<String>,
    pub maybe_deposit_info_json: Option<DepositAddressInfoJson>,
    pub tx_id: Option<String>,
    pub v_out: Option<u32>,
}

impl BtcUtxoAndValueJson {
    pub fn from_str(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }

    pub fn to_string(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn get_maybe_extra_data(&self) -> Result<Option<Bytes>> {
        match self.maybe_extra_data {
            Some(ref byte_string) => Ok(Some(hex::decode(byte_string)?)),
            None => Ok(None),
        }
    }

    pub fn get_maybe_pointer(&self) -> Result<Option<sha256d::Hash>> {
        match self.maybe_pointer {
            Some(ref byte_string) => Ok(Some(sha256d::Hash::from_slice(&hex::decode(byte_string)?)?)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::btc::btc_test_utils::{get_sample_p2sh_utxo_and_value, get_sample_utxo_and_values};

    #[test]
    fn should_make_utxo_and_value_to_json_round_trip() {
        let utxo_and_value = get_sample_p2sh_utxo_and_value().unwrap();
        let json = utxo_and_value.to_json().unwrap();
        let result = BtcUtxoAndValue::from_json(&json).unwrap();
        assert_eq!(result, utxo_and_value);
    }

    #[test]
    fn should_make_utxo_and_value_to_string_round_trip() {
        let utxo_and_value = get_sample_p2sh_utxo_and_value().unwrap();
        let json_string = utxo_and_value.to_string().unwrap();
        let result = BtcUtxoAndValue::from_str(&json_string).unwrap();
        assert_eq!(result, utxo_and_value);
    }

    #[test]
    fn should_make_utxos_and_values_to_string_round_trip() {
        let utxos = get_sample_utxo_and_values();
        let json_string = utxos.to_string().unwrap();
        let result = BtcUtxosAndValues::from_str(&json_string).unwrap();
        assert_eq!(result, utxos);
    }
}
