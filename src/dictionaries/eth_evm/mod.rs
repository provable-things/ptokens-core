use derive_more::{Constructor, Deref, DerefMut};
use ethereum_types::{Address as EthAddress, U256};
use serde::{Deserialize, Serialize};

use crate::{
    chains::{eth::eth_state::EthState, evm::eth_state::EthState as EvmState},
    constants::MIN_DATA_SENSITIVITY_LEVEL,
    dictionaries::dictionary_constants::ETH_EVM_DICTIONARY_KEY,
    fees::fee_utils::get_last_withdrawal_date_as_human_readable_string,
    traits::DatabaseInterface,
    types::{Byte, Bytes, Result},
    utils::{get_unix_timestamp, strip_hex_prefix},
};

pub(crate) mod test_utils;

#[derive(Debug, Clone, Eq, PartialEq, Constructor, Deref, DerefMut, Serialize, Deserialize)]
pub struct EthEvmTokenDictionary(pub Vec<EthEvmTokenDictionaryEntry>);

impl EthEvmTokenDictionary {
    pub fn convert_eth_amount_to_evm_amount(&self, address: &EthAddress, amount: U256) -> Result<U256> {
        self.get_entry_via_address(address)
            .and_then(|entry| entry.convert_eth_amount_to_evm_amount(amount))
    }

    pub fn convert_evm_amount_to_eth_amount(&self, address: &EthAddress, amount: U256) -> Result<U256> {
        self.get_entry_via_address(address)
            .and_then(|entry| entry.convert_evm_amount_to_eth_amount(amount))
    }

    pub fn to_json(&self) -> Result<EthEvmTokenDictionaryJson> {
        Ok(EthEvmTokenDictionaryJson::new(
            self.iter().map(|entry| entry.to_json()).collect(),
        ))
    }

    pub fn from_json(json: &EthEvmTokenDictionaryJson) -> Result<Self> {
        Ok(Self(
            json.iter()
                .map(|entry_json| EthEvmTokenDictionaryEntry::from_json(entry_json))
                .collect::<Result<Vec<EthEvmTokenDictionaryEntry>>>()?,
        ))
    }

    fn to_bytes(&self) -> Result<Bytes> {
        self.to_json()?.to_bytes()
    }

    fn from_bytes(bytes: &[Byte]) -> Result<Self> {
        EthEvmTokenDictionaryJson::from_bytes(bytes).and_then(|json| Self::from_json(&json))
    }

    fn add(&self, entry: EthEvmTokenDictionaryEntry) -> Self {
        let mut new_self = self.clone();
        match self.contains(&entry) {
            true => {
                info!("✘ Not adding new `EthEvmTokenDictionaryEntry` ∵ entry already extant!");
                new_self
            },
            false => {
                info!("✔ Adding `EthEvmTokenDictionary` entry: {:?}...", entry);
                new_self.push(entry);
                new_self
            },
        }
    }

    fn remove(&self, entry: &EthEvmTokenDictionaryEntry) -> Self {
        let mut new_self = self.clone();
        match self.contains(entry) {
            false => {
                info!(
                    "✔ Not removing `EthEvmTokenDictionary` entry ∵ it's not in the dictionary! {:?}",
                    entry
                );
                new_self
            },
            true => {
                info!("✔ Removing `EthEvmTokenDictionaryEntry`: {:?}", entry);
                new_self.retain(|x| x != entry);
                new_self
            },
        }
    }

    fn save_in_db<D: DatabaseInterface>(&self, db: &D) -> Result<()> {
        db.put(
            ETH_EVM_DICTIONARY_KEY.to_vec(),
            self.to_bytes()?,
            MIN_DATA_SENSITIVITY_LEVEL,
        )
    }

    pub fn get_from_db<D: DatabaseInterface>(db: &D) -> Result<Self> {
        info!("✔ Getting `EthEvmTokenDictionaryJson` from db...");
        match db.get(ETH_EVM_DICTIONARY_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL) {
            Ok(bytes) => Self::from_bytes(&bytes),
            Err(_) => {
                info!("✘ No `EthEvmTokenDictionaryJson` in db! Initializing a new one...");
                Ok(Self::new(vec![]))
            },
        }
    }

    pub fn add_and_update_in_db<D: DatabaseInterface>(&self, entry: EthEvmTokenDictionaryEntry, db: &D) -> Result<()> {
        self.add(entry).save_in_db(db)
    }

    fn remove_and_update_in_db<D: DatabaseInterface>(&self, entry: &EthEvmTokenDictionaryEntry, db: &D) -> Result<()> {
        if self.contains(entry) {
            info!("✔ Removing entry & updating in db...");
            self.remove(entry).save_in_db(db)
        } else {
            info!("✘ Not removing entry || updating in db ∵ entry not extant!");
            Ok(())
        }
    }

    pub fn remove_entry_via_eth_address_and_update_in_db<D: DatabaseInterface>(
        &self,
        eth_address: &EthAddress,
        db: &D,
    ) -> Result<()> {
        self.get_entry_via_eth_address(eth_address)
            .and_then(|entry| self.remove_and_update_in_db(&entry, db))
    }

    pub fn get_entry_via_eth_address(&self, address: &EthAddress) -> Result<EthEvmTokenDictionaryEntry> {
        match self.iter().find(|entry| entry.eth_address == *address) {
            Some(entry) => Ok(entry.clone()),
            None => Err(format!("No `EthEvmTokenDictionaryEntry` exists with ETH address: {}", address).into()),
        }
    }

    pub fn get_entry_via_evm_address(&self, address: &EthAddress) -> Result<EthEvmTokenDictionaryEntry> {
        match self.iter().find(|entry| &entry.evm_address == address) {
            Some(entry) => Ok(entry.clone()),
            None => Err(format!("No `EthEvmTokenDictionaryEntry` exists with ETH address: {}", address).into()),
        }
    }

    pub fn get_evm_address_from_eth_address(&self, address: &EthAddress) -> Result<EthAddress> {
        self.get_entry_via_eth_address(address).map(|entry| entry.evm_address)
    }

    pub fn get_eth_address_from_evm_address(&self, address: &EthAddress) -> Result<EthAddress> {
        self.get_entry_via_evm_address(address).map(|entry| entry.eth_address)
    }

    pub fn is_evm_token_supported(&self, address: &EthAddress) -> bool {
        self.get_entry_via_evm_address(address).is_ok()
    }

    pub fn to_evm_addresses(&self) -> Vec<EthAddress> {
        self.iter().map(|entry| entry.evm_address).collect()
    }

    #[cfg(test)]
    pub fn from_str(s: &str) -> Result<Self> {
        let entry_jsons: Vec<EthEvmTokenDictionaryEntryJson> = serde_json::from_str(s)?;
        Ok(Self::new(
            entry_jsons
                .iter()
                .map(|ref entry_json| EthEvmTokenDictionaryEntry::from_json(entry_json))
                .collect::<Result<Vec<EthEvmTokenDictionaryEntry>>>()?,
        ))
    }

    fn get_eth_fee_basis_points(&self, eth_address: &EthAddress) -> Result<u64> {
        Ok(self.get_entry_via_eth_address(eth_address)?.eth_fee_basis_points)
    }

    fn get_evm_fee_basis_points(&self, evm_address: &EthAddress) -> Result<u64> {
        Ok(self.get_entry_via_evm_address(evm_address)?.evm_fee_basis_points)
    }

    pub fn get_fee_basis_points(&self, address: &EthAddress) -> Result<u64> {
        self.get_eth_fee_basis_points(address)
            .or_else(|_| self.get_evm_fee_basis_points(address))
    }

    fn get_entry_via_address(&self, address: &EthAddress) -> Result<EthEvmTokenDictionaryEntry> {
        self.get_entry_via_eth_address(address)
            .or_else(|_| self.get_entry_via_evm_address(address))
    }

    pub fn replace_entry(
        &self,
        entry_to_remove: &EthEvmTokenDictionaryEntry,
        entry_to_add: EthEvmTokenDictionaryEntry,
    ) -> Self {
        if entry_to_add == *entry_to_remove {
            info!("✘ Entry to replace is identical to new entry, doing nothing!");
            self.clone()
        } else {
            info!("✔ Replacing dictionary entry...");
            self.add(entry_to_add).remove(entry_to_remove)
        }
    }

    pub fn increment_accrued_fee(&self, address: &EthAddress, addend: U256) -> Result<Self> {
        self.get_entry_via_address(address)
            .map(|entry| self.replace_entry(&entry, entry.add_to_accrued_fees(addend)))
    }

    pub fn increment_accrued_fees(&self, fee_tuples: Vec<(EthAddress, U256)>) -> Result<Self> {
        info!("✔ Incrementing accrued fees...");
        fee_tuples
            .iter()
            .filter(|(address, addend)| {
                if *addend > U256::zero() {
                    true
                } else {
                    info!("✘ Not adding to accrued fees for {} ∵ increment is 0!", address);
                    false
                }
            })
            .try_fold(self.clone(), |new_self, (address, addend)| {
                new_self.increment_accrued_fee(address, *addend)
            })
    }

    pub fn increment_accrued_fees_and_save_in_db<D: DatabaseInterface>(
        &self,
        db: &D,
        fee_tuples: Vec<(EthAddress, U256)>,
    ) -> Result<()> {
        self.increment_accrued_fees(fee_tuples)
            .and_then(|new_dictionary| new_dictionary.save_in_db(db))
    }

    fn change_eth_fee_basis_points(&self, eth_address: &EthAddress, new_fee: u64) -> Result<Self> {
        info!(
            "✔ Changing ETH fee basis points for address {} to {}...",
            eth_address, new_fee
        );
        self.get_entry_via_eth_address(eth_address)
            .map(|entry| self.replace_entry(&entry, entry.change_eth_fee_basis_points(new_fee)))
    }

    fn change_evm_fee_basis_points(&self, evm_address: &EthAddress, new_fee: u64) -> Result<Self> {
        info!(
            "✔ Changing EVM fee basis points for address {} to {}...",
            evm_address, new_fee
        );
        self.get_entry_via_evm_address(evm_address)
            .map(|entry| self.replace_entry(&entry, entry.change_evm_fee_basis_points(new_fee)))
    }

    fn change_fee_basis_points(&self, address: &EthAddress, new_fee: u64) -> Result<Self> {
        self.change_eth_fee_basis_points(address, new_fee)
            .or_else(|_| self.change_evm_fee_basis_points(address, new_fee))
    }

    pub fn change_fee_basis_points_and_update_in_db<D: DatabaseInterface>(
        &self,
        db: &D,
        address: &EthAddress,
        new_fee: u64,
    ) -> Result<()> {
        self.change_fee_basis_points(address, new_fee)
            .and_then(|updated_dictionary| updated_dictionary.save_in_db(db))
    }

    fn set_last_withdrawal_timestamp_in_entry(&self, address: &EthAddress, timestamp: u64) -> Result<Self> {
        self.get_entry_via_address(address)
            .map(|entry| self.replace_entry(&entry, entry.set_last_withdrawal_timestamp(timestamp)))
    }

    fn zero_accrued_fees_in_entry(&self, address: &EthAddress) -> Result<Self> {
        self.get_entry_via_address(address)
            .map(|entry| self.replace_entry(&entry, entry.zero_accrued_fees()))
    }

    pub fn withdraw_fees_and_save_in_db<D: DatabaseInterface>(
        &self,
        db: &D,
        maybe_entry_address: &EthAddress,
    ) -> Result<(EthAddress, U256)> {
        let entry = self.get_entry_via_address(maybe_entry_address)?;
        let token_address = entry.eth_address;
        let withdrawal_amount = entry.accrued_fees;
        self.set_last_withdrawal_timestamp_in_entry(&token_address, get_unix_timestamp()?)
            .and_then(|dictionary| dictionary.zero_accrued_fees_in_entry(&token_address))
            .and_then(|dictionary| dictionary.save_in_db(db))
            .map(|_| (token_address, withdrawal_amount))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Deref, Constructor)]
pub struct EthEvmTokenDictionaryJson(pub Vec<EthEvmTokenDictionaryEntryJson>);

impl EthEvmTokenDictionaryJson {
    pub fn to_bytes(&self) -> Result<Bytes> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_bytes(bytes: &[Byte]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Constructor, Deserialize, Serialize)]
pub struct EthEvmTokenDictionaryEntry {
    pub eth_symbol: String,
    pub evm_symbol: String,
    pub evm_address: EthAddress,
    pub eth_address: EthAddress,
    pub eth_fee_basis_points: u64,
    pub evm_fee_basis_points: u64,
    pub accrued_fees: U256,
    pub last_withdrawal: u64,
    pub accrued_fees_human_readable: u128,
    pub last_withdrawal_human_readable: String,
    pub eth_token_decimals: Option<u16>,
    pub evm_token_decimals: Option<u16>,
}

impl EthEvmTokenDictionaryEntry {
    fn require_decimal_conversion(&self) -> bool {
        self.eth_token_decimals.is_some()
            && self.evm_token_decimals.is_some()
            && self.eth_token_decimals != self.evm_token_decimals
    }

    fn to_json(&self) -> EthEvmTokenDictionaryEntryJson {
        EthEvmTokenDictionaryEntryJson {
            evm_symbol: self.evm_symbol.to_string(),
            eth_symbol: self.eth_symbol.to_string(),
            evm_address: hex::encode(self.evm_address),
            eth_address: hex::encode(self.eth_address),
            eth_fee_basis_points: Some(self.eth_fee_basis_points),
            evm_fee_basis_points: Some(self.evm_fee_basis_points),
            accrued_fees: Some(self.accrued_fees.as_u128()),
            last_withdrawal: Some(self.last_withdrawal),
            eth_token_decimals: self.eth_token_decimals,
            evm_token_decimals: self.evm_token_decimals,
        }
    }

    pub fn from_json(json: &EthEvmTokenDictionaryEntryJson) -> Result<Self> {
        let timestamp = json.last_withdrawal.unwrap_or_default();
        let accrued_fees = U256::from(json.accrued_fees.unwrap_or_default());
        Ok(Self {
            evm_symbol: json.evm_symbol.clone(),
            eth_symbol: json.eth_symbol.clone(),
            eth_address: EthAddress::from_slice(&hex::decode(strip_hex_prefix(&json.eth_address))?),
            evm_address: EthAddress::from_slice(&hex::decode(strip_hex_prefix(&json.evm_address))?),
            eth_fee_basis_points: json.eth_fee_basis_points.unwrap_or_default(),
            evm_fee_basis_points: json.evm_fee_basis_points.unwrap_or_default(),
            accrued_fees_human_readable: accrued_fees.as_u128(),
            last_withdrawal: timestamp,
            last_withdrawal_human_readable: get_last_withdrawal_date_as_human_readable_string(timestamp),
            accrued_fees,
            eth_token_decimals: json.eth_token_decimals,
            evm_token_decimals: json.evm_token_decimals,
        })
    }

    pub fn from_str(json_string: &str) -> Result<Self> {
        EthEvmTokenDictionaryEntryJson::from_str(json_string).and_then(|entry_json| Self::from_json(&entry_json))
    }

    pub fn add_to_accrued_fees(&self, addend: U256) -> Self {
        let new_accrued_fees = self.accrued_fees + addend;
        info!("✔ Adding to accrued fees in {:?}...", self);
        info!(
            "✔ Updating accrued fees from {} to {}...",
            self.accrued_fees, new_accrued_fees
        );
        let mut new_entry = self.clone();
        new_entry.accrued_fees = new_accrued_fees;
        new_entry.accrued_fees_human_readable = new_accrued_fees.as_u128();
        new_entry
    }

    pub fn change_eth_fee_basis_points(&self, new_fee: u64) -> Self {
        info!(
            "✔ Changing ETH fee basis points for address {} from {} to {}...",
            self.eth_address, self.eth_fee_basis_points, new_fee
        );
        let mut new_entry = self.clone();
        new_entry.eth_fee_basis_points = new_fee;
        new_entry
    }

    pub fn change_evm_fee_basis_points(&self, new_fee: u64) -> Self {
        info!(
            "✔ Changing EVM fee basis points for address {} from {} to {}...",
            self.evm_address, self.evm_fee_basis_points, new_fee
        );
        let mut new_entry = self.clone();
        new_entry.evm_fee_basis_points = new_fee;
        new_entry
    }

    fn set_last_withdrawal_timestamp(&self, timestamp: u64) -> Self {
        let timestamp_human_readable = get_last_withdrawal_date_as_human_readable_string(timestamp);
        info!("✔ Setting withdrawal date to {}", timestamp_human_readable);
        let mut new_entry = self.clone();
        new_entry.last_withdrawal = timestamp;
        new_entry.last_withdrawal_human_readable = timestamp_human_readable;
        new_entry
    }

    fn zero_accrued_fees(&self) -> Self {
        info!("✔ Zeroing accrued fees in {:?}...", self);
        let mut new_entry = self.clone();
        new_entry.accrued_fees = U256::zero();
        new_entry.accrued_fees_human_readable = 0;
        new_entry
    }

    fn get_eth_token_decimals(&self) -> Result<u16> {
        self.eth_token_decimals
            .ok_or_else(|| format!("Dictionary entry does NOT have ETH token decimals set! {:?}", self).into())
    }

    fn get_evm_token_decimals(&self) -> Result<u16> {
        self.evm_token_decimals
            .ok_or_else(|| format!("Dictionary entry does NOT have EVM token decimals set! {:?}", self).into())
    }

    pub fn convert_eth_amount_to_evm_amount(&self, amount: U256) -> Result<U256> {
        info!("✔ Converting from ETH amount to EVM amount...");
        self.convert_amount(amount, true)
    }

    pub fn convert_evm_amount_to_eth_amount(&self, amount: U256) -> Result<U256> {
        info!("✔ Converting from EVM amount to ETH amount...");
        self.convert_amount(amount, false)
    }

    fn convert_amount(&self, amount: U256, eth_to_evm: bool) -> Result<U256> {
        if self.require_decimal_conversion() {
            let eth_token_decimals = self.get_eth_token_decimals()?;
            let evm_token_decimals = self.get_evm_token_decimals()?;
            let to = if eth_to_evm {
                evm_token_decimals
            } else {
                eth_token_decimals
            };
            let from = if eth_to_evm {
                eth_token_decimals
            } else {
                evm_token_decimals
            };
            let multiplicand = U256::from(10).pow(U256::from(to));
            let divisor = U256::from(10).pow(U256::from(from));
            info!("✔ Converting {} from {} decimals to {}...", amount, from, to);
            Ok((amount * multiplicand) / divisor)
        } else {
            info!(
                "✔ Amounts for this dictionary entry do NOT require decimal conversion! {:?}",
                self,
            );
            Ok(amount)
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct EthEvmTokenDictionaryEntryJson {
    eth_symbol: String,
    evm_symbol: String,
    eth_address: String,
    evm_address: String,
    eth_fee_basis_points: Option<u64>,
    evm_fee_basis_points: Option<u64>,
    accrued_fees: Option<u128>,
    last_withdrawal: Option<u64>,
    eth_token_decimals: Option<u16>,
    evm_token_decimals: Option<u16>,
}

impl EthEvmTokenDictionaryEntryJson {
    pub fn from_str(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

pub fn get_eth_evm_token_dictionary_from_db_and_add_to_evm_state<D: DatabaseInterface>(
    state: EvmState<D>,
) -> Result<EvmState<D>> {
    info!("✔ Getting `EthEvmTokenDictionary` and adding to EVM state...");
    EthEvmTokenDictionary::get_from_db(&state.db).and_then(|dictionary| state.add_eth_evm_token_dictionary(dictionary))
}

pub fn get_eth_evm_token_dictionary_from_db_and_add_to_eth_state<D: DatabaseInterface>(
    state: EthState<D>,
) -> Result<EthState<D>> {
    info!("✔ Getting `EthEvmTokenDictionary` and adding to ETH state...");
    EthEvmTokenDictionary::get_from_db(&state.db).and_then(|dictionary| state.add_eth_evm_token_dictionary(dictionary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dictionaries::eth_evm::test_utils::{get_sample_eth_evm_dictionary, get_sample_eth_evm_dictionary_json_str},
        errors::AppError,
        test_utils::get_test_database,
    };

    fn get_dictionary_entry_with_different_decimals() -> EthEvmTokenDictionaryEntry {
        let dictionary = get_sample_eth_evm_dictionary();
        let eth_address = EthAddress::from_slice(&hex::decode("15D4c048F83bd7e37d49eA4C83a07267Ec4203dA").unwrap());
        dictionary.get_entry_via_eth_address(&eth_address).unwrap()
    }

    fn get_dictionary_entry_with_same_decimals() -> EthEvmTokenDictionaryEntry {
        let dictionary = get_sample_eth_evm_dictionary();
        let eth_address = EthAddress::from_slice(&hex::decode("89ab32156e46f46d02ade3fecbe5fc4243b9aaed").unwrap());
        dictionary.get_entry_via_eth_address(&eth_address).unwrap()
    }

    fn get_dictionary_entry_with_no_decimals() -> EthEvmTokenDictionaryEntry {
        // NOTE:The decimals here are techincally the same, but in this case happen to be "None"
        get_dictionary_entry_with_same_decimals()
    }

    #[test]
    fn should_get_dictionary_from_str() {
        let result = EthEvmTokenDictionary::from_str(&get_sample_eth_evm_dictionary_json_str().unwrap());
        assert!(result.is_ok());
    }

    #[test]
    fn should_perform_dict_json_bytes_roundtrip() {
        let json = get_sample_eth_evm_dictionary().to_json().unwrap();
        let bytes = json.to_bytes().unwrap();
        let result = EthEvmTokenDictionaryJson::from_bytes(&bytes).unwrap();
        assert_eq!(result, json);
    }

    #[test]
    fn should_convert_bytes_to_dictionary() {
        // NOTE: This was the bytes encoding of a dictionary BEFORE extra optional args were added.
        // And so the test remains useful!
        let bytes = hex::decode("5b7b226574685f73796d626f6c223a22504e54222c2265766d5f73796d626f6c223a22504e54222c226574685f61646472657373223a2238396162333231353665343666343664303261646533666563626535666334323433623961616564222c2265766d5f61646472657373223a2264616163623061623666623334643234653861363762666131346266346439356434633761663932227d2c7b226574685f73796d626f6c223a224f5049554d222c2265766d5f73796d626f6c223a22704f5049554d222c226574685f61646472657373223a2238383838383838383838383963303063363736383930323964373835366161633130363565633131222c2265766d5f61646472657373223a2235363663656464323031663637653534326136383531613239353963316134343961303431393435227d2c7b226574685f73796d626f6c223a22505445524941222c2265766d5f73796d626f6c223a22505445524941222c226574685f61646472657373223a2230326563613931306362336137643433656263376538303238363532656435633662373032353962222c2265766d5f61646472657373223a2239663533373766613033646364343031366133333636396233383562653464306530326632376263227d2c7b226574685f73796d626f6c223a22424350222c2265766d5f73796d626f6c223a2270424350222c226574685f61646472657373223a2265346637323661646338653839633661363031376630316561646137373836356462323264613134222c2265766d5f61646472657373223a2261313134663839623439643661353834313662623037646265303935303263346633613139653266227d2c7b226574685f73796d626f6c223a22444546492b2b222c2265766d5f73796d626f6c223a2270444546492b2b222c226574685f61646472657373223a2238643163653336316562363865396530353537333434336334303764346133626564323362303333222c2265766d5f61646472657373223a2261653232653237643166373237623538353534396331306532363139326232626330313038326361227d2c7b226574685f73796d626f6c223a22434747222c2265766d5f73796d626f6c223a22434747222c226574685f61646472657373223a2231666532346632356231636636303962396334653765313264383032653336343064666135653433222c2265766d5f61646472657373223a2231363133393537313539653962306163366338306538323466376565613734386133326130616532227d5d").unwrap();
        let result = EthEvmTokenDictionaryJson::from_bytes(&bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn pnt_token_in_sample_dictionary_should_have_fees_set() {
        let dictionary = get_sample_eth_evm_dictionary();
        let pnt_address = EthAddress::from_slice(&hex::decode("89ab32156e46f46d02ade3fecbe5fc4243b9aaed").unwrap());
        let entry = dictionary.get_entry_via_eth_address(&pnt_address).unwrap();
        assert!(entry.eth_fee_basis_points > 0);
        assert!(entry.evm_fee_basis_points > 0);
    }

    #[test]
    fn should_get_eth_fee_basis_points() {
        let dictionary = get_sample_eth_evm_dictionary();
        let eth_address = EthAddress::from_slice(&hex::decode("89ab32156e46f46d02ade3fecbe5fc4243b9aaed").unwrap());
        let result = dictionary.get_eth_fee_basis_points(&eth_address).unwrap();
        let expected_result = 10;
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_evm_fee_basis_points() {
        let dictionary = get_sample_eth_evm_dictionary();
        let evm_address = EthAddress::from_slice(&hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap());
        let result = dictionary.get_evm_fee_basis_points(&evm_address).unwrap();
        let expected_result = 20;
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_fee_basis_points() {
        let dictionary = get_sample_eth_evm_dictionary();
        let evm_address = EthAddress::from_slice(&hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap());
        let result = dictionary.get_fee_basis_points(&evm_address).unwrap();
        let expected_result = 20;
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_add_to_accrued_fees_in_dictionary_entry() {
        let dictionary = get_sample_eth_evm_dictionary();
        let evm_address = EthAddress::from_slice(&hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap());
        let entry = dictionary.get_entry_via_evm_address(&evm_address).unwrap();
        assert_eq!(entry.last_withdrawal, 0);
        assert_eq!(entry.accrued_fees, U256::zero());
        let fee_to_add = U256::from(1337);
        let result = entry.add_to_accrued_fees(fee_to_add);
        assert_eq!(result.accrued_fees, fee_to_add);
    }

    #[test]
    fn should_get_entry_via_address() {
        let dictionary = get_sample_eth_evm_dictionary();
        let evm_address = EthAddress::from_slice(&hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap());
        let result = dictionary.get_entry_via_address(&evm_address).unwrap();
        assert_eq!(result.evm_address, evm_address);
    }

    #[test]
    fn should_increment_accrued_fees() {
        let dictionary = get_sample_eth_evm_dictionary();
        let fee_1 = U256::from(666);
        let fee_2 = U256::from(1337);
        let address_1 = EthAddress::from_slice(&hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap());
        let address_2 = EthAddress::from_slice(&hex::decode("888888888889c00c67689029d7856aac1065ec11").unwrap());
        let fee_tuples = vec![(address_1, fee_1), (address_2, fee_2)];
        let entry_1_before = dictionary.get_entry_via_address(&address_1).unwrap();
        let entry_2_before = dictionary.get_entry_via_address(&address_2).unwrap();
        assert_eq!(entry_1_before.accrued_fees, U256::zero());
        assert_eq!(entry_2_before.accrued_fees, U256::zero());
        assert_eq!(entry_1_before.last_withdrawal, 0);
        assert_eq!(entry_2_before.last_withdrawal, 0);
        let result = dictionary.increment_accrued_fees(fee_tuples).unwrap();
        let entry_1_after = result.get_entry_via_address(&address_1).unwrap();
        let entry_2_after = result.get_entry_via_address(&address_2).unwrap();
        assert_eq!(entry_1_after.accrued_fees, fee_1);
        assert_eq!(entry_2_after.accrued_fees, fee_2);
    }

    #[test]
    fn should_change_eth_fee_basis_points() {
        let new_fee = 1337;
        let dictionary = get_sample_eth_evm_dictionary();
        let eth_address = EthAddress::from_slice(&hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap());
        let entry = dictionary.get_entry_via_address(&eth_address).unwrap();
        let fee_before = entry.eth_fee_basis_points;
        assert_ne!(fee_before, new_fee);
        let result = entry.change_eth_fee_basis_points(new_fee);
        assert_eq!(result.eth_fee_basis_points, new_fee);
    }

    #[test]
    fn should_change_evm_fee_basis_points() {
        let new_fee = 1337;
        let dictionary = get_sample_eth_evm_dictionary();
        let evm_address = EthAddress::from_slice(&hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap());
        let entry = dictionary.get_entry_via_address(&evm_address).unwrap();
        let fee_before = entry.evm_fee_basis_points;
        assert_ne!(fee_before, new_fee);
        let result = entry.change_evm_fee_basis_points(new_fee);
        assert_eq!(result.evm_fee_basis_points, new_fee);
    }

    #[test]
    fn should_change_eth_fee_basis_points_via_dictionary() {
        let new_fee = 1337;
        let dictionary = get_sample_eth_evm_dictionary();
        let eth_address = EthAddress::from_slice(&hex::decode("89ab32156e46f46d02ade3fecbe5fc4243b9aaed").unwrap());
        let fee_before = dictionary.get_eth_fee_basis_points(&eth_address).unwrap();
        assert_ne!(fee_before, new_fee);
        let updated_dictionary = dictionary.change_fee_basis_points(&eth_address, new_fee).unwrap();
        let result = updated_dictionary.get_eth_fee_basis_points(&eth_address).unwrap();
        assert_eq!(result, new_fee)
    }

    #[test]
    fn should_change_evm_fee_basis_points_via_dictionary() {
        let new_fee = 1337;
        let dictionary = get_sample_eth_evm_dictionary();
        let evm_address = EthAddress::from_slice(&hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap());
        let fee_before = dictionary.get_evm_fee_basis_points(&evm_address).unwrap();
        assert_ne!(fee_before, new_fee);
        let updated_dictionary = dictionary.change_fee_basis_points(&evm_address, new_fee).unwrap();
        let result = updated_dictionary.get_evm_fee_basis_points(&evm_address).unwrap();
        assert_eq!(result, new_fee)
    }

    #[test]
    fn should_change_fee_basis_points_and_update_in_db() {
        let db = get_test_database();
        let new_fee = 1337;
        let dictionary = get_sample_eth_evm_dictionary();
        let eth_address = EthAddress::from_slice(&hex::decode("89ab32156e46f46d02ade3fecbe5fc4243b9aaed").unwrap());
        let fee_before = dictionary.get_eth_fee_basis_points(&eth_address).unwrap();
        assert_ne!(fee_before, new_fee);
        dictionary
            .change_fee_basis_points_and_update_in_db(&db, &eth_address, new_fee)
            .unwrap();
        let dictionary_from_db = EthEvmTokenDictionary::get_from_db(&db).unwrap();
        let result = dictionary_from_db.get_eth_fee_basis_points(&eth_address).unwrap();
        assert_eq!(result, new_fee)
    }

    #[test]
    fn should_set_last_withdrawal_timestamp_in_dictionary_entry() {
        let timestamp = get_unix_timestamp().unwrap();
        let human_readable_timestamp = get_last_withdrawal_date_as_human_readable_string(timestamp);
        let dictionary = get_sample_eth_evm_dictionary();
        let evm_address = EthAddress::from_slice(&hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap());
        let entry = dictionary.get_entry_via_address(&evm_address).unwrap();
        let result = entry.set_last_withdrawal_timestamp(timestamp);
        assert_eq!(result.last_withdrawal, timestamp);
        assert_eq!(result.last_withdrawal_human_readable, human_readable_timestamp);
    }

    #[test]
    fn should_zero_accrued_fees_in_dictionary_entry() {
        let fees_before = U256::from(1337);
        let fees_after = U256::zero();
        let dictionary = get_sample_eth_evm_dictionary();
        let evm_address = EthAddress::from_slice(&hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap());
        let entry = dictionary.get_entry_via_address(&evm_address).unwrap();
        let updated_entry = entry.add_to_accrued_fees(fees_before);
        assert_eq!(updated_entry.accrued_fees, fees_before);
        let result = entry.zero_accrued_fees();
        assert_eq!(result.accrued_fees, fees_after);
    }

    #[test]
    fn should_set_last_withdrawal_timestamp_in_entry_via_dictionary() {
        let timestamp = get_unix_timestamp().unwrap();
        let dictionary = get_sample_eth_evm_dictionary();
        let address = EthAddress::from_slice(&hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap());
        let entry_before = dictionary.get_entry_via_address(&address).unwrap();
        assert_eq!(entry_before.last_withdrawal, 0);
        let updated_dictionary = dictionary
            .set_last_withdrawal_timestamp_in_entry(&address, timestamp)
            .unwrap();
        let result = updated_dictionary.get_entry_via_address(&address).unwrap();
        assert_eq!(result.last_withdrawal, timestamp);
    }

    #[test]
    fn should_zero_accrued_fees_in_entry_via_dictionary() {
        let fees_before = U256::from(1337);
        let fees_after = U256::zero();
        let dictionary = get_sample_eth_evm_dictionary();
        let address = EthAddress::from_slice(&hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap());
        let updated_dictionary = dictionary.increment_accrued_fee(&address, fees_before).unwrap();
        let entry = updated_dictionary.get_entry_via_address(&address).unwrap();
        assert_eq!(entry.accrued_fees, fees_before);
        let final_dictionary = updated_dictionary.zero_accrued_fees_in_entry(&address).unwrap();
        let result = final_dictionary.get_entry_via_address(&address).unwrap();
        assert_eq!(result.accrued_fees, fees_after);
    }

    #[test]
    fn should_withdraw_fees_and_save_in_db() {
        let timestamp = get_unix_timestamp().unwrap();
        let db = get_test_database();
        let expected_fee = U256::from(1337);
        let dictionary = get_sample_eth_evm_dictionary();
        let expected_token_address =
            EthAddress::from_slice(&hex::decode("89ab32156e46f46d02ade3fecbe5fc4243b9aaed").unwrap());
        let address = EthAddress::from_slice(&hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap());
        let updated_dictionary = dictionary.increment_accrued_fee(&address, expected_fee).unwrap();
        let entry_before = updated_dictionary.get_entry_via_address(&address).unwrap();
        assert_eq!(entry_before.accrued_fees, expected_fee);
        assert_eq!(entry_before.last_withdrawal, 0);
        let (token_address, withdrawal_amount) =
            updated_dictionary.withdraw_fees_and_save_in_db(&db, &address).unwrap();
        assert_eq!(withdrawal_amount, expected_fee);
        assert_eq!(token_address, expected_token_address);
        let dictionary_from_db = EthEvmTokenDictionary::get_from_db(&db).unwrap();
        let entry_after = dictionary_from_db.get_entry_via_address(&address).unwrap();
        assert_eq!(entry_after.accrued_fees, U256::zero());
        assert!(entry_after.last_withdrawal >= timestamp);
    }

    fn get_pnt_address() -> EthAddress {
        EthAddress::from_slice(&hex::decode("89ab32156e46f46d02ade3fecbe5fc4243b9aaed").unwrap())
    }

    fn get_pnt_dictionary_entry() -> EthEvmTokenDictionaryEntry {
        let dictionary = get_sample_eth_evm_dictionary();
        dictionary.get_entry_via_address(&get_pnt_address()).unwrap()
    }

    #[test]
    fn should_add_entry_and_update_in_db() {
        let db = get_test_database();
        let dictionary = EthEvmTokenDictionary::new(vec![]);
        let entry = get_pnt_dictionary_entry();
        dictionary.add_and_update_in_db(entry.clone(), &db).unwrap();
        let dictionary_from_db = EthEvmTokenDictionary::get_from_db(&db).unwrap();
        assert!(dictionary_from_db.contains(&entry));
    }

    #[test]
    fn should_remove_entry_via_eth_address_and_update_in_db() {
        let db = get_test_database();
        let dictionary = get_sample_eth_evm_dictionary();
        let address = get_pnt_address();
        let entry = get_pnt_dictionary_entry();
        dictionary
            .remove_entry_via_eth_address_and_update_in_db(&address, &db)
            .unwrap();
        let dictionary_from_db = EthEvmTokenDictionary::get_from_db(&db).unwrap();
        assert!(!dictionary_from_db.contains(&entry));
    }

    #[test]
    fn should_replace_entry() {
        let new_accrued_fees = U256::from(1337);
        let dictionary = get_sample_eth_evm_dictionary();
        let pnt_address = get_pnt_address();
        let entry_before = dictionary.get_entry_via_address(&pnt_address).unwrap();
        assert_eq!(entry_before.accrued_fees, U256::zero());
        let entry_after = entry_before.add_to_accrued_fees(new_accrued_fees);
        assert_eq!(entry_after.accrued_fees, new_accrued_fees);
        let final_dictionary = dictionary.replace_entry(&entry_before, entry_after);
        let final_entry = final_dictionary.get_entry_via_address(&pnt_address).unwrap();
        assert_eq!(final_entry.accrued_fees, new_accrued_fees);
    }

    #[test]
    fn should_increment_accrued_fees_and_save_in_db() {
        let db = get_test_database();
        let dictionary = get_sample_eth_evm_dictionary();
        let fee_1 = U256::from(666);
        let fee_2 = U256::from(1337);
        let address_1 = EthAddress::from_slice(&hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap());
        let address_2 = EthAddress::from_slice(&hex::decode("888888888889c00c67689029d7856aac1065ec11").unwrap());
        let fee_tuples = vec![(address_1, fee_1), (address_2, fee_2)];
        let entry_1_before = dictionary.get_entry_via_address(&address_1).unwrap();
        let entry_2_before = dictionary.get_entry_via_address(&address_2).unwrap();
        assert_eq!(entry_1_before.accrued_fees, U256::zero());
        assert_eq!(entry_2_before.accrued_fees, U256::zero());
        assert_eq!(entry_1_before.last_withdrawal, 0);
        assert_eq!(entry_2_before.last_withdrawal, 0);
        dictionary
            .increment_accrued_fees_and_save_in_db(&db, fee_tuples)
            .unwrap();
        let result = EthEvmTokenDictionary::get_from_db(&db).unwrap();
        let entry_1_after = result.get_entry_via_address(&address_1).unwrap();
        let entry_2_after = result.get_entry_via_address(&address_2).unwrap();
        assert_eq!(entry_1_after.accrued_fees, fee_1);
        assert_eq!(entry_2_after.accrued_fees, fee_2);
    }

    #[test]
    fn incrementing_accrued_fees_by_0_and_saving_in_db_should_work() {
        let db = get_test_database();
        let dictionary = get_sample_eth_evm_dictionary();
        let fee_1 = U256::from(0);
        let fee_2 = U256::from(1337);
        let address_1 = EthAddress::from_slice(&hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap());
        let address_2 = EthAddress::from_slice(&hex::decode("888888888889c00c67689029d7856aac1065ec11").unwrap());
        let fee_tuples = vec![(address_1, fee_1), (address_2, fee_2)];
        let entry_1_before = dictionary.get_entry_via_address(&address_1).unwrap();
        let entry_2_before = dictionary.get_entry_via_address(&address_2).unwrap();
        assert_eq!(entry_1_before.accrued_fees, U256::zero());
        assert_eq!(entry_2_before.accrued_fees, U256::zero());
        assert_eq!(entry_1_before.last_withdrawal, 0);
        assert_eq!(entry_2_before.last_withdrawal, 0);
        dictionary
            .increment_accrued_fees_and_save_in_db(&db, fee_tuples)
            .unwrap();
        let result = EthEvmTokenDictionary::get_from_db(&db).unwrap();
        let entry_1_after = result.get_entry_via_address(&address_1).unwrap();
        let entry_2_after = result.get_entry_via_address(&address_2).unwrap();
        assert_eq!(entry_1_after.accrued_fees, fee_1);
        assert_eq!(entry_2_after.accrued_fees, fee_2);
    }

    #[test]
    fn dictionary_entry_with_different_decimals_should_require_decimal_conversion() {
        let entry = get_dictionary_entry_with_different_decimals();
        assert_ne!(entry.eth_token_decimals, entry.evm_token_decimals);
        let expected_result = true;
        let result = entry.require_decimal_conversion();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn dictionary_entry_with_same_decimals_not_should_require_decimal_conversion() {
        let entry = get_dictionary_entry_with_same_decimals();
        assert_eq!(entry.eth_token_decimals, entry.evm_token_decimals);
        let expected_result = false;
        let result = entry.require_decimal_conversion();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_eth_token_decimals_if_set() {
        let entry = get_dictionary_entry_with_different_decimals();
        let result = entry.get_eth_token_decimals().unwrap();
        let expected_result = 8;
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_evm_token_decimals_if_set() {
        let entry = get_dictionary_entry_with_different_decimals();
        let result = entry.get_evm_token_decimals().unwrap();
        let expected_result = 18;
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_fail_to_get_decimals_if_none_set() {
        let entry = get_dictionary_entry_with_no_decimals();
        let expected_err = format!("Dictionary entry does NOT have ETH token decimals set! {:?}", entry);
        match entry.get_eth_token_decimals() {
            Ok(_) => panic!("Should not have succeeded!"),
            Err(AppError::Custom(err)) => assert_eq!(err, expected_err),
            Err(_) => panic!("Wrong error received!"),
        }
    }

    #[test]
    fn should_convert_evm_amount_to_eth_amount() {
        let amounts = vec![
            U256::from_dec_str("0").unwrap(),
            U256::from_dec_str("1").unwrap(),
            U256::from_dec_str("12").unwrap(),
            U256::from_dec_str("123").unwrap(),
            U256::from_dec_str("1234").unwrap(),
            U256::from_dec_str("12345").unwrap(),
            U256::from_dec_str("123456").unwrap(),
            U256::from_dec_str("1234567").unwrap(),
            U256::from_dec_str("12345678").unwrap(),
            U256::from_dec_str("123456789").unwrap(),
            U256::from_dec_str("1234567891").unwrap(),
            U256::from_dec_str("12345678912").unwrap(),
            U256::from_dec_str("123456789123").unwrap(),
            U256::from_dec_str("1234567891234").unwrap(),
            U256::from_dec_str("12345678912345").unwrap(),
            U256::from_dec_str("123456789123456").unwrap(),
            U256::from_dec_str("1234567891234567").unwrap(),
            U256::from_dec_str("12345678912345678").unwrap(),
            U256::from_dec_str("123456789123456789").unwrap(),
            U256::from_dec_str("1234567891234567891").unwrap(),
            U256::from_dec_str("12345678912345678912").unwrap(),
        ];
        let expected_results = vec![
            U256::from_dec_str("0").unwrap(),
            U256::from_dec_str("0").unwrap(),
            U256::from_dec_str("0").unwrap(),
            U256::from_dec_str("0").unwrap(),
            U256::from_dec_str("0").unwrap(),
            U256::from_dec_str("0").unwrap(),
            U256::from_dec_str("0").unwrap(),
            U256::from_dec_str("0").unwrap(),
            U256::from_dec_str("0").unwrap(),
            U256::from_dec_str("0").unwrap(),
            U256::from_dec_str("0").unwrap(),
            U256::from_dec_str("1").unwrap(),
            U256::from_dec_str("12").unwrap(),
            U256::from_dec_str("123").unwrap(),
            U256::from_dec_str("1234").unwrap(),
            U256::from_dec_str("12345").unwrap(),
            U256::from_dec_str("123456").unwrap(),
            U256::from_dec_str("1234567").unwrap(),
            U256::from_dec_str("12345678").unwrap(),
            U256::from_dec_str("123456789").unwrap(),
            U256::from_dec_str("1234567891").unwrap(),
        ];
        let entry = get_dictionary_entry_with_different_decimals();
        let expected_eth_token_decimals = 8;
        let expected_evm_token_decimals = 18;
        let eth_token_decimals = entry.get_eth_token_decimals().unwrap();
        let evm_token_decimals = entry.get_evm_token_decimals().unwrap();
        assert_eq!(eth_token_decimals, expected_eth_token_decimals);
        assert_eq!(evm_token_decimals, expected_evm_token_decimals);
        amounts.iter().enumerate().for_each(|(i, amount)| {
            let result = entry.convert_evm_amount_to_eth_amount(*amount).unwrap();
            let expected_result = expected_results[i];
            assert_eq!(result, expected_result);
        });
    }

    #[test]
    fn should_convert_eth_amount_to_evm_amount() {
        let amounts = vec![
            U256::from_dec_str("0").unwrap(),
            U256::from_dec_str("1").unwrap(),
            U256::from_dec_str("12").unwrap(),
            U256::from_dec_str("123").unwrap(),
            U256::from_dec_str("1234").unwrap(),
            U256::from_dec_str("12345").unwrap(),
            U256::from_dec_str("123456").unwrap(),
            U256::from_dec_str("1234567").unwrap(),
            U256::from_dec_str("12345678").unwrap(),
            U256::from_dec_str("123456789").unwrap(),
            U256::from_dec_str("1234567891").unwrap(),
        ];
        let expected_results = vec![
            U256::from_dec_str("0").unwrap(),
            U256::from_dec_str("10000000000").unwrap(),
            U256::from_dec_str("120000000000").unwrap(),
            U256::from_dec_str("1230000000000").unwrap(),
            U256::from_dec_str("12340000000000").unwrap(),
            U256::from_dec_str("123450000000000").unwrap(),
            U256::from_dec_str("1234560000000000").unwrap(),
            U256::from_dec_str("12345670000000000").unwrap(),
            U256::from_dec_str("123456780000000000").unwrap(),
            U256::from_dec_str("1234567890000000000").unwrap(),
            U256::from_dec_str("12345678910000000000").unwrap(),
        ];
        let entry = get_dictionary_entry_with_different_decimals();
        let expected_eth_token_decimals = 8;
        let expected_evm_token_decimals = 18;
        let eth_token_decimals = entry.get_eth_token_decimals().unwrap();
        let evm_token_decimals = entry.get_evm_token_decimals().unwrap();
        assert_eq!(eth_token_decimals, expected_eth_token_decimals);
        assert_eq!(evm_token_decimals, expected_evm_token_decimals);
        amounts.iter().enumerate().for_each(|(i, amount)| {
            let result = entry.convert_eth_amount_to_evm_amount(*amount).unwrap();
            let expected_result = expected_results[i];
            assert_eq!(result, expected_result);
        });
    }
}
