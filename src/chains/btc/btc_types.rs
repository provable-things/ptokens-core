use std::str::FromStr;

pub use bitcoin::{
    blockdata::{
        block::{Block as BtcBlock, BlockHeader as BtcBlockHeader},
        transaction::Transaction as BtcTransaction,
    },
    consensus::encode::deserialize as btc_deserialize,
    hashes::sha256d,
    util::address::Address as BtcAddress,
};

use crate::{
    chains::btc::{btc_constants::BTC_PUB_KEY_SLICE_LENGTH, deposit_address_info::DepositAddressInfoJson},
    constants::SAFE_BTC_ADDRESS,
    types::{Byte, Bytes, Result},
};

pub type BtcTransactions = Vec<BtcTransaction>;
pub type BtcPubKeySlice = [Byte; BTC_PUB_KEY_SLICE_LENGTH];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BtcUtxoAndValue {
    pub value: u64,
    pub serialized_utxo: Bytes,
    pub maybe_extra_data: Option<Bytes>,
    pub maybe_pointer: Option<sha256d::Hash>,
    pub maybe_deposit_info_json: Option<DepositAddressInfoJson>,
}

pub type BtcRecipientsAndAmounts = Vec<BtcRecipientAndAmount>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcRecipientAndAmount {
    pub amount: u64,
    pub recipient: BtcAddress,
}

impl BtcRecipientAndAmount {
    pub fn new(recipient: &str, amount: u64) -> Result<Self> {
        Ok(BtcRecipientAndAmount {
            amount,
            recipient: match BtcAddress::from_str(recipient) {
                Ok(address) => address,
                Err(error) => {
                    info!("✔ Error parsing BTC address for recipient: {}", error);
                    info!("✔ Defaulting to SAFE BTC address: {}", SAFE_BTC_ADDRESS);
                    BtcAddress::from_str(SAFE_BTC_ADDRESS)?
                },
            },
        })
    }
}
