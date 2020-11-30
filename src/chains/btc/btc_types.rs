use std::str::FromStr;
use crate::{
    constants::SAFE_BTC_ADDRESS,
    chains::btc::deposit_address_info::DepositAddressInfoJson,
    types::{
        Bytes,
        Result,
    },
};
pub use bitcoin::{
    hashes::sha256d,
    util::address::Address as BtcAddress,
    consensus::encode::deserialize as btc_deserialize,
    blockdata::{
        block::Block as BtcBlock,
        block::BlockHeader as BtcBlockHeader,
        transaction::Transaction as BtcTransaction,
    },
};

pub type BtcTransactions = Vec<BtcTransaction>;

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
                }
            },
        })
    }
}
