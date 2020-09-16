use std::str::FromStr;
use eos_primitives::AccountName as EosAccountName;
use crate::{
    types::{
        Bytes,
        Result,
    },
    chains::btc::deposit_address_info::{
        DepositInfoList,
        DepositAddressInfoJson,
        DepositAddressInfoJsonList,
    },
    btc_on_eos::{
        utils::convert_u64_to_eos_asset,
        constants::{
            SAFE_BTC_ADDRESS,
            SAFE_EOS_ADDRESS,
        },
    },
};
use bitcoin::{
    hashes::sha256d,
    util::address::Address as BtcAddress,
    blockdata::block::Block as BtcBlock,
};

pub use bitcoin::blockdata::transaction::Transaction as BtcTransaction;

pub type BtcTransactions = Vec<BtcTransaction>;
pub type MintingParams = Vec<MintingParamStruct>;
pub type BtcRecipientsAndAmounts = Vec<BtcRecipientAndAmount>;

#[derive(Debug, Serialize, Deserialize)]
pub struct BtcTxInfo {
    pub btc_tx_hex: String,
    pub btc_tx_amount: u64,
    pub btc_tx_hash: String,
    pub signature_timestamp: u64,
    pub btc_account_nonce: u64,
    pub btc_tx_recipient: String,
    pub originating_tx_hash: String,
    pub originating_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcRecipientAndAmount {
    pub amount: u64,
    pub recipient: BtcAddress,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmissionMaterial {
    pub ref_block_num: u16,
    pub ref_block_prefix: u32,
    pub block_and_id: BtcBlockAndId,
}

impl BtcRecipientAndAmount {
    pub fn new(recipient: &str, amount: u64) -> Result<Self> {
        Ok(
            BtcRecipientAndAmount {
                amount,
                recipient: match BtcAddress::from_str(recipient) {
                    Ok(address) => address,
                    Err(error) => {
                        info!(
                            "✔ Error parsing BTC address for recipient: {}",
                            error
                        );
                        info!(
                            "✔ Defaulting to SAFE BTC address: {}",
                            SAFE_BTC_ADDRESS,
                        );
                        BtcAddress::from_str(SAFE_BTC_ADDRESS)?
                    }
                }
            }
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcBlockInDbFormat {
    pub height: u64,
    pub block: BtcBlock,
    pub id: sha256d::Hash,
    pub extra_data: Bytes,
    pub minting_params: MintingParams,
}

impl BtcBlockInDbFormat {
    pub fn new(
        height: u64,
        id: sha256d::Hash,
        minting_params: MintingParams,
        block: BtcBlock,
        extra_data: Bytes,
    ) -> Result<Self> {
        Ok(BtcBlockInDbFormat{ id, block, height, minting_params, extra_data })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintingParamStruct {
    pub amount: String,
    pub to: String,
    pub originating_tx_hash: String,
    pub originating_tx_address: String,
}

impl MintingParamStruct {
    pub fn new(
        amount: u64,
        to: String,
        originating_tx_hash: sha256d::Hash,
        originating_tx_address: BtcAddress,
        symbol: &str,
    ) -> MintingParamStruct {
        MintingParamStruct {
            to: match EosAccountName::from_str(&to) {
                Ok(_) => to,
                Err(_) => {
                    info!("✘ Error converting '{}' to EOS address!", to);
                    info!(
                        "✔ Defaulting to safe EOS address: '{}'",
                        SAFE_EOS_ADDRESS
                    );
                    SAFE_EOS_ADDRESS.to_string()
                }
            },
            amount: convert_u64_to_eos_asset(amount, symbol),
            originating_tx_hash: originating_tx_hash.to_string(),
            originating_tx_address: originating_tx_address.to_string(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct SubmissionMaterialJson {
    pub ref_block_num: u16,
    pub block: BtcBlockJson,
    pub ref_block_prefix: u32,
    pub transactions: Vec<String>,
    pub deposit_address_list: DepositAddressInfoJsonList,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BtcBlockJson {
    pub bits: u32,
    pub id: String,
    pub nonce: u32,
    pub version: u32,
    pub height: u64,
    pub timestamp: u32,
    pub merkle_root: String,
    pub previousblockhash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcBlockAndId {
    pub height: u64,
    pub block: BtcBlock,
    pub id: sha256d::Hash,
    pub deposit_address_list: DepositInfoList,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BtcUtxoAndValue {
    pub value: u64,
    pub serialized_utxo: Bytes,
    pub maybe_extra_data: Option<Bytes>,
    pub maybe_pointer: Option<sha256d::Hash>,
    pub maybe_deposit_info_json: Option<DepositAddressInfoJson>,
}
