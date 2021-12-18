use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{
    chains::{
        eos::{eos_database_utils::get_latest_eos_block_number, eos_state::EosState},
        eth::{
            any_sender::relay_transaction::RelayTransaction,
            eth_crypto::eth_transaction::EthTransaction,
            eth_database_utils::{
                get_any_sender_nonce_from_db,
                get_eth_account_nonce_from_db,
                get_latest_eth_block_number,
            },
            eth_traits::EthTxInfoCompatible,
        },
    },
    eos_on_eth::eos::eos_tx_info::{EosOnEthEosTxInfo, EosOnEthEosTxInfos},
    traits::DatabaseInterface,
    types::{NoneError, Result},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct EosOutput {
    pub eos_latest_block_number: u64,
    pub eth_signed_transactions: Vec<EthTxInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EthTxInfo {
    pub _id: String,
    pub broadcast: bool,
    pub eth_tx_hash: String,
    pub eth_tx_amount: String,
    pub eth_tx_recipient: String,
    pub witnessed_timestamp: u64,
    pub host_token_address: String,
    pub originating_tx_hash: String,
    pub originating_address: String,
    pub native_token_address: String,
    pub eth_signed_tx: Option<String>,
    pub any_sender_nonce: Option<u64>,
    pub eth_account_nonce: Option<u64>,
    pub eth_latest_block_number: usize,
    pub broadcast_tx_hash: Option<String>,
    pub broadcast_timestamp: Option<String>,
    pub any_sender_tx: Option<RelayTransaction>,
}

impl EthTxInfo {
    pub fn new<T: EthTxInfoCompatible>(
        tx: &T,
        tx_info: &EosOnEthEosTxInfo,
        maybe_nonce: Option<u64>,
        eth_latest_block_number: usize,
    ) -> Result<EthTxInfo> {
        let nonce = maybe_nonce.ok_or(NoneError("No nonce for eth output!"))?;
        Ok(EthTxInfo {
            eth_latest_block_number,
            broadcast: false,
            broadcast_tx_hash: None,
            broadcast_timestamp: None,
            eth_signed_tx: tx.eth_tx_hex(),
            any_sender_tx: tx.any_sender_tx(),
            _id: if tx.is_any_sender() {
                format!("peos-on-eth-any-sender-{}", nonce)
            } else {
                format!("peos-on-eth-eth-{}", nonce)
            },
            eth_tx_amount: tx_info.amount.to_string(),
            eth_tx_hash: format!("0x{}", tx.get_tx_hash()),
            originating_address: tx_info.from.to_string(),
            host_token_address: format!("0x{}", hex::encode(&tx_info.eth_token_address)),
            originating_tx_hash: tx_info.originating_tx_id.to_string(),
            any_sender_nonce: if tx.is_any_sender() { maybe_nonce } else { None },
            eth_account_nonce: if tx.is_any_sender() { None } else { maybe_nonce },
            witnessed_timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            eth_tx_recipient: format!("0x{}", hex::encode(tx_info.recipient.as_bytes())),
            native_token_address: tx_info.eos_token_address.to_string(),
        })
    }
}

pub fn get_eth_signed_tx_info_from_eth_txs(
    txs: &[EthTransaction],
    tx_info: &EosOnEthEosTxInfos,
    eth_account_nonce: u64,
    use_any_sender_tx_type: bool,
    any_sender_nonce: u64,
    eth_latest_block_number: usize,
) -> Result<Vec<EthTxInfo>> {
    let start_nonce = if use_any_sender_tx_type {
        info!("✔ Getting AnySender tx info from ETH txs...");
        any_sender_nonce - txs.len() as u64
    } else {
        info!("✔ Getting ETH tx info from ETH txs...");
        eth_account_nonce - txs.len() as u64
    };
    txs.iter()
        .enumerate()
        .map(|(i, tx)| EthTxInfo::new(tx, &tx_info[i], Some(start_nonce + i as u64), eth_latest_block_number))
        .collect::<Result<Vec<EthTxInfo>>>()
}

pub fn get_eos_output<D>(state: EosState<D>) -> Result<String>
where
    D: DatabaseInterface,
{
    info!("✔ Getting EOS output json...");
    let output = serde_json::to_string(&EosOutput {
        eos_latest_block_number: get_latest_eos_block_number(&state.db)?,
        eth_signed_transactions: match state.eth_signed_txs.len() {
            0 => vec![],
            _ => get_eth_signed_tx_info_from_eth_txs(
                &state.eth_signed_txs,
                &state.eos_on_eth_eos_tx_infos,
                get_eth_account_nonce_from_db(&state.db)?,
                false, // TODO Get this from state submission material when/if we support AnySender
                get_any_sender_nonce_from_db(&state.db)?,
                get_latest_eth_block_number(&state.db)?,
            )?,
        },
    })?;
    info!("✔ EOS output: {}", output);
    Ok(output)
}
