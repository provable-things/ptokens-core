use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::blockdata::transaction::Transaction as BtcTransaction;

use crate::{
    btc_on_eth::eth::redeem_info::{BtcOnEthRedeemInfo, BtcOnEthRedeemInfos},
    chains::{
        btc::{btc_database_utils::get_btc_account_nonce_from_db, btc_utils::get_hex_tx_from_signed_btc_tx},
        eth::{eth_database_utils::get_eth_latest_block_from_db, eth_state::EthState},
    },
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct BtcTxInfo {
    pub btc_tx_hex: String,
    pub btc_tx_hash: String,
    pub btc_tx_amount: u64,
    pub btc_account_nonce: u64,
    pub btc_tx_recipient: String,
    pub signature_timestamp: u64,
    pub originating_tx_hash: String,
    pub originating_address: String,
}

impl BtcTxInfo {
    pub fn new(btc_tx: &BtcTransaction, redeem_info: &BtcOnEthRedeemInfo, btc_account_nonce: u64) -> Result<BtcTxInfo> {
        Ok(BtcTxInfo {
            btc_account_nonce,
            btc_tx_hash: btc_tx.txid().to_string(),
            btc_tx_amount: redeem_info.amount.as_u64(),
            btc_tx_hex: get_hex_tx_from_signed_btc_tx(&btc_tx),
            btc_tx_recipient: redeem_info.recipient.clone(),
            originating_address: format!("0x{}", hex::encode(redeem_info.from.as_bytes())),
            originating_tx_hash: format!("0x{}", hex::encode(redeem_info.originating_tx_hash.as_bytes())),
            signature_timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EthOutput {
    pub eth_latest_block_number: usize,
    pub btc_signed_transactions: Vec<BtcTxInfo>,
}

pub fn get_btc_signed_tx_info_from_btc_txs(
    btc_account_nonce: u64,
    btc_txs: Vec<BtcTransaction>,
    redeem_info: &BtcOnEthRedeemInfos,
) -> Result<Vec<BtcTxInfo>> {
    info!("✔ Getting BTC tx info from BTC txs...");
    let start_nonce = btc_account_nonce - btc_txs.len() as u64;
    btc_txs
        .iter()
        .enumerate()
        .map(|(i, btc_tx)| BtcTxInfo::new(btc_tx, &redeem_info.0[i], start_nonce + i as u64))
        .collect::<Result<Vec<BtcTxInfo>>>()
}

pub fn get_eth_output_json<D>(state: EthState<D>) -> Result<String>
where
    D: DatabaseInterface,
{
    info!("✔ Getting ETH output json...");
    let output = serde_json::to_string(&EthOutput {
        eth_latest_block_number: get_eth_latest_block_from_db(&state.db)?.get_block_number()?.as_usize(),
        btc_signed_transactions: match state.btc_transactions {
            Some(txs) => get_btc_signed_tx_info_from_btc_txs(
                get_btc_account_nonce_from_db(&state.db)?,
                txs,
                &state.btc_on_eth_redeem_infos,
            )?,
            None => vec![],
        },
    })?;
    info!("✔ ETH Output: {}", output);
    Ok(output)
}
