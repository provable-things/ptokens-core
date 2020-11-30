use bitcoin::blockdata::transaction::Transaction as BtcTransaction;
use std::time::{
    SystemTime,
    UNIX_EPOCH
};
use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::{
        eos::eos_state::EosState,
        btc::{
            btc_utils::get_hex_tx_from_signed_btc_tx,
            btc_database_utils::get_btc_account_nonce_from_db,
        },
    },
    btc_on_eos::{
        eos::redeem_info::{
            BtcOnEosRedeemInfo,
            BtcOnEosRedeemInfos,
        },
    },
};

#[derive(Debug, Serialize, Deserialize)]
pub struct EosOutput {
    pub btc_signed_transactions: Vec<BtcTxInfo>,
}

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

impl BtcTxInfo {
    pub fn new(btc_tx: &BtcTransaction, redeem_info: &BtcOnEosRedeemInfo, btc_account_nonce: u64) -> Result<BtcTxInfo> {
        Ok(
            BtcTxInfo {
                btc_account_nonce,
                btc_tx_amount: redeem_info.amount,
                btc_tx_hash: btc_tx.txid().to_string(),
                btc_tx_recipient: redeem_info.recipient.clone(),
                btc_tx_hex: get_hex_tx_from_signed_btc_tx(&btc_tx),
                originating_address: format!("{}", redeem_info.from),
                originating_tx_hash: format!("{}", redeem_info.originating_tx_id),
                signature_timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            }
        )
    }
}

pub fn get_btc_signed_tx_info_from_btc_txs(
    btc_account_nonce: u64,
    btc_txs: &[BtcTransaction],
    redeem_infos: &BtcOnEosRedeemInfos,
) -> Result<Vec<BtcTxInfo>> {
    info!("✔ Getting BTC tx info from BTC txs...");
    let start_nonce = btc_account_nonce - btc_txs.len() as u64;
    btc_txs
        .iter()
        .enumerate()
        .map(|(i, btc_tx)| BtcTxInfo::new(btc_tx, &redeem_infos.0[i], start_nonce + i as u64))
        .collect()
}

pub fn get_eos_output<D>(state: EosState<D>) -> Result<String> where D: DatabaseInterface {
    info!("✔ Getting EOS output json...");
    let output = serde_json::to_string(
        &EosOutput {
            btc_signed_transactions: match &state.btc_on_eos_signed_txs.len() {
                0 => vec![],
                _ => get_btc_signed_tx_info_from_btc_txs(
                    get_btc_account_nonce_from_db(&state.db)?,
                    &state.btc_on_eos_signed_txs,
                    &state.btc_on_eos_redeem_infos,
                )?,
            }
        }
    )?;
    info!("✔ EOS output: {}", output);
    Ok(output)
}
