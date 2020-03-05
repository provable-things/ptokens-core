use bitcoin::blockdata::transaction::Transaction as BtcTransaction;
use std::time::{
    SystemTime,
    UNIX_EPOCH
};
use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc::{
        btc_utils::get_hex_tx_from_signed_btc_tx,
        btc_database_utils::get_btc_account_nonce_from_db,
    },
    eth::{
        eth_state::EthState,
        eth_types::RedeemParams,
        eth_database_utils::get_eth_latest_block_from_db,
    },
};

#[derive(Debug, Serialize, Deserialize)]
struct BtcTxInfo {
    btc_tx_hex: String,
    btc_tx_hash: String,
    btc_tx_amount: u64,
    btc_account_nonce: u64,
    btc_tx_recipient: String,
    signature_timestamp: u64,
    originating_tx_hash: String,
    originating_address: String,
}

impl BtcTxInfo {
    pub fn new(
        btc_tx: &BtcTransaction,
        redeem_params: &RedeemParams,
        btc_account_nonce: u64,
    ) -> Result<BtcTxInfo> {
        Ok(
            BtcTxInfo {
                btc_account_nonce,
                btc_tx_hash: btc_tx.txid().to_string(),
                btc_tx_amount: redeem_params.amount.as_u64(),
                btc_tx_hex: get_hex_tx_from_signed_btc_tx(&btc_tx),
                btc_tx_recipient: redeem_params.recipient.clone(),
                originating_address: format!(
                    "0x{}",
                    hex::encode(redeem_params.from.as_bytes())
                ),
                originating_tx_hash: format!(
                    "0x{}",
                    hex::encode(redeem_params.originating_tx_hash.as_bytes())
                ),
                signature_timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_secs(),
            }
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct EthOutput {
    eth_latest_block_number: usize,
    btc_signed_transactions: Vec<BtcTxInfo>,
}

fn get_btc_signed_tx_info_from_btc_txs(
    btc_account_nonce: u64,
    btc_txs: Vec<BtcTransaction>,
    redeem_params: &Vec<RedeemParams>,
) -> Result<Vec<BtcTxInfo>> {
    info!("✔ Getting BTC tx info from BTC txs...");
    let start_nonce = btc_account_nonce - btc_txs.len() as u64;
    btc_txs
        .iter()
        .enumerate()
        .map(|(i, btc_tx)|
            BtcTxInfo::new(
                btc_tx,
                &redeem_params[i],
                start_nonce + i as u64,
            )
        )
        .collect::<Result<Vec<BtcTxInfo>>>()
}

pub fn get_eth_output_json<D>(state: EthState<D>) -> Result<String>
    where D: DatabaseInterface
{
    info!("✔ Getting ETH output json...");
    let output = serde_json::to_string(
        &EthOutput {
            eth_latest_block_number:
                get_eth_latest_block_from_db(&state.db)?
                    .block
                    .number
                    .as_usize(),
            btc_signed_transactions: match state.btc_transactions {
                Some(txs) => get_btc_signed_tx_info_from_btc_txs(
                    get_btc_account_nonce_from_db(&state.db)?,
                    txs,
                    &state.redeem_params,
                )?,
                None => vec![],
            }
        }
    )?;
    info!("✔ ETH Output: {}", output);
    Ok(output)
}
