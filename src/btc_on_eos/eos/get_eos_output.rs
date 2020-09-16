use bitcoin::blockdata::transaction::Transaction as BtcTransaction;
use std::time::{
    SystemTime,
    UNIX_EPOCH
};
use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::{
        btc::{
            btc_types::BtcTxInfo,
            btc_utils::get_hex_tx_from_signed_btc_tx,
            btc_database_utils::get_btc_account_nonce_from_db,
        },
        eos::{
            eos_state::EosState,
            eos_types::RedeemParams,
        },
    },
};

#[derive(Debug, Serialize, Deserialize)]
pub struct EosOutput {
    pub btc_signed_transactions: Vec<BtcTxInfo>,
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
                btc_tx_amount: redeem_params.amount,
                btc_tx_hash: btc_tx.txid().to_string(),
                btc_tx_hex: get_hex_tx_from_signed_btc_tx(&btc_tx),
                btc_tx_recipient: redeem_params.recipient.clone(),
                originating_address: format!("{}", redeem_params.from),
                originating_tx_hash: format!(
                    "{}",
                    redeem_params.originating_tx_id
                ),
                signature_timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_secs(),
            }
        )
    }
}

pub fn get_btc_signed_tx_info_from_btc_txs(
    btc_account_nonce: u64,
    btc_txs: &[BtcTransaction],
    redeem_params: &[RedeemParams],
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

pub fn get_eos_output<D>(
    state: EosState<D>
) -> Result<String>
    where D: DatabaseInterface
{
    info!("✔ Getting EOS output json...");
    let output = serde_json::to_string(
        &EosOutput {
            btc_signed_transactions: match &state.signed_txs.len() {
                0 => vec![],
                _ => get_btc_signed_tx_info_from_btc_txs(
                    get_btc_account_nonce_from_db(&state.db)?,
                    &state.signed_txs,
                    &state.redeem_params,
                )?,
            }
        }
    )?;
    info!("✔ EOS output: {}", output);
    Ok(output)
}
