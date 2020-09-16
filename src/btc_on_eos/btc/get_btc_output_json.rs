use std::time::{
    SystemTime,
    UNIX_EPOCH
};
use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::{
        utils::convert_eos_asset_to_u64,
        eos::{
            eos_types::EosSignedTransaction,
            eos_database_utils::get_eos_account_nonce_from_db,
        },
        btc::{
            btc_state::BtcState,
            btc_types::MintingParamStruct,
            btc_database_utils::{
                get_btc_canon_block_from_db,
                get_btc_latest_block_from_db,
            },
        },
    },
};

#[derive(Debug, Serialize, Deserialize)]
pub struct TxInfo {
    pub eos_tx: String,
    pub eos_tx_amount: u64,
    pub eos_account_nonce: u64,
    pub eos_tx_recipient: String,
    pub eos_tx_signature: String,
    pub signature_timestamp: u64,
    pub originating_tx_hash: String,
    pub originating_address: String,
}

impl TxInfo {
    pub fn new(
        tx: &EosSignedTransaction,
        minting_param_struct: &MintingParamStruct,
        eos_account_nonce: u64,
    ) -> Result<TxInfo> {
        Ok(
            TxInfo {
                eos_tx: tx.transaction.clone(),
                eos_tx_signature: tx.signature.clone(),
                eos_tx_recipient: tx.recipient.clone(),
                eos_account_nonce,
                eos_tx_amount:
                    convert_eos_asset_to_u64(&tx.amount)?,
                originating_tx_hash:
                    minting_param_struct.originating_tx_hash.clone(),
                originating_address:
                    minting_param_struct.originating_tx_address.clone(),
                signature_timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_secs(),
            }
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BtcOutput {
    pub btc_latest_block_number: u64,
    pub eos_signed_transactions: Vec<TxInfo>,
}

pub fn get_eos_signed_tx_info_from_eth_txs(
    txs: &[EosSignedTransaction],
    minting_params: &[MintingParamStruct],
    eos_account_nonce: u64,
) -> Result<Vec<TxInfo>> {
    info!("✔ Getting tx info from txs in state...");
    let start_nonce = eos_account_nonce - txs.len() as u64;
    txs
        .iter()
        .enumerate()
        .map(|(i, tx)|
            TxInfo::new(tx, &minting_params[i], start_nonce + i as u64)
        )
        .collect::<Result<Vec<TxInfo>>>()
}

pub fn create_btc_output_json_and_put_in_state<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Getting BTC output json and putting in state...");
    Ok(serde_json::to_string(
        &BtcOutput {
            btc_latest_block_number: get_btc_latest_block_from_db(&state.db)?
                .height,
            eos_signed_transactions: match &state.signed_txs.len() {
                0 => vec![],
                _ =>
                    get_eos_signed_tx_info_from_eth_txs(
                        &state.signed_txs,
                        &get_btc_canon_block_from_db(&state.db)?.minting_params,
                        get_eos_account_nonce_from_db(&state.db)?,
                    )?,
            }
        }
    )?)
        .and_then(|output| state.add_output_json_string(output))
}

pub fn get_btc_output_as_string<D>(
    state: BtcState<D>
) -> Result<String>
    where D: DatabaseInterface
{
    info!("✔ Getting BTC output as string...");
    let output = state.get_output_json_string()?.to_string();
    info!("✔ BTC Output: {}", output);
    Ok(output)
}
