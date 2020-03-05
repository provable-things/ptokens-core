use std::time::{
    SystemTime,
    UNIX_EPOCH
};
use crate::{
    types::Result,
    traits::DatabaseInterface,
    eth::{
        eth_types::EthTransactions,
        eth_crypto::eth_transaction::EthTransaction,
        eth_database_utils::get_eth_account_nonce_from_db,
    },
    btc::{
        btc_state::BtcState,
        btc_constants::DEFAULT_BTC_ADDRESS,
        btc_types::{
            MintingParams,
            MintingParamStruct,
        },
        btc_database_utils::{
            get_btc_canon_block_from_db,
            get_btc_latest_block_from_db,
        },
    },
};

#[derive(Debug, Serialize, Deserialize)]
struct EthTxInfo {
    eth_tx_hex: String,
    eth_tx_hash: String,
    eth_tx_amount: String,
    eth_account_nonce: u64,
    eth_tx_recipient: String,
    signature_timestamp: u64,
    originating_tx_hash: String,
    originating_address: String,
}

impl EthTxInfo {
    pub fn new(
        eth_tx: &EthTransaction,
        minting_param_struct: &MintingParamStruct,
        eth_account_nonce: u64,
    ) -> Result<EthTxInfo> {
        let default_address = DEFAULT_BTC_ADDRESS.to_string();
        let retrieved_address = minting_param_struct
            .originating_tx_address
            .to_string();
        let address_string = match default_address == retrieved_address {
            false => retrieved_address,
            true => "could not retrieve sender address".to_string(),
        };
        Ok(
            EthTxInfo {
                eth_account_nonce,
                eth_tx_hash: format!("0x{}", eth_tx.get_tx_hash()),
                eth_tx_hex: eth_tx.serialize_hex(),
                originating_address: address_string,
                eth_tx_amount: minting_param_struct.amount.to_string(),
                originating_tx_hash:
                    minting_param_struct.originating_tx_hash.to_string(),
                eth_tx_recipient: format!(
                    "0x{}",
                    hex::encode(minting_param_struct.eth_address.as_bytes())
                ),
                signature_timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_secs(),
            }
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct BtcOutput {
    btc_latest_block_number: u64,
    eth_signed_transactions: Vec<EthTxInfo>,
}

fn get_eth_signed_tx_info_from_eth_txs(
    eth_txs: &EthTransactions,
    minting_params: &MintingParams,
    eth_account_nonce: u64,
) -> Result<Vec<EthTxInfo>> {
    info!("✔ Getting ETH tx info from ETH txs...");
    let start_nonce = eth_account_nonce - eth_txs.len() as u64;
    eth_txs
        .iter()
        .enumerate()
        .map(|(i, tx)|
            EthTxInfo::new(tx, &minting_params[i], start_nonce + i as u64)
        )
        .collect::<Result<Vec<EthTxInfo>>>()
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
            eth_signed_transactions: match &state.eth_signed_txs {
                None => vec![],
                Some(txs) =>
                    get_eth_signed_tx_info_from_eth_txs(
                        txs,
                        &get_btc_canon_block_from_db(&state.db)?.minting_params,
                        get_eth_account_nonce_from_db(&state.db)?,
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
