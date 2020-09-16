use std::collections::HashMap;
use ethereum_types::{
    H256,
    U256,
    Bloom,
    Address,
};
use crate::{
    types::Bytes,
    btc_on_eth::eth::trie_nodes::Node,
    chains::eth::{
        any_sender::relay_transaction::RelayTransaction,
        eth_crypto::{
            eth_private_key::EthPrivateKey,
            eth_transaction::EthTransaction,
        },
    },
};

pub type EthHash = H256;
pub type EthAddress = Address;
pub type EthTopic = EthHash;
pub type NodeStack = Vec<Node>;
pub type EthSignature = [u8; 65];
pub type EthReceipts = Vec<EthReceipt>;
pub type EthSignedTransaction = String;
pub type ChildNodes = [Option<Bytes>; 16];
pub type TrieHashMap = HashMap<H256, Bytes>;
pub type EthTransactions = Vec<EthTransaction>;
pub type RelayTransactions = Vec<RelayTransaction>;

#[cfg(test)]
pub type EthTopics = Vec<EthTopic>;
#[cfg(test)]
pub type EthLogs = Vec<EthLog>;

#[derive(Debug)]
pub struct EthSigningParams {
    pub chain_id: u8,
    pub gas_price: u64,
    pub eth_account_nonce: u64,
    pub eth_private_key: EthPrivateKey,
    pub ptoken_contract_address: EthAddress,
}

#[derive(Debug)]
pub struct AnySenderSigningParams {
    pub chain_id: u8,
    pub any_sender_nonce: u64,
    pub eth_private_key: EthPrivateKey,
    pub public_eth_address: EthAddress,
    pub erc777_proxy_address: EthAddress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemParams {
    pub amount: U256,
    pub from: EthAddress,
    pub recipient: String,
    pub originating_tx_hash: EthHash,
}

impl RedeemParams {
    pub fn new(
        amount: U256,
        from: EthAddress,
        recipient: String,
        originating_tx_hash: EthHash,
    ) -> RedeemParams {
        RedeemParams { amount, recipient, originating_tx_hash, from }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct EthBlockAndReceipts {
    pub block: EthBlock,
    pub receipts: Vec<EthReceipt>
}

#[derive(Clone, Debug, Deserialize)]
pub struct EthBlockAndReceiptsJson {
    pub block: EthBlockJson,
    pub receipts: Vec<EthReceiptJson>
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct EthReceipt {
    pub to: Address,
    pub from: Address,
    pub status: bool,
    pub gas_used: U256,
    pub block_hash: H256,
    pub transaction_hash: H256,
    pub cumulative_gas_used: U256,
    pub block_number: U256,
    pub transaction_index: U256,
    pub contract_address: Address,
    pub logs: Vec<EthLog>,
    pub logs_bloom: Bloom,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct EthBlock {
    pub difficulty: U256,
    pub extra_data: Bytes,
    pub gas_limit: U256,
    pub gas_used: U256,
    pub hash: H256,
    pub logs_bloom: Bloom,
    pub miner: Address,
    pub mix_hash: H256,
    pub nonce: Bytes,
    pub number: U256,
    pub parent_hash: H256,
    pub receipts_root: H256,
    pub sha3_uncles: H256,
    pub size: U256,
    pub state_root: H256,
    pub timestamp: U256,
    pub total_difficulty: U256,
    pub transactions: Vec<H256>,
    pub transactions_root: H256,
    pub uncles: Vec<H256>,
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Deserialize)]
pub struct EthBlockJson {
    pub difficulty: String,
    pub extraData: String,
    pub gasLimit: usize,
    pub gasUsed: usize,
    pub hash: String,
    pub logsBloom: String,
    pub miner: String,
    pub mixHash: String,
    pub nonce: String,
    pub number: usize,
    pub parentHash: String,
    pub receiptsRoot: String,
    pub sha3Uncles: String,
    pub size: usize,
    pub stateRoot: String,
    pub timestamp: usize,
    pub totalDifficulty: String,
    pub transactions: Vec<String>,
    pub transactionsRoot: String,
    pub uncles: Vec<String>,
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Deserialize)]
pub struct EthReceiptJson {
    pub from: String,
    pub status: bool,
    pub gasUsed: usize,
    pub blockHash: String,
    pub logsBloom: String,
    pub logs: Vec<EthLogJson>,
    pub blockNumber: usize,
    pub to: serde_json::Value,
    pub transactionHash: String,
    pub transactionIndex: usize,
    pub cumulativeGasUsed: usize,
    pub contractAddress: serde_json::Value,
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Deserialize)]
pub struct EthLogJson {
    pub data: String,
    pub address: String,
    pub topics: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct EthLog {
    pub address: Address,
    pub topics: Vec<H256>,
    pub data: Bytes,
}
