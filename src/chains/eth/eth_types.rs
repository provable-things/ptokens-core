use std::collections::HashMap;

use ethereum_types::{Address, H256};

use crate::{
    chains::eth::{
        any_sender::relay_transaction::RelayTransaction,
        eth_crypto::{eth_private_key::EthPrivateKey, eth_transaction::EthTransaction},
        trie_nodes::Node,
    },
    types::Bytes,
};

pub type EthHash = H256;
pub type EthAddress = Address;
pub type NodeStack = Vec<Node>;
pub type EthSignature = [u8; 65];
pub type EthSignedTransaction = String;
pub type ChildNodes = [Option<Bytes>; 16];
pub type TrieHashMap = HashMap<H256, Bytes>;
pub type EthTransactions = Vec<EthTransaction>;
pub type RelayTransactions = Vec<RelayTransaction>;

#[derive(Debug)]
pub struct EthSigningParams {
    pub chain_id: u8,
    pub gas_price: u64,
    pub eth_account_nonce: u64,
    pub eth_private_key: EthPrivateKey,
    pub smart_contract_address: EthAddress,
}

#[derive(Debug)]
pub struct AnySenderSigningParams {
    pub chain_id: u8,
    pub any_sender_nonce: u64,
    pub eth_private_key: EthPrivateKey,
    pub public_eth_address: EthAddress,
    pub erc777_proxy_address: EthAddress,
}
