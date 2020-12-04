use crate::{
    chains::eth::{
        any_sender::{
            relay_contract::RelayContract,
            serde::{compensation, data},
        },
        eth_constants::{ETH_MAINNET_CHAIN_ID, ETH_ROPSTEN_CHAIN_ID},
        eth_contracts::erc777_proxy::encode_mint_by_proxy_tx_data,
        eth_crypto::eth_private_key::EthPrivateKey,
        eth_traits::EthTxInfoCompatible,
    },
    types::{Byte, Bytes, Result},
};
use ethabi::{encode, Token};
use ethereum_types::{Address as EthAddress, Signature as EthSignature, U256};
use rlp::RlpStream;

pub const ANY_SENDER_GAS_LIMIT: u32 = 300_000;
pub const ANY_SENDER_MAX_DATA_LEN: usize = 3_000;
pub const ANY_SENDER_MAX_GAS_LIMIT: u32 = 3_000_000;
pub const ANY_SENDER_DEFAULT_DEADLINE: Option<u64> = None;
pub const ANY_SENDER_MAX_COMPENSATION_WEI: u64 = 49_999_999_999_999_999;

/// An AnySender relay transaction. It is very similar
/// to a normal transaction except for a few fields.
/// The schema can be found [here](https://github.com/PISAresearch/docs.any.sender/blob/master/docs/relayTx.schema.json).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayTransaction {
    /// The standard eth chain id.
    /// Currently supports Ropsten = 3 and Mainnet = 1.
    chain_id: Byte,

    /// The ethereum address of the user
    /// authorising this relay transaction.
    pub from: EthAddress,

    /// A signature made by the `from` authority
    /// over the full relay transaction data.
    /// Using this [digest](https://github.com/PISAresearch/contracts.any.sender/blob/e7d9cf8c26bdcae67e39f464b4a102a8572ff468/versions/0.2.1/contracts/core/RelayTxStruct.sol#L22).
    pub signature: EthSignature,

    /// The ABI encoded call data.
    /// Same as standard Ethereum.
    /// Max data length is 3000 bytes (BETA).
    #[serde(with = "data")]
    pub data: Bytes,

    /// The block by which this transaction must be mined.
    /// Must be at most 400 blocks larger than the current block height (BETA).
    /// There is a tolerance of 20 blocks above and below this value (BETA).
    /// Can optionally be set to 0. In this case the AnySender API will
    /// fill in a deadline (currentBlock + 400) and populate it in the returned receipt.
    // An integer in range 0..=(currentBlock + 400).
    pub deadline: u64,

    /// The gas limit provided to the transaction for execution.
    /// Same as standard Ethereum.
    /// An integer in range 0..=3.000.000 (BETA).
    pub gas_limit: u32,

    /// The value of the compensation that the user will be owed
    /// if AnySender fails to mine the transaction
    /// before the `deadline`.
    /// Max compensation is 0.05 ETH (BETA).
    // Maximum value 50_000_000_000_000_000
    #[serde(with = "compensation")]
    pub compensation: u64,

    /// The address of the relay contract
    /// that will be used to relay this transaction.
    pub relay_contract_address: EthAddress,

    /// The address the transaction is directed to.
    /// Cannot be empty.
    pub to: EthAddress,
}

impl RelayTransaction {
    /// Creates a new signed relay transaction.
    #[cfg(test)]
    pub fn new(
        from: EthAddress,
        chain_id: u8,
        eth_private_key: EthPrivateKey,
        data: Bytes,
        deadline: Option<u64>,
        gas_limit: u32,
        compensation: u64,
        to: EthAddress,
    ) -> Result<RelayTransaction> {
        let relay_contract_address = RelayContract::from_eth_chain_id(chain_id)?.address()?;

        let relay_transaction = RelayTransaction::new_unsigned(
            chain_id,
            from,
            data,
            deadline,
            gas_limit,
            compensation,
            relay_contract_address,
            to,
        )?
        .sign(&eth_private_key)?;

        info!("✔ AnySender transaction signature is calculated. Returning signed transaction...");

        Ok(relay_transaction)
    }

    /// Creates a new unsigned relay transaction from data.
    fn new_unsigned(
        chain_id: u8,
        from: EthAddress,
        data: Bytes,
        deadline: Option<u64>,
        gas_limit: u32,
        compensation: u64,
        relay_contract_address: EthAddress,
        to: EthAddress,
    ) -> Result<RelayTransaction> {
        info!("✔ Checking AnySender transaction constraints...");

        let deadline = deadline.unwrap_or_default();

        if gas_limit > ANY_SENDER_MAX_GAS_LIMIT {
            return Err("✘ AnySender gas limit is out of range!".into());
        }

        if data.len() > ANY_SENDER_MAX_DATA_LEN {
            return Err("✘ AnySender data length is out of range!".into());
        }

        if compensation > ANY_SENDER_MAX_COMPENSATION_WEI {
            return Err("✘ AnySender compensation should be smaller than 0.05 ETH!".into());
        }

        if chain_id != ETH_MAINNET_CHAIN_ID && chain_id != ETH_ROPSTEN_CHAIN_ID {
            return Err("✘ AnySender is not available on chain with the id provided!".into());
        }

        info!("✔ AnySender transaction constraints are satisfied. Returning unsigned transaction...");

        Ok(RelayTransaction {
            chain_id,
            from,
            data,
            deadline,
            gas_limit,
            compensation,
            relay_contract_address,
            to,
            signature: EthSignature::default(),
        })
    }

    /// Calculates AnySender relay transaction signature.
    fn sign(mut self, eth_private_key: &EthPrivateKey) -> Result<RelayTransaction> {
        info!("Calculating relay transaction signature...");

        let transaction_bytes = encode(&[
            Token::Address(self.to),
            Token::Address(self.from),
            Token::Bytes(self.data.clone()),
            Token::Uint(self.deadline.into()),
            Token::Uint(self.compensation.into()),
            Token::Uint(self.gas_limit.into()),
            Token::Uint(self.chain_id.into()),
            Token::Address(self.relay_contract_address),
        ]);

        let signed_message = eth_private_key.sign_eth_prefixed_msg_bytes(&transaction_bytes)?;
        self.signature = EthSignature::from_slice(&signed_message);

        Ok(self)
    }

    /// Creates a new AnySender relayed `mintByProxy` ERC777 proxy contract transaction.
    pub fn new_mint_by_proxy_tx(
        chain_id: Byte,
        from: EthAddress,
        token_amount: U256,
        any_sender_nonce: u64,
        eth_private_key: &EthPrivateKey,
        to: EthAddress,
        token_recipient: EthAddress,
    ) -> Result<RelayTransaction> {
        Ok(RelayTransaction::new_unsigned(
            chain_id,
            from,
            encode_mint_by_proxy_tx_data(eth_private_key, token_recipient, token_amount, any_sender_nonce)?,
            ANY_SENDER_DEFAULT_DEADLINE,
            ANY_SENDER_GAS_LIMIT,
            ANY_SENDER_MAX_COMPENSATION_WEI,
            RelayContract::from_eth_chain_id(chain_id)?.address()?,
            to,
        )?
        .sign(eth_private_key)?)
    }

    #[cfg(test)]
    pub fn serialize_hex(&self) -> String {
        hex::encode(self.serialize_bytes())
    }
}

impl EthTxInfoCompatible for RelayTransaction {
    fn is_any_sender(&self) -> bool {
        true
    }

    fn any_sender_tx(&self) -> Option<RelayTransaction> {
        Some(self.clone())
    }

    fn eth_tx_hex(&self) -> Option<String> {
        None
    }

    fn serialize_bytes(&self) -> Bytes {
        let mut rlp_stream = RlpStream::new();
        rlp_stream.begin_list(9);
        rlp_stream.append(&self.to);
        rlp_stream.append(&self.from);
        rlp_stream.append(&self.data);
        rlp_stream.append(&self.deadline);
        rlp_stream.append(&self.compensation);
        rlp_stream.append(&self.gas_limit);
        rlp_stream.append(&self.chain_id);
        rlp_stream.append(&self.relay_contract_address);
        rlp_stream.append(&self.signature);
        rlp_stream.out()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_on_eth::eth::eth_test_utils::get_sample_unsigned_eth_transaction;

    #[test]
    fn should_create_new_signed_relay_tx_from_data() {
        let chain_id = 3;
        let data = hex::decode("f15da729000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000047465737400000000000000000000000000000000000000000000000000000000").unwrap();
        let deadline = Some(0);
        let gas_limit = 100000;
        let compensation = 500000000;
        let relay_contract_address = RelayContract::Ropsten.address().unwrap();
        let to = EthAddress::from_slice(&hex::decode("FDE83bd51bddAA39F15c1Bf50E222a7AE5831D83").unwrap());

        let expected_data = hex::decode("f15da729000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000047465737400000000000000000000000000000000000000000000000000000000").unwrap();

        // private key without recovery param
        let eth_private_key = EthPrivateKey::from_slice([
            132, 23, 52, 203, 67, 154, 240, 53, 117, 195, 124, 41, 179, 50, 97, 159, 61, 169, 234, 47, 186, 237, 88,
            161, 200, 177, 24, 142, 207, 242, 168, 221,
        ])
        .unwrap();
        let from = EthAddress::from_slice(&hex::decode("736661736533BcfC9cc35649e6324aceFb7D32c1").unwrap());

        let relay_transaction = RelayTransaction::new(
            from,
            chain_id,
            eth_private_key,
            data.clone(),
            deadline,
            gas_limit,
            compensation,
            to,
        )
        .unwrap();

        let expected_signature = EthSignature::from_slice(
            &hex::decode("5aa14a852439d9f5aa7b22c63a228d79c6822cf644badc9a63117dd7880d9a4c639eccd4aeeee91eaea63e36640d151be71346d785d2bd274fb82351c6bb2c101b")
                .unwrap(),
        );
        let expected_relay_transaction = RelayTransaction {
            signature: expected_signature,
            data: expected_data.clone(),
            chain_id: 3,
            deadline: 0,
            from,
            gas_limit,
            compensation,
            relay_contract_address,
            to,
        };

        assert_eq!(relay_transaction, expected_relay_transaction);

        // private key with recovery param
        let eth_private_key = EthPrivateKey::from_slice([
            6, 55, 162, 221, 254, 198, 108, 20, 103, 12, 93, 123, 226, 232, 71, 70, 139, 212, 41, 54, 65, 132, 18, 158,
            202, 14, 137, 226, 174, 63, 11, 45,
        ])
        .unwrap();
        let from = EthAddress::from_slice(&hex::decode("1a96829d85bdf719b58b2593e2853d4ae5a0f50b").unwrap());

        let relay_transaction = RelayTransaction::new(
            from,
            chain_id,
            eth_private_key,
            data,
            deadline,
            gas_limit,
            compensation,
            to,
        )
        .unwrap();

        let expected_signature = EthSignature::from_slice(
            &hex::decode("89397a8de1489ab225704fdfe2187a72d837659c190b6bd0c0e2b6cd5f2705da1fa1db87fd516f4677f6db821a6ede7b4f7f4779d9f248a7ed93c1b8ca86c48f1b")
                .unwrap()
        );
        let expected_relay_transaction = RelayTransaction {
            signature: expected_signature,
            data: expected_data,
            chain_id: 3,
            deadline: 0,
            from,
            gas_limit,
            compensation,
            relay_contract_address,
            to,
        };

        assert_eq!(relay_transaction, expected_relay_transaction);
    }

    #[test]
    fn should_create_new_any_sender_relayed_mint_by_proxy_tx() {
        let eth_transaction = get_sample_unsigned_eth_transaction();
        let chain_id = 3;
        let eth_private_key = EthPrivateKey::from_slice([
            132, 23, 52, 203, 67, 154, 240, 53, 117, 195, 124, 41, 179, 50, 97, 159, 61, 169, 234, 47, 186, 237, 88,
            161, 200, 177, 24, 142, 207, 242, 168, 221,
        ])
        .unwrap();
        let from = EthAddress::from_slice(&hex::decode("736661736533BcfC9cc35649e6324aceFb7D32c1").unwrap());
        let any_sender_nonce = 0;
        let amount = U256::from(1337);

        let relay_transaction = RelayTransaction::new_mint_by_proxy_tx(
            chain_id,
            from,
            amount,
            any_sender_nonce,
            &eth_private_key,
            EthAddress::from_slice(&eth_transaction.to),
            EthAddress::from_slice(&eth_transaction.to), // FIXME This should be a different address really!
        )
        .expect("Error creating AnySender relay transaction from eth transaction!");
        let expected_relay_transaction = RelayTransaction {
            chain_id: 3,
            from: EthAddress::from_slice(
                &hex::decode("736661736533BcfC9cc35649e6324aceFb7D32c1").unwrap()),
            signature: EthSignature::from_slice(
                &hex::decode("6b7a97497a94eaef7f19b3512ecfc776a740c6802e08afe1b0422df62acd48c1649be24bdea460be79315d9c9bdbea0dbdac118b3577eb6aab48d3cdf7c11f931c").unwrap()),
            data: vec![122, 214, 174, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 194, 4, 141, 173, 79, 207, 171, 68, 195, 239, 61, 22, 232, 130, 181, 23, 141, 244, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 57, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65, 155, 196, 23, 176, 241, 106, 157, 159, 93, 33, 109, 139, 206, 183, 77, 162, 108, 242, 171, 31, 212, 249, 141, 180, 202, 134, 217, 239, 84, 242, 88, 6, 113, 242, 43, 136, 1, 215, 205, 182, 59, 242, 3, 109, 145, 213, 166, 32, 222, 8, 251, 143, 7, 215, 54, 128, 82, 237, 31, 99, 7, 176, 247, 39, 27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            deadline: 0,
            gas_limit: 300000,
            compensation: 49999999999999999,
            relay_contract_address: EthAddress::from_slice(
                &hex::decode("9b4fa5a1d9f6812e2b56b36fbde62736fa82c2a7").unwrap()),
            to: EthAddress::from_slice(
                &hex::decode("53c2048dad4fcfab44c3ef3d16e882b5178df42b").unwrap()),
        };

        assert_eq!(relay_transaction, expected_relay_transaction);
    }

    #[test]
    fn should_serialize_deserialize_relay_tx_as_json() {
        // deserialize
        let json_str = r#"
            {
                "chainId": 3,
                "from": "0x736661736533BcfC9cc35649e6324aceFb7D32c1",
                "to": "0xFDE83bd51bddAA39F15c1Bf50E222a7AE5831D83",
                "data": "0xf15da729000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000047465737400000000000000000000000000000000000000000000000000000000",
                "deadline": 0,
                "gasLimit": 100000,
                "compensation": "500000000",
                "relayContractAddress": "0x9b4FA5A1D9f6812e2B56B36fBde62736Fa82c2a7",
                "signature": "0x5aa14a852439d9f5aa7b22c63a228d79c6822cf644badc9a63117dd7880d9a4c639eccd4aeeee91eaea63e36640d151be71346d785d2bd274fb82351c6bb2c101b"
            }
        "#;

        let relay_transaction: RelayTransaction = serde_json::from_str(json_str).unwrap();

        let chain_id = 3;
        let eth_private_key = EthPrivateKey::from_slice([
            132, 23, 52, 203, 67, 154, 240, 53, 117, 195, 124, 41, 179, 50, 97, 159, 61, 169, 234, 47, 186, 237, 88,
            161, 200, 177, 24, 142, 207, 242, 168, 221,
        ])
        .unwrap();
        let from = EthAddress::from_slice(&hex::decode("736661736533BcfC9cc35649e6324aceFb7D32c1").unwrap());
        let data = hex::decode("f15da729000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000047465737400000000000000000000000000000000000000000000000000000000").unwrap();
        let deadline = Some(0);
        let gas_limit = 100000;
        let compensation = 500000000;
        let to = EthAddress::from_slice(&hex::decode("FDE83bd51bddAA39F15c1Bf50E222a7AE5831D83").unwrap());

        let expected_relay_transaction = RelayTransaction::new(
            from,
            chain_id,
            eth_private_key,
            data,
            deadline,
            gas_limit,
            compensation,
            to,
        )
        .unwrap();

        assert_eq!(relay_transaction, expected_relay_transaction);

        // serialize
        let expected_relay_transaction = "{\"chainId\":3,\"from\":\"0x736661736533bcfc9cc35649e6324acefb7d32c1\",\"signature\":\"0x5aa14a852439d9f5aa7b22c63a228d79c6822cf644badc9a63117dd7880d9a4c639eccd4aeeee91eaea63e36640d151be71346d785d2bd274fb82351c6bb2c101b\",\"data\":\"0xf15da729000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000047465737400000000000000000000000000000000000000000000000000000000\",\"deadline\":0,\"gasLimit\":100000,\"compensation\":\"500000000\",\"relayContractAddress\":\"0x9b4fa5a1d9f6812e2b56b36fbde62736fa82c2a7\",\"to\":\"0xfde83bd51bddaa39f15c1bf50e222a7ae5831d83\"}".to_string();
        let relay_transaction = serde_json::to_string(&relay_transaction).unwrap();

        assert_eq!(relay_transaction, expected_relay_transaction);
    }

    #[test]
    fn should_serialize_relay_tx_to_bytes() {
        let expected_result = vec![
            248, 243, 148, 253, 232, 59, 213, 27, 221, 170, 57, 241, 92, 27, 245, 14, 34, 42, 122, 229, 131, 29, 131,
            148, 115, 102, 97, 115, 101, 51, 188, 252, 156, 195, 86, 73, 230, 50, 74, 206, 251, 125, 50, 193, 184, 100,
            241, 93, 167, 41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 116,
            101, 115, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128,
            132, 29, 205, 101, 0, 131, 1, 134, 160, 3, 148, 155, 79, 165, 161, 217, 246, 129, 46, 43, 86, 179, 111,
            189, 230, 39, 54, 250, 130, 194, 167, 184, 65, 90, 161, 74, 133, 36, 57, 217, 245, 170, 123, 34, 198, 58,
            34, 141, 121, 198, 130, 44, 246, 68, 186, 220, 154, 99, 17, 125, 215, 136, 13, 154, 76, 99, 158, 204, 212,
            174, 238, 233, 30, 174, 166, 62, 54, 100, 13, 21, 27, 231, 19, 70, 215, 133, 210, 189, 39, 79, 184, 35, 81,
            198, 187, 44, 16, 27,
        ];
        let expected_tx_hash = "e93eab63e9b863d4c93007b0a641c749af840c8c19602ea18f6546a308431cc4";
        let expected_tx_hex = "f8f394fde83bd51bddaa39f15c1bf50e222a7ae5831d8394736661736533bcfc9cc35649e6324acefb7d32c1b864f15da72900000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000004746573740000000000000000000000000000000000000000000000000000000080841dcd6500830186a003949b4fa5a1d9f6812e2b56b36fbde62736fa82c2a7b8415aa14a852439d9f5aa7b22c63a228d79c6822cf644badc9a63117dd7880d9a4c639eccd4aeeee91eaea63e36640d151be71346d785d2bd274fb82351c6bb2c101b";

        let chain_id = 3;
        let eth_private_key = EthPrivateKey::from_slice([
            132, 23, 52, 203, 67, 154, 240, 53, 117, 195, 124, 41, 179, 50, 97, 159, 61, 169, 234, 47, 186, 237, 88,
            161, 200, 177, 24, 142, 207, 242, 168, 221,
        ])
        .unwrap();
        let from = EthAddress::from_slice(&hex::decode("736661736533BcfC9cc35649e6324aceFb7D32c1").unwrap());
        let data = hex::decode("f15da729000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000047465737400000000000000000000000000000000000000000000000000000000").unwrap();
        let deadline = Some(0);
        let gas_limit = 100000;
        let compensation = 500000000;
        let to = EthAddress::from_slice(&hex::decode("FDE83bd51bddAA39F15c1Bf50E222a7AE5831D83").unwrap());

        let relay_transaction = RelayTransaction::new(
            from,
            chain_id,
            eth_private_key,
            data,
            deadline,
            gas_limit,
            compensation,
            to,
        )
        .unwrap();

        // bytes
        let result = relay_transaction.serialize_bytes();
        assert_eq!(result, expected_result);

        // hash
        let tx_hash = relay_transaction.get_tx_hash();
        assert_eq!(tx_hash, expected_tx_hash);

        // hex
        let tx_hex = relay_transaction.serialize_hex();
        assert_eq!(tx_hex, expected_tx_hex);
    }
}
