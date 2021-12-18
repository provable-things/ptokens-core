use std::str::FromStr;

use bitcoin::{
    blockdata::{
        script::{Instruction, Script as BtcScript},
        transaction::{Transaction as BtcTransaction, TxIn as BtcTxIn, TxOut as BtcTxOut},
    },
    consensus::encode::serialize as btc_serialize,
    network::constants::Network as BtcNetwork,
    util::{address::Address as BtcAddress, key::PublicKey as BtcPublicKey},
    Txid,
};
use derive_more::{Constructor, Deref, DerefMut};
use ethereum_types::{Address as EthAddress, U256};
use serde::{Deserialize, Serialize};

use crate::{
    btc_on_eth::utils::{convert_satoshis_to_wei, convert_wei_to_satoshis},
    chains::{
        btc::{
            btc_constants::{MINIMUM_REQUIRED_SATOSHIS, PLACEHOLDER_BTC_ADDRESS},
            btc_database_utils::{get_btc_address_from_db, get_btc_network_from_db},
            btc_state::BtcState,
            btc_utils::get_pay_to_pub_key_hash_script,
            deposit_address_info::DepositInfoHashMap,
        },
        eth::eth_utils::safely_convert_hex_to_eth_address,
    },
    constants::{FEE_BASIS_POINTS_DIVISOR, SAFE_ETH_ADDRESS},
    fees::fee_utils::sanity_check_basis_points_value,
    traits::DatabaseInterface,
    types::{Byte, Bytes, NoneError, Result},
};

const NUM_BYTES_IN_SCRIPT: u8 = 22;
const OP_RETURN_OP_CODE_AS_DECIMAL: u8 = 106;
const NUM_BYTES_IN_ETH_ADDRESS: u8 = 20;
const NUM_BYTES_IN_SCRIPT_WITH_LEN_PREFIX: usize = 23;
const NUM_PREFIX_BYTES_IN_SERIALIZED_P2PKH: usize = 3;

pub fn parse_minting_params_from_p2sh_deposits_and_add_to_state<D: DatabaseInterface>(
    state: BtcState<D>,
) -> Result<BtcState<D>> {
    info!("✔ Parsing minting params from `P2SH` deposit txs in state...");
    BtcOnEthMintingParams::from_btc_txs(
        state.get_p2sh_deposit_txs()?,
        state.get_deposit_info_hash_map()?,
        get_btc_network_from_db(&state.db)?,
    )
    .and_then(|params| state.add_btc_on_eth_minting_params(params))
}

pub fn parse_minting_params_from_p2pkh_deposits_and_add_to_state<D: DatabaseInterface>(
    state: BtcState<D>,
) -> Result<BtcState<D>> {
    info!("✔ Parsing minting params from `P2PKH` deposit txs in state...");
    get_btc_address_from_db(&state.db)
        .and_then(|btc_address| get_pay_to_pub_key_hash_script(&btc_address))
        .and_then(|target_deposit_script| {
            BtcOnEthMintingParams::from_btc_p2pkh_txs(
                &target_deposit_script,
                state.get_p2pkh_deposit_txs()?,
                get_btc_network_from_db(&state.db)?,
            )
        })
        .and_then(|minting_params| state.add_btc_on_eth_minting_params(minting_params))
}

#[derive(Debug, Clone, PartialEq, Eq, Deref, DerefMut, Constructor, Serialize, Deserialize)]
pub struct BtcOnEthMintingParams(pub Vec<BtcOnEthMintingParamStruct>);

impl BtcOnEthMintingParams {
    #[cfg(test)]
    pub fn sum(&self) -> U256 {
        self.iter().fold(U256::zero(), |a, params| a + params.amount)
    }

    pub fn calculate_fees(&self, basis_points: u64) -> Result<(Vec<u64>, u64)> {
        sanity_check_basis_points_value(basis_points).map(|_| {
            info!("✔ Calculating fees in `BtcOnEthMintingParams`...");
            let fees = self
                .iter()
                .map(|minting_params| minting_params.calculate_fee(basis_points))
                .collect::<Vec<u64>>();
            let total_fee = fees.iter().sum();
            info!("✔      Fees: {:?}", fees);
            info!("✔ Total fee: {:?}", fees);
            (fees, total_fee)
        })
    }

    pub fn to_bytes(&self) -> Result<Bytes> {
        Ok(serde_json::to_vec(&self.0)?)
    }

    pub fn from_bytes(bytes: &[Byte]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn filter_out_value_too_low(&self) -> Result<BtcOnEthMintingParams> {
        info!(
            "✔ Filtering out any minting params below a minimum of {} Satoshis...",
            MINIMUM_REQUIRED_SATOSHIS
        );
        let threshold = convert_satoshis_to_wei(MINIMUM_REQUIRED_SATOSHIS);
        Ok(BtcOnEthMintingParams::new(
            self.iter()
                .filter(|params| match params.amount >= threshold {
                    true => true,
                    false => {
                        info!("✘ Filtering minting params ∵ value too low: {:?}", params);
                        false
                    },
                })
                .cloned()
                .collect::<Vec<BtcOnEthMintingParamStruct>>(),
        ))
    }

    fn from_btc_tx(tx: &BtcTransaction, deposit_info: &DepositInfoHashMap, network: BtcNetwork) -> Result<Self> {
        info!("✔ Parsing minting params from single `P2SH` transaction...");
        Ok(Self::new(
            tx.output
                .iter()
                .filter(|tx_out| tx_out.script_pubkey.is_p2sh())
                .map(|tx_out| match BtcAddress::from_script(&tx_out.script_pubkey, network) {
                    None => {
                        info!("✘ Could not derive BTC address from tx: {:?}", tx);
                        (tx_out, None)
                    },
                    Some(address) => {
                        info!("✔ BTC address extracted from `tx_out`: {}", address);
                        (tx_out, Some(address))
                    },
                })
                .filter(|(_, maybe_address)| maybe_address.is_some())
                .map(|(tx_out, address)| {
                    match deposit_info.get(&address.clone().ok_or(NoneError("Could not unwrap BTC address!"))?) {
                        None => {
                            info!(
                                "✘ BTC address {} not in deposit list!",
                                address.ok_or(NoneError("Could not unwrap BTC address!"))?
                            );
                            Err("Filtering out this err!".into())
                        },
                        Some(deposit_info) => {
                            info!("✔ Deposit info from list: {:?}", deposit_info);
                            BtcOnEthMintingParamStruct::new(
                                convert_satoshis_to_wei(tx_out.value),
                                deposit_info.address.clone(),
                                tx.txid(),
                                address.ok_or(NoneError("Could not unwrap BTC address!"))?,
                            )
                        },
                    }
                })
                .filter(|maybe_minting_params| maybe_minting_params.is_ok())
                .collect::<Result<Vec<BtcOnEthMintingParamStruct>>>()?,
        ))
    }

    pub fn from_btc_txs(
        txs: &[BtcTransaction],
        deposit_info: &DepositInfoHashMap,
        network: BtcNetwork,
    ) -> Result<Self> {
        info!("✔ Parsing minting params from `P2SH` transactions...");
        Ok(Self::new(
            txs.iter()
                .flat_map(|tx| Self::from_btc_tx(tx, deposit_info, network))
                .map(|minting_params| minting_params.0)
                .flatten()
                .collect::<Vec<BtcOnEthMintingParamStruct>>(),
        ))
    }

    pub fn from_btc_p2pkh_txs(script: &BtcScript, txs: &[BtcTransaction], btc_network: BtcNetwork) -> Result<Self> {
        debug!("✔ Parsing minting params from target script: {}", script);
        Ok(Self::new(
            txs.iter()
                .map(|tx| BtcOnEthMintingParamStruct::from_p2pkh_tx(script, tx, btc_network))
                .collect::<Result<Vec<BtcOnEthMintingParamStruct>>>()?,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtcOnEthMintingParamStruct {
    pub amount: U256,
    pub eth_address: EthAddress,
    pub originating_tx_hash: Txid,
    pub originating_tx_address: String,
}

impl BtcOnEthMintingParamStruct {
    pub fn new(
        amount: U256,
        eth_address_hex: String,
        originating_tx_hash: Txid,
        originating_tx_address: BtcAddress,
    ) -> Result<BtcOnEthMintingParamStruct> {
        Ok(BtcOnEthMintingParamStruct {
            amount,
            originating_tx_hash,
            originating_tx_address: originating_tx_address.to_string(),
            eth_address: safely_convert_hex_to_eth_address(&eth_address_hex)?,
        })
    }

    fn to_satoshi_amount(&self) -> u64 {
        convert_wei_to_satoshis(self.amount)
    }

    pub fn calculate_fee(&self, basis_points: u64) -> u64 {
        (self.to_satoshi_amount() * basis_points) / FEE_BASIS_POINTS_DIVISOR
    }

    fn update_amount(&self, new_amount: U256) -> Self {
        let mut new_self = self.clone();
        new_self.amount = new_amount;
        new_self
    }

    pub fn subtract_satoshi_amount(&self, subtrahend: u64) -> Result<Self> {
        let self_amount_in_satoshis = self.to_satoshi_amount();
        if subtrahend > self_amount_in_satoshis {
            Err("Cannot subtract amount from `BtcOnEthMintingParamStruct`: subtrahend too large!".into())
        } else {
            let amount_minus_fee = self_amount_in_satoshis - subtrahend;
            debug!(
                "Subtracted amount of {} from current minting params amount of {} to get final amount of {}",
                subtrahend, self_amount_in_satoshis, amount_minus_fee
            );
            Ok(self.update_amount(convert_satoshis_to_wei(amount_minus_fee)))
        }
    }

    fn serialized_script_pubkey_should_be_desired_op_return(serialized_script: &[Byte]) -> bool {
        serialized_script.len() == NUM_BYTES_IN_SCRIPT_WITH_LEN_PREFIX
            && serialized_script[0] == NUM_BYTES_IN_SCRIPT
            && serialized_script[1] == OP_RETURN_OP_CODE_AS_DECIMAL
            && serialized_script[2] == NUM_BYTES_IN_ETH_ADDRESS
    }

    fn output_is_desired_op_return(output: &BtcTxOut) -> bool {
        Self::serialized_script_pubkey_should_be_desired_op_return(&btc_serialize(&output.script_pubkey))
    }

    fn extract_spender_address_from_op_return_input(input: &BtcTxIn, btc_network: BtcNetwork) -> Result<BtcAddress> {
        info!("✔ Extracting spender address from OP_RETURN input...");
        Ok(input
            .script_sig
            .instructions_minimal()
            .skip(1)
            .map(|script_instruction| -> Result<BtcAddress> {
                let instruction = script_instruction?;
                const BYTE: [u8; 1] = [0u8];
                let data = match instruction {
                    Instruction::PushBytes(bytes) => bytes,
                    _ => &BYTE,
                };
                info!("✔ Instruction: {:?}", instruction);
                info!("✔ data: {:?}", data);
                Ok(BtcAddress::p2pkh(&BtcPublicKey::from_slice(data)?, btc_network))
            })
            .collect::<Result<Vec<BtcAddress>>>()?[0]
            .clone())
    }

    fn sum_deposit_values_from_tx_outputs(transaction: &BtcTransaction, target_deposit_script: &BtcScript) -> u64 {
        trace!("✔ Getting deposit values from transaction: {:?}", transaction);
        transaction
            .output
            .iter()
            .filter(|output| &output.script_pubkey == target_deposit_script)
            .map(|output| output.value)
            .sum::<u64>()
    }

    fn get_eth_address_from_op_return_in_tx_else_safe_address(transaction: &BtcTransaction) -> String {
        let maybe_op_return_txs = transaction
            .output
            .iter()
            .cloned()
            .filter(Self::output_is_desired_op_return)
            .collect::<Vec<BtcTxOut>>();
        match maybe_op_return_txs.len() {
            0 => {
                let address = hex::encode(SAFE_ETH_ADDRESS.as_bytes());
                info!("✔ No address found, default to safe address: 0x{}", address);
                address
            },
            _ => {
                let address = Self::parse_eth_address_from_op_return_script(&maybe_op_return_txs[0].script_pubkey);
                info!("✔ Address parsed from `op_return` script: 0x{}", hex::encode(address));
                hex::encode(address)
            },
        }
    }

    fn parse_eth_address_from_op_return_script(script: &BtcScript) -> EthAddress {
        trace!("✔ Parsing ETH address from OP_RETURN script: {}", script);
        EthAddress::from_slice(&btc_serialize(script)[NUM_PREFIX_BYTES_IN_SERIALIZED_P2PKH..])
    }

    pub fn from_p2pkh_tx(
        target_deposit_script: &BtcScript,
        tx: &BtcTransaction,
        btc_network: BtcNetwork,
    ) -> Result<Self> {
        Self::new(
            convert_satoshis_to_wei(Self::sum_deposit_values_from_tx_outputs(tx, target_deposit_script)),
            Self::get_eth_address_from_op_return_in_tx_else_safe_address(tx),
            tx.txid(),
            // NOTE: Currently not supporting the getting of the origin from witness data.
            match tx.input[0].witness.is_empty() {
                true => Self::extract_spender_address_from_op_return_input(&tx.input[0].clone(), btc_network)?,
                false => {
                    info!("✔ Not an op_return script, can't get sender address");
                    BtcAddress::from_str(PLACEHOLDER_BTC_ADDRESS)?
                },
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::util::address::Address as BtcAddress;
    use ethereum_types::H160 as EthAddress;

    use super::*;
    use crate::{
        chains::btc::{
            btc_test_utils::{
                get_sample_btc_block_n,
                get_sample_btc_p2pkh_address,
                get_sample_btc_p2pkh_tx,
                get_sample_btc_pub_key_slice,
                get_sample_btc_tx,
                get_sample_minting_params,
                get_sample_p2pkh_btc_block_and_txs,
                get_sample_p2pkh_op_return_output,
                get_sample_pay_to_pub_key_hash_script,
                SAMPLE_P2PKH_TRANSACTION_OUTPUT_INDEX,
            },
            btc_utils::convert_bytes_to_btc_pub_key_slice,
            filter_p2pkh_deposit_txs::filter_txs_for_p2pkh_deposits,
            filter_p2sh_deposit_txs::filter_p2sh_deposit_txs,
            get_deposit_info_hash_map::create_hash_map_from_deposit_info_list,
        },
        errors::AppError,
    };

    fn get_expected_eth_address() -> EthAddress {
        EthAddress::from_slice(&hex::decode("fedfe2616eb3661cb8fed2782f5f0cc91d59dcac").unwrap())
    }

    #[test]
    fn should_filter_minting_params() {
        let expected_length_before = 3;
        let expected_length_after = 2;
        let minting_params = get_sample_minting_params();
        let threshold = convert_satoshis_to_wei(MINIMUM_REQUIRED_SATOSHIS);
        let length_before = minting_params.len();
        assert_eq!(length_before, expected_length_before);
        let result = minting_params.filter_out_value_too_low().unwrap();
        let length_after = result.len();
        assert_eq!(length_after, expected_length_after);
        result.iter().for_each(|params| assert!(params.amount >= threshold));
    }

    #[test]
    fn should_parse_minting_params_struct_from_p2sh_deposit_tx() {
        let pub_key = get_sample_btc_pub_key_slice();
        let expected_amount = convert_satoshis_to_wei(10000);
        let expected_num_results = 1;
        let expected_eth_address_bytes = hex::decode("fedfe2616eb3661cb8fed2782f5f0cc91d59dcac").unwrap();
        let expected_btc_address = "2N2LHYbt8K1KDBogd6XUG9VBv5YM6xefdM2";
        let expected_tx_hash = "4d19fed40e7d1944c8590a8a2e21d1f16f65c060244277a3d207770d1c848352";
        let btc_network = BtcNetwork::Testnet;
        let block_and_id = get_sample_btc_block_n(5).unwrap();
        let deposit_address_list = block_and_id.deposit_address_list.clone();
        let txs = block_and_id.block.txdata;
        let hash_map = create_hash_map_from_deposit_info_list(&deposit_address_list).unwrap();
        let tx = filter_p2sh_deposit_txs(&hash_map, &pub_key, &txs, btc_network).unwrap()[0].clone();
        let result = BtcOnEthMintingParams::from_btc_tx(&tx, &hash_map, btc_network).unwrap();
        assert_eq!(result[0].amount, expected_amount);
        assert_eq!(result.len(), expected_num_results);
        assert_eq!(result[0].originating_tx_hash.to_string(), expected_tx_hash);
        assert_eq!(result[0].originating_tx_address.to_string(), expected_btc_address);
        assert_eq!(result[0].eth_address.as_bytes(), &expected_eth_address_bytes[..]);
    }

    #[test]
    fn should_parse_minting_params_struct_from_p2sh_deposit_txs() {
        let expected_num_results = 1;
        let expected_amount = convert_satoshis_to_wei(10000);
        let expected_eth_address_bytes = hex::decode("fedfe2616eb3661cb8fed2782f5f0cc91d59dcac").unwrap();
        let expected_btc_address = "2N2LHYbt8K1KDBogd6XUG9VBv5YM6xefdM2";
        let expected_tx_hash = "4d19fed40e7d1944c8590a8a2e21d1f16f65c060244277a3d207770d1c848352";
        let btc_network = BtcNetwork::Testnet;
        let block_and_id = get_sample_btc_block_n(5).unwrap();
        let deposit_address_list = block_and_id.deposit_address_list.clone();
        let txs = block_and_id.block.txdata;
        let hash_map = create_hash_map_from_deposit_info_list(&deposit_address_list).unwrap();
        let result = BtcOnEthMintingParams::from_btc_txs(&txs, &hash_map, btc_network).unwrap();
        assert_eq!(result.len(), expected_num_results);
        assert_eq!(result[0].amount, expected_amount);
        assert_eq!(result[0].originating_tx_hash.to_string(), expected_tx_hash);
        assert_eq!(result[0].originating_tx_address.to_string(), expected_btc_address);
        assert_eq!(result[0].eth_address.as_bytes(), &expected_eth_address_bytes[..]);
    }

    #[test]
    fn should_parse_minting_params_struct_from_two_p2sh_deposit_txs() {
        let expected_num_results = 2;
        let expected_amount_1 = convert_satoshis_to_wei(314159);
        let expected_btc_address_1 = BtcAddress::from_str("2NCfNHvNAecRyXPBDaAkfgMLL7NjvPrC6GU").unwrap();
        let expected_amount_2 = convert_satoshis_to_wei(1000000);
        let expected_btc_address_2 = BtcAddress::from_str("2N6DgNSaX3D5rUYXuMM3b5Ujgw4sPrddSHp").unwrap();
        let expected_eth_address_1 =
            EthAddress::from_slice(&hex::decode("edb86cd455ef3ca43f0e227e00469c3bdfa40628").unwrap()[..]);
        let expected_eth_address_2 =
            EthAddress::from_slice(&hex::decode("7344d31d7025f72bd1d3c08645fa6b12d406fc05").unwrap()[..]);
        let expected_originating_tx_hash_1 =
            Txid::from_str("ee022f1be2981fbdd51f7c7ac2e07c1233bb7806e481df9c52b8077a628b2ea8").unwrap();
        let expected_originating_tx_hash_2 =
            Txid::from_str("130a150ff71f8cabf02d4315f7d61f801ced234c7fcc3144d858816033578110").unwrap();
        let pub_key_slice = convert_bytes_to_btc_pub_key_slice(
            &hex::decode("03a3bea6d8d15a38d9c96074d994c788bc1286d557ef5bdbb548741ddf265637ce").unwrap(),
        )
        .unwrap();
        let expected_result_1 = BtcOnEthMintingParamStruct::new(
            expected_amount_1,
            hex::encode(expected_eth_address_1),
            expected_originating_tx_hash_1,
            expected_btc_address_1,
        )
        .unwrap();
        let expected_result_2 = BtcOnEthMintingParamStruct::new(
            expected_amount_2,
            hex::encode(expected_eth_address_2),
            expected_originating_tx_hash_2,
            expected_btc_address_2,
        )
        .unwrap();
        let btc_network = BtcNetwork::Testnet;
        let block_and_id = get_sample_btc_block_n(6).unwrap();
        let deposit_address_list = block_and_id.deposit_address_list.clone();
        let txs = block_and_id.block.txdata;
        let hash_map = create_hash_map_from_deposit_info_list(&deposit_address_list).unwrap();
        let filtered_txs = filter_p2sh_deposit_txs(&hash_map, &pub_key_slice, &txs, btc_network).unwrap();
        let result = BtcOnEthMintingParams::from_btc_txs(&filtered_txs, &hash_map, btc_network).unwrap();
        let result_1 = result[0].clone();
        let result_2 = result[1].clone();
        assert_eq!(result.len(), expected_num_results);
        assert_eq!(result_1, expected_result_1);
        assert_eq!(result_2, expected_result_2);
    }

    #[test]
    fn serialized_script_pubkey_should_be_desired_op_return() {
        let p2pkh_output = get_sample_p2pkh_op_return_output();
        let bytes = btc_serialize(&p2pkh_output.script_pubkey);
        let result = BtcOnEthMintingParamStruct::serialized_script_pubkey_should_be_desired_op_return(&bytes);
        assert!(result);
    }

    #[test]
    fn correct_output_should_be_desired_op_return_output() {
        let p2pkh_output = get_sample_p2pkh_op_return_output();
        let result = BtcOnEthMintingParamStruct::output_is_desired_op_return(&p2pkh_output);
        assert!(result);
    }

    #[test]
    fn incorrect_output_should_not_be_desired_op_return() {
        const INDEX_OF_NON_P2PKH_OUTPUT: usize = 0;
        assert_ne!(INDEX_OF_NON_P2PKH_OUTPUT, SAMPLE_P2PKH_TRANSACTION_OUTPUT_INDEX);
        let tx = get_sample_btc_p2pkh_tx();
        let wrong_output = tx.output[INDEX_OF_NON_P2PKH_OUTPUT].clone();
        let result = BtcOnEthMintingParamStruct::output_is_desired_op_return(&wrong_output);
        assert!(!result);
    }

    #[test]
    fn should_parse_eth_address_from_op_return_script() {
        let expected_result = get_expected_eth_address();
        let script = get_sample_p2pkh_op_return_output().script_pubkey;
        let result = BtcOnEthMintingParamStruct::parse_eth_address_from_op_return_script(&script);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_first_deposit_value_from_tx() {
        let expected_result: u64 = 1337;
        let tx = get_sample_btc_p2pkh_tx();
        let target_script = get_sample_pay_to_pub_key_hash_script();
        let result = BtcOnEthMintingParamStruct::sum_deposit_values_from_tx_outputs(&tx, &target_script);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_eth_address_from_p2pkh_in_tx_else_safe_address() {
        let expected_result = get_expected_eth_address();
        let tx = get_sample_btc_p2pkh_tx();
        let result = BtcOnEthMintingParamStruct::get_eth_address_from_op_return_in_tx_else_safe_address(&tx);
        assert_eq!(result, hex::encode(expected_result));
    }

    #[test]
    fn should_default_to_safe_address_if_no_p2pkh() {
        let tx = get_sample_btc_tx();
        let result = BtcOnEthMintingParamStruct::get_eth_address_from_op_return_in_tx_else_safe_address(&tx);
        assert_eq!(result, hex::encode(SAFE_ETH_ADDRESS.as_bytes()));
    }

    #[test]
    fn should_extract_spender_address_from_p2pkh_input() {
        let network = BtcNetwork::Testnet;
        let expected_origin_address = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM";
        let block = get_sample_p2pkh_btc_block_and_txs().block;
        let sample_pub_key_hash = get_sample_btc_pub_key_slice();
        let sample_address = get_sample_btc_p2pkh_address();
        let include_change_outputs = false;
        let filtered_txs = filter_txs_for_p2pkh_deposits(
            &sample_address,
            &sample_pub_key_hash,
            &block.txdata,
            include_change_outputs,
        )
        .unwrap();
        let input = filtered_txs[0].input[0].clone();
        let result = BtcOnEthMintingParamStruct::extract_spender_address_from_op_return_input(&input, network).unwrap();
        assert_eq!(result.to_string(), expected_origin_address);
    }

    #[test]
    fn should_parse_minting_params_from_p2pkh_tx() {
        let tx_index = 56;
        let network = BtcNetwork::Testnet;
        let expected_address = get_expected_eth_address();
        let expected_value = convert_satoshis_to_wei(1337);
        let expected_origin_address = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM";
        let expected_tx_hash = "183d4334c0e06d38cebfe2387e192c3a5f24f13c612214945af95f0aec696c6b".to_string();
        let block = get_sample_p2pkh_btc_block_and_txs().block;
        let tx = block.txdata[tx_index].clone();
        let target_deposit_script = get_sample_pay_to_pub_key_hash_script();
        let result = BtcOnEthMintingParamStruct::from_p2pkh_tx(&target_deposit_script, &tx, network).unwrap();
        assert_eq!(result.amount, expected_value);
        assert_eq!(result.eth_address, expected_address);
        assert_eq!(result.originating_tx_hash.to_string(), expected_tx_hash);
        let input = tx.input[0].clone();
        let address =
            BtcOnEthMintingParamStruct::extract_spender_address_from_op_return_input(&input, network).unwrap();
        assert_eq!(address.to_string(), expected_origin_address);
    }

    #[test]
    fn should_default_to_safe_address_if_no_op_return_present() {
        let tx_index = 36;
        let network = BtcNetwork::Testnet;
        let expected_value = convert_satoshis_to_wei(4610922);
        let expected_origin_address = "moBSQbHn7N9BC9pdtAMnA7GBiALzNMQJyE";
        let expected_tx_hash = "9ac032f07cacce63d66fc3937ea04c032eb33852bed705e3e7a309baa8bedf19".to_string();
        let block = get_sample_btc_block_n(8).unwrap().block;
        let tx = block.txdata[tx_index].clone();
        let target_deposit_script = get_sample_pay_to_pub_key_hash_script();
        let result = BtcOnEthMintingParamStruct::from_p2pkh_tx(&target_deposit_script, &tx, network).unwrap();
        assert_eq!(result.amount, expected_value);
        assert_eq!(result.eth_address, *SAFE_ETH_ADDRESS);
        assert_eq!(result.originating_tx_hash.to_string(), expected_tx_hash);
        let input = tx.input[0].clone();
        let address =
            BtcOnEthMintingParamStruct::extract_spender_address_from_op_return_input(&input, network).unwrap();
        assert_eq!(address.to_string(), expected_origin_address);
    }

    #[test]
    fn should_parse_minting_params_from_txs() {
        let network = BtcNetwork::Testnet;
        let expected_address = get_expected_eth_address();
        let expected_value = convert_satoshis_to_wei(1337);
        let sample_pub_key_hash = get_sample_btc_pub_key_slice();
        let sample_address = get_sample_btc_p2pkh_address();
        let expected_origin_address = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM";
        let expected_tx_hash = "183d4334c0e06d38cebfe2387e192c3a5f24f13c612214945af95f0aec696c6b".to_string();
        let block = get_sample_p2pkh_btc_block_and_txs().block;
        let include_change_outputs = false;
        let filtered_txs = filter_txs_for_p2pkh_deposits(
            &sample_address,
            &sample_pub_key_hash,
            &block.txdata,
            include_change_outputs,
        )
        .unwrap();
        let target_deposit_script = get_sample_pay_to_pub_key_hash_script();
        let result = BtcOnEthMintingParams::from_btc_p2pkh_txs(&target_deposit_script, &filtered_txs, network).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].amount, expected_value);
        assert_eq!(result[0].eth_address, expected_address);
        assert_eq!(result[0].originating_tx_hash.to_string(), expected_tx_hash);
        let input = filtered_txs[0].input[0].clone();
        let address =
            BtcOnEthMintingParamStruct::extract_spender_address_from_op_return_input(&input, network).unwrap();
        assert_eq!(address.to_string(), expected_origin_address);
    }

    #[test]
    fn should_get_amount_in_satoshi() {
        let params = get_sample_minting_params()[0].clone();
        let result = params.to_satoshi_amount();
        let expected_result = 5000;
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_subtract_satoshi_amount() {
        let params = get_sample_minting_params()[0].clone();
        let subtracted_params = params.subtract_satoshi_amount(1).unwrap();
        let expected_result = 4999;
        let result = subtracted_params.to_satoshi_amount();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_calculate_fee() {
        let params = get_sample_minting_params()[0].clone();
        let basis_points = 25;
        let expected_result = 12;
        let result = params.calculate_fee(basis_points);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_calculate_fees() {
        let basis_points = 25;
        let params = get_sample_minting_params();
        let (fees, total_fee) = params.calculate_fees(basis_points).unwrap();
        let expected_total_fee = 36;
        let expected_fees = vec![12, 12, 12];
        assert_eq!(total_fee, expected_total_fee);
        assert_eq!(fees, expected_fees);
    }

    #[test]
    fn should_error_subtracting_amount_if_subtrahend_is_too_large() {
        let params = get_sample_minting_params()[0].clone();
        let subtrahend = (params.amount + 1).as_u64();
        let expected_error = "Cannot subtract amount from `BtcOnEthMintingParamStruct`: subtrahend too large!";
        match params.subtract_satoshi_amount(subtrahend) {
            Ok(_) => panic!("Should not have succeeded!"),
            Err(AppError::Custom(error)) => assert_eq!(error, expected_error),
            Err(_) => panic!("Wrong error received!"),
        }
    }
}
