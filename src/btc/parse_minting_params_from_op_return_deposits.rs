use std::str::FromStr;
use ethereum_types::Address as EthAddress;
use bitcoin::{
    network::constants::Network as BtcNetwork,
    util::{
        key::PublicKey as BtcPublicKey,
        address::Address as BtcAddress,
    },
    blockdata::{
        script::{
            Instruction,
            Script as BtcScript,
        },
        transaction::{
            TxIn as BtcTxIn,
            TxOut as BtcTxOut,
            Transaction as BtcTransaction,
        },
    },
    consensus::encode::serialize as btc_serialize,
};
use crate::{
    traits::DatabaseInterface,
    constants::SAFE_ETH_ADDRESS,
    utils::convert_satoshis_to_ptoken,
    types::{
        Bytes,
        Result,
    },
    btc::{
        btc_state::BtcState,
        btc_constants::DEFAULT_BTC_ADDRESS,
        btc_database_utils::{
            get_btc_address_from_db,
            get_btc_network_from_db,
        },
        btc_utils::{
            get_safe_eth_address,
            get_pay_to_pub_key_hash_script,
        },
        btc_types::{
            MintingParams,
            BtcTransactions,
            MintingParamStruct,
        },
    },
};

pub const NUM_BYTES_IN_SCRIPT: u8 = 22;
pub const OP_RETURN_AS_DECIMAL: u8 = 106;
pub const NUM_BYTES_IN_ETH_ADDRESS: u8 = 20;
pub const NUM_BYTES_IN_SCRIPT_WITH_LEN_PREFIX: usize = 23;
pub const NUM_PREFIX_BYTES_IN_SERIALIZED_OP_RETURN: usize = 3;

fn extract_spender_address_from_p2pkh_input(
    input: &BtcTxIn,
    btc_network: BtcNetwork,
) -> Result<BtcAddress> {
    info!("✔ Extracting spender address from p2pkh input...");
    Ok(
        input
            .script_sig
            .iter(false)
            .enumerate()
            .filter(|(i, _)| i == &1)
            .map(|(_, script_instruction)| -> Result<BtcAddress> {
                let byte = [0u8];
                let data = match script_instruction {
                    Instruction::PushBytes(bytes) => bytes,
                    _ => &byte,
                };
                info!("✔ Instruction: {:?}", script_instruction);
                info!("✔ data: {:?}", data);
                Ok(
                    BtcAddress::p2pkh(
                        &BtcPublicKey::from_slice(data)?,
                        btc_network,
                    )
                )
            })
            .collect::<Result<Vec<BtcAddress>>>()?[0]
            .clone()
    )
}

fn parse_eth_address_from_op_return_script(
    op_return_script: &BtcScript
) -> EthAddress {
    trace!("✔ Parsing ETH address from script: {}", op_return_script);
    EthAddress::from_slice(
        &btc_serialize(op_return_script)[
            NUM_PREFIX_BYTES_IN_SERIALIZED_OP_RETURN..
        ]
    )
}

fn serialized_script_pubkey_is_desired_op_return(
    serialized_script: &Bytes
) -> bool {
    serialized_script.len() == NUM_BYTES_IN_SCRIPT_WITH_LEN_PREFIX &&
    serialized_script[0] == NUM_BYTES_IN_SCRIPT &&
    serialized_script[1] == OP_RETURN_AS_DECIMAL &&
    serialized_script[2] == NUM_BYTES_IN_ETH_ADDRESS
}

fn output_is_desired_op_return(
    output: &BtcTxOut
) -> bool {
    serialized_script_pubkey_is_desired_op_return(
        &btc_serialize(&output.script_pubkey)
    )
}

fn sum_deposit_values_from_tx_outputs(
    transaction: &BtcTransaction,
    target_deposit_script: &BtcScript,
) -> u64 {
    trace!("✔ Getting deposit values from transaction: {:?}", transaction);
    transaction
        .output
        .iter()
        .filter(|output| &output.script_pubkey == target_deposit_script)
        .map(|output| output.value)
        .sum::<u64>()
}

fn get_eth_address_from_op_return_in_tx_else_safe_address(
    transaction: &BtcTransaction,
) -> EthAddress {
    let maybe_op_return = transaction
        .output
        .iter()
        .cloned()
        .filter(output_is_desired_op_return)
        .collect::<Vec<BtcTxOut>>();

    match maybe_op_return.len() {
        0 => {
            info!(
                "✔ No address found, default to safe address: 0x{}",
                hex::encode(SAFE_ETH_ADDRESS)
            );
            get_safe_eth_address()
        }
        _ => {
            let address = parse_eth_address_from_op_return_script(
                &maybe_op_return[0].script_pubkey
            );
            info!(
                "✔ Address parsed from `op_return` script: 0x{}",
                hex::encode(address)
            );
            address
        }
    }
}

fn parse_minting_param_struct_from_tx(
    target_deposit_script: &BtcScript,
    tx: &BtcTransaction,
    btc_network: BtcNetwork,
) -> Result<MintingParamStruct> {
    Ok(
        MintingParamStruct::new(
            convert_satoshis_to_ptoken(
                sum_deposit_values_from_tx_outputs(&tx, &target_deposit_script),
            ),
            get_eth_address_from_op_return_in_tx_else_safe_address(&tx),
            tx.txid(),
            // NOTE: Currently not supporting the getting of the origin from
            // witness data.
            match tx.input[0].witness.len() == 0 {
                true => extract_spender_address_from_p2pkh_input(
                    &tx.input[0].clone(),
                    btc_network
                )?,
                false => {
                    info!("✔ Not a p2pkh script, can't get sender address");
                    BtcAddress::from_str(&DEFAULT_BTC_ADDRESS)?
                }
            }
        )
    )
}

fn parse_minting_params_from_txs(
    target_deposit_script: &BtcScript,
    op_return_deposit_containing_transactions: &BtcTransactions,
    btc_network: BtcNetwork,
) -> Result<MintingParams> {
    trace!(
        "✔ Parsing minting params from target script: {}",
        target_deposit_script
    );
    op_return_deposit_containing_transactions
        .iter()
        .map(|tx|
             parse_minting_param_struct_from_tx(
                 target_deposit_script,
                 tx,
                 btc_network
             )
        )
        .collect::<Result<Vec<MintingParamStruct>>>()
}

pub fn parse_minting_params_from_op_return_deposits_and_add_to_state<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Parsing minting params from `OP_RETURN` deposit txs in state...");
    get_btc_address_from_db(&state.db)
        .and_then(|btc_address| get_pay_to_pub_key_hash_script(&btc_address))
        .and_then(|target_deposit_script|
            parse_minting_params_from_txs(
                &target_deposit_script,
                state.get_op_return_deposit_txs()?,
                get_btc_network_from_db(&state.db)?,
            )
        )
        .and_then(|minting_params| state.add_minting_params(minting_params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc::{
        filter_op_return_deposit_txs::{
            filter_txs_for_op_return_deposits
        },
        btc_test_utils::{
            get_sample_btc_tx,
            get_sample_btc_block_n,
            get_sample_btc_private_key,
            get_sample_btc_op_return_tx,
            get_sample_op_return_output,
            get_sample_pay_to_pub_key_hash_script,
            get_sample_op_return_btc_block_and_txs,
            SAMPLE_OP_RETURN_TRANSACTION_OUTPUT_INDEX
        },
    };

    fn get_expected_eth_address() -> EthAddress {
        EthAddress::from_slice(
            &hex::decode("fedfe2616eb3661cb8fed2782f5f0cc91d59dcac").unwrap()
        )
    }

    #[test]
    fn serialized_script_pubkey_should_be_desired_op_return() {
        let op_return_output = get_sample_op_return_output();
        let serialized_output_script = btc_serialize(
            &op_return_output.script_pubkey
        );
        let result = serialized_script_pubkey_is_desired_op_return(
            &serialized_output_script
        );
        assert!(result);
    }

    #[test]
    fn correct_output_should_be_desired_op_return_output() {
        let op_return_output = get_sample_op_return_output();
        let result = output_is_desired_op_return(&op_return_output);
        assert!(result);
    }

    #[test]
    fn incorrect_output_should_not_be_desired_op_return() {
        #[allow(non_snake_case)]
        let INDEX_OF_NON_OP_RETURN_OUTPUT = 0;
        assert!(
            INDEX_OF_NON_OP_RETURN_OUTPUT !=
            SAMPLE_OP_RETURN_TRANSACTION_OUTPUT_INDEX
        );
        let tx = get_sample_btc_op_return_tx();
        let wrong_output = tx
            .output[INDEX_OF_NON_OP_RETURN_OUTPUT]
            .clone();
        let result = output_is_desired_op_return(&wrong_output);
        assert!(!result);
    }

    #[test]
    fn should_parse_eth_address_from_op_return_script() {
        let expected_result = get_expected_eth_address();
        let script = get_sample_op_return_output()
            .script_pubkey;
        let result = parse_eth_address_from_op_return_script(&script);
        assert!(result == expected_result);
    }

    #[test]
    fn should_get_first_deposit_value_from_tx() {
        let expected_result: u64 = 1337;
        let tx = get_sample_btc_op_return_tx();
        let target_script = get_sample_pay_to_pub_key_hash_script();
        let result = sum_deposit_values_from_tx_outputs(&tx, &target_script);
        assert!(result == expected_result);
    }

    #[test]
    fn should_get_eth_address_from_op_return_in_tx_else_safe_address() {
        let expected_result = get_expected_eth_address();
        let tx = get_sample_btc_op_return_tx();
        let result = get_eth_address_from_op_return_in_tx_else_safe_address(
            &tx
        );
        assert!(result == expected_result);
    }

    #[test]
    fn should_default_to_safe_address_if_no_op_return() {
        let tx_no_op_return = get_sample_btc_tx();
        let expected_result = get_safe_eth_address();
        let result = get_eth_address_from_op_return_in_tx_else_safe_address(
            &tx_no_op_return
        );
        assert!(result == expected_result);
    }

    #[test]
    fn should_parse_minting_params_from_txs() {
        let network = BtcNetwork::Testnet;
        let expected_address = get_expected_eth_address();
        let expected_value = convert_satoshis_to_ptoken(1337);
        let expected_origin_address = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM";
        let expected_tx_hash =
            "183d4334c0e06d38cebfe2387e192c3a5f24f13c612214945af95f0aec696c6b"
                .to_string();
        let block = get_sample_op_return_btc_block_and_txs()
            .block;
        let filtered_txs = filter_txs_for_op_return_deposits(
            &get_sample_btc_private_key(),
            &block.txdata,
        ).unwrap();
        let target_deposit_script = get_sample_pay_to_pub_key_hash_script();
        let result = parse_minting_params_from_txs(
            &target_deposit_script,
            &filtered_txs,
            network,
        ).unwrap();
        assert!(result.len() == 1);
        assert!(result[0].amount == expected_value);
        assert!(result[0].eth_address == expected_address);
        assert!(result[0].originating_tx_hash.to_string() == expected_tx_hash);
        let input = filtered_txs[0].input[0].clone();
        let address = extract_spender_address_from_p2pkh_input(&input, network)
            .unwrap();
        assert!(address.to_string() == expected_origin_address);
    }

    #[test]
    fn should_extract_spender_address_from_p2pkh_input() {
        let network = BtcNetwork::Testnet;
        let expected_origin_address = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM";
        let block = get_sample_op_return_btc_block_and_txs()
            .block;
        let filtered_txs = filter_txs_for_op_return_deposits(
            &get_sample_btc_private_key(),
            &block.txdata,
        ).unwrap();
        let input = filtered_txs[0].input[0].clone();
        let result = extract_spender_address_from_p2pkh_input(&input, network)
            .unwrap();
        assert!(result.to_string() == expected_origin_address);
    }

    #[test]
    fn should_parse_minting_params_from_tx() {
        let tx_index = 56;
        let network = BtcNetwork::Testnet;
        let expected_address = get_expected_eth_address();
        let expected_value = convert_satoshis_to_ptoken(1337);
        let expected_origin_address = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM";
        let expected_tx_hash =
            "183d4334c0e06d38cebfe2387e192c3a5f24f13c612214945af95f0aec696c6b"
                .to_string();
        let block = get_sample_op_return_btc_block_and_txs()
            .block;
        let tx = block.txdata[tx_index].clone();
        let target_deposit_script = get_sample_pay_to_pub_key_hash_script();
        let result = parse_minting_param_struct_from_tx(
            &target_deposit_script,
            &tx,
            network,
        ).unwrap();
        assert!(result.amount == expected_value);
        assert!(result.eth_address == expected_address);
        assert!(result.originating_tx_hash.to_string() == expected_tx_hash);
        let input = tx.input[0].clone();
        let address = extract_spender_address_from_p2pkh_input(&input, network)
            .unwrap();
        assert!(address.to_string() == expected_origin_address);
    }

    #[test]
    fn should_default_to_safe_address_if_no_op_return_present() {
        let tx_index = 36;
        let network = BtcNetwork::Testnet;
        let expected_eth_address = get_safe_eth_address();
        let expected_value = convert_satoshis_to_ptoken(4610922);
        let expected_origin_address = "moBSQbHn7N9BC9pdtAMnA7GBiALzNMQJyE";
        let expected_tx_hash =
            "9ac032f07cacce63d66fc3937ea04c032eb33852bed705e3e7a309baa8bedf19"
                .to_string();
        let block = get_sample_btc_block_n(8)
            .unwrap()
            .block;
        let tx = block.txdata[tx_index].clone();
        let target_deposit_script = get_sample_pay_to_pub_key_hash_script();
        let result = parse_minting_param_struct_from_tx(
            &target_deposit_script,
            &tx,
            network,
        ).unwrap();
        assert!(result.amount == expected_value);
        assert!(result.eth_address == expected_eth_address);
        assert!(result.originating_tx_hash.to_string() == expected_tx_hash);
        let input = tx.input[0].clone();
        let address = extract_spender_address_from_p2pkh_input(&input, network)
            .unwrap();
        assert!(address.to_string() == expected_origin_address);
    }

    // TODO Fashion a transaction w/ > 1 deposit output in OP_RETURN
    // plus another output that's NOT a deposit & use that as test vector.
}
