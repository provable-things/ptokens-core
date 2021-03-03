#![cfg(test)]
use std::{fs::read_to_string, path::Path, str::FromStr};

use ethereum_types::{Address as EthAddress, H256 as EthHash, U256};

use crate::{
    chains::eth::{
        eth_block::{EthBlock, EthBlockJson},
        eth_crypto::{eth_private_key::EthPrivateKey, eth_public_key::EthPublicKey, eth_transaction::EthTransaction},
        eth_database_utils::{get_special_eth_hash_from_db, put_special_eth_block_in_db},
        eth_log::{EthLog, EthLogs},
        eth_receipt::EthReceipt,
        eth_state::EthState,
        eth_submission_material::{EthSubmissionMaterial, EthSubmissionMaterialJson},
        eth_types::TrieHashMap,
        nibble_utils::{get_nibbles_from_bytes, get_nibbles_from_offset_bytes, Nibbles},
        trie_nodes::Node,
    },
    erc20_on_eos::eth::peg_in_info::{Erc20OnEosPegInInfo, Erc20OnEosPegInInfos},
    errors::AppError,
    test_utils::{get_test_database, TestDB},
    traits::DatabaseInterface,
    types::{Bytes, Result},
};

pub const HASH_HEX_CHARS: usize = 64;
pub const HEX_PREFIX_LENGTH: usize = 2;
pub const SAMPLE_RECEIPT_INDEX: usize = 2;
pub const SEQUENTIAL_BLOCKS_FIRST_NUMBER: usize = 8065750;

pub const ETH_SMART_CONTRACT_BYTECODE_PATH: &str = "./src/chains/eth/eth_test_utils/ptoken-erc777-bytecode";

pub const SAMPLE_BLOCK_JSON_PATH: &str = "src/chains/eth/eth_test_utils/sample-block-json";

pub const SAMPLE_RECEIPT_JSON_PATH: &str = "src/chains/eth/eth_test_utils/sample-receipt-json";

pub const SAMPLE_PTOKEN_CONTRACT_ADDRESS: &str = "60a640e2d10e020fee94217707bfa9543c8b59e0";

pub const SAMPLE_BLOCK_AND_RECEIPT_JSON: &str = "src/chains/eth/eth_test_utils/sample-eth-block-and-receipts-json";

pub const SAMPLE_INVALID_BLOCK_AND_RECEIPT_JSON: &str =
    "src/chains/eth/eth_test_utils/sample-invalid-eth-block-and-receipts-json";

// NOTE: Hash of an ERC20 transfer fxn signature: keccak256("Transfer(address,address,uint256)")
pub const TEMPORARY_CONTRACT_TOPIC: &str = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

pub const SAMPLE_SEQUENTIAL_BLOCK_AND_RECEIPT_JSONS_PATH_PREFIX: &str =
    "src/chains/eth/eth_test_utils/sequential_block_and_receipts_jsons/eth_block_and_receipts_num_";

pub const SAMPLE_BLOCK_AND_RECEIPT_JSON_1: &str =
    "src/chains/eth/eth_test_utils/eth-7004586-ropsten-eth-block-and-receipts.json";

pub const SAMPLE_BLOCK_AND_RECEIPT_JSON_2: &str =
    "src/chains/eth/eth_test_utils/eth-7120953-ropsten-eth-block-and-receipts.json";

pub const SAMPLE_BLOCK_AND_RECEIPT_JSON_3: &str =
    "src/chains/eth/eth_test_utils/eth-7129763-ropsten-eth-block-and-receipts.json";

pub const SAMPLE_BLOCK_AND_RECEIPT_JSON_4: &str =
    "src/chains/eth/eth_test_utils/eth-7420497-ropsten-eth-block-and-receipts.json";

pub const SAMPLE_BLOCK_AND_RECEIPT_JSON_5: &str =
    "src/chains/eth/eth_test_utils/eth-7418933-ropsten-eth-block-and-receipts.json";

pub const SAMPLE_BLOCK_AND_RECEIPT_JSON_6: &str =
    "src/chains/eth/eth_test_utils/eth-7425517-ropsten-eth-block-and-receipts.json";

pub const SAMPLE_BLOCK_AND_RECEIPT_JSON_7: &str =
    "src/chains/eth/eth_test_utils/eth-submission-material-block-8739996-with-erc20-peg-in-event.json";

pub const SAMPLE_BLOCK_AND_RECEIPT_JSON_8: &str =
    "src/chains/eth/eth_test_utils/eth-submission-material-block-11011551.json";

pub const SAMPLE_BLOCK_AND_RECEIPT_JSON_9: &str =
    "src/chains/eth/eth_test_utils/eth-submission-material-block-11087536-with-erc20-peg-in-event.json";

pub fn put_eth_latest_block_in_db<D>(db: &D, eth_submission_material: &EthSubmissionMaterial) -> Result<()>
where
    D: DatabaseInterface,
{
    info!("✔ Putting ETH latest block in db...");
    put_special_eth_block_in_db(db, eth_submission_material, "latest")
}

pub fn put_eth_anchor_block_in_db<D>(db: &D, eth_submission_material: &EthSubmissionMaterial) -> Result<()>
where
    D: DatabaseInterface,
{
    info!("✔ Putting ETH anchor block in db...");
    put_special_eth_block_in_db(db, eth_submission_material, "anchor")
}

pub fn put_eth_tail_block_in_db<D>(db: &D, eth_submission_material: &EthSubmissionMaterial) -> Result<()>
where
    D: DatabaseInterface,
{
    info!("✔ Putting ETH tail block in db...");
    put_special_eth_block_in_db(db, eth_submission_material, "tail")
}

pub fn get_eth_latest_block_hash_from_db<D>(db: &D) -> Result<EthHash>
where
    D: DatabaseInterface,
{
    info!("✔ Getting ETH latest block hash from db...");
    get_special_eth_hash_from_db(db, "latest")
}

pub fn get_eth_canon_block_hash_from_db<D>(db: &D) -> Result<EthHash>
where
    D: DatabaseInterface,
{
    info!("✔ Getting ETH canon block hash from db...");
    get_special_eth_hash_from_db(db, "canon")
}

pub fn get_eth_linker_hash_from_db<D>(db: &D) -> Result<EthHash>
where
    D: DatabaseInterface,
{
    info!("✔ Getting ETH linker hash from db...");
    get_special_eth_hash_from_db(db, "linker")
}

pub fn convert_h256_to_prefixed_hex(hash: EthHash) -> String {
    format!("0x{}", hex::encode(hash))
}

pub fn get_sample_eth_submission_material_string(num: usize) -> Result<String> {
    let path = match num {
        0 => Ok(SAMPLE_BLOCK_AND_RECEIPT_JSON),
        1 => Ok(SAMPLE_BLOCK_AND_RECEIPT_JSON_1),
        2 => Ok(SAMPLE_BLOCK_AND_RECEIPT_JSON_2),
        3 => Ok(SAMPLE_BLOCK_AND_RECEIPT_JSON_3),
        4 => Ok(SAMPLE_BLOCK_AND_RECEIPT_JSON_4),
        5 => Ok(SAMPLE_BLOCK_AND_RECEIPT_JSON_5),
        6 => Ok(SAMPLE_BLOCK_AND_RECEIPT_JSON_6),
        7 => Ok(SAMPLE_BLOCK_AND_RECEIPT_JSON_7),
        8 => Ok(SAMPLE_BLOCK_AND_RECEIPT_JSON_8),
        9 => Ok(SAMPLE_BLOCK_AND_RECEIPT_JSON_9),
        _ => Err(AppError::Custom(format!("Cannot find sample block num: {}", num))),
    }?;
    match Path::new(&path).exists() {
        true => Ok(read_to_string(path)?),
        false => Err("✘ Cannot find sample-eth-block-and-receipts-json file!".into()),
    }
}

pub fn get_sample_eth_submission_material_n(num: usize) -> Result<EthSubmissionMaterial> {
    get_sample_eth_submission_material_string(num).and_then(|s| EthSubmissionMaterial::from_str(&s))
}

pub fn get_sample_receipt_n(sample_block_num: usize, receipt_index: usize) -> Result<EthReceipt> {
    get_sample_eth_submission_material_n(sample_block_num).map(|block| block.receipts.0[receipt_index].clone())
}

pub fn get_sample_log_n(sample_block_num: usize, receipt_index: usize, log_index: usize) -> Result<EthLog> {
    get_sample_receipt_n(sample_block_num, receipt_index).map(|receipt| receipt.logs.0[log_index].clone())
}

pub fn get_sample_contract_topic() -> EthHash {
    EthHash::from_slice(&hex::decode(TEMPORARY_CONTRACT_TOPIC).unwrap())
}

pub fn get_sample_contract_topics() -> Vec<EthHash> {
    vec![EthHash::from_slice(&hex::decode(TEMPORARY_CONTRACT_TOPIC).unwrap())]
}

pub fn get_sample_contract_address() -> EthAddress {
    EthAddress::from_slice(&hex::decode(SAMPLE_PTOKEN_CONTRACT_ADDRESS).unwrap())
}

pub fn get_sample_eth_private_key_slice() -> [u8; 32] {
    [
        // NOTE: pEOS-test-eth-account.
        232, 238, 178, 99, 26, 180, 118, 218, 205, 104, 248, 78, 176, 185, 238, 85, 139, 135, 47, 81, 85, 160, 136, 191,
        116, 56, 27, 95, 44, 99, 161, 48,
    ]
}

pub fn get_sample_eth_public_key_bytes() -> Bytes {
    vec![
        4, 217, 81, 73, 242, 234, 58, 7, 133, 35, 210, 143, 184, 251, 13, 88, 159, 138, 140, 142, 144, 217, 104, 138,
        155, 220, 188, 217, 127, 67, 225, 87, 167, 78, 197, 33, 183, 253, 49, 126, 74, 2, 189, 129, 237, 88, 34, 214,
        255, 147, 234, 120, 213, 41, 205, 42, 124, 45, 25, 110, 201, 146, 208, 7, 84,
    ]
}

pub fn get_sample_eth_address_string() -> String {
    "1739624f5cd969885a224da84418d12b8570d61a".to_string()
}

pub fn get_sample_eth_address() -> EthAddress {
    EthAddress::from_slice(&hex::decode(get_sample_eth_address_string()).unwrap())
}

pub fn get_sample_eth_private_key() -> EthPrivateKey {
    EthPrivateKey::from_slice(&get_sample_eth_private_key_slice()).unwrap()
}

pub fn get_sample_eth_public_key() -> EthPublicKey {
    get_sample_eth_private_key().to_public_key()
}

pub fn get_sequential_eth_blocks_and_receipts() -> Vec<EthSubmissionMaterial> {
    let mut block_and_receipts = Vec::new();
    for i in 0..20 {
        let path = format!(
            "{}{}.json",
            SAMPLE_SEQUENTIAL_BLOCK_AND_RECEIPT_JSONS_PATH_PREFIX,
            SEQUENTIAL_BLOCKS_FIRST_NUMBER + i,
        );
        let block_and_receipt = EthSubmissionMaterial::from_str(&read_to_string(path).unwrap()).unwrap();
        block_and_receipts.push(block_and_receipt)
    }
    block_and_receipts
}

pub fn get_sample_receipt_with_desired_topic() -> EthReceipt {
    get_sample_eth_submission_material().receipts.0[2].clone()
}

pub fn get_sample_receipt_with_desired_address() -> EthReceipt {
    get_sample_eth_submission_material().receipts.0[2].clone()
}

pub fn get_sample_logs_with_desired_topic() -> EthLogs {
    get_sample_receipt_with_desired_topic().logs
}

pub fn get_sample_logs_with_desired_address() -> EthLogs {
    get_sample_receipt_with_desired_address().logs
}

pub fn get_sample_log_with_desired_topic() -> EthLog {
    get_sample_logs_with_desired_topic().0[0].clone()
}

pub fn get_sample_log_with_desired_address() -> EthLog {
    get_sample_logs_with_desired_address().0[0].clone()
}

pub fn get_sample_receipt_without_desired_topic() -> EthReceipt {
    get_sample_eth_submission_material().receipts.0[9].clone()
}

pub fn get_sample_receipt_without_desired_address() -> EthReceipt {
    // NOTE: Has neither topic nor log
    get_sample_receipt_without_desired_topic()
}

pub fn get_sample_logs_without_desired_topic() -> EthLogs {
    get_sample_receipt_without_desired_topic().logs
}

pub fn get_sample_log_without_desired_topic() -> EthLog {
    get_sample_logs_without_desired_topic().0[0].clone()
}

pub fn get_sample_log_without_desired_address() -> EthLog {
    // NOTE: Has neither topic nor log
    get_sample_log_without_desired_topic()
}

pub fn convert_hex_string_to_nibbles(hex_string: String) -> Result<Nibbles> {
    match hex_string.len() % 2 == 0 {
        true => Ok(get_nibbles_from_bytes(hex::decode(hex_string)?)),
        false => Ok(get_nibbles_from_offset_bytes(hex::decode(format!("0{}", hex_string))?)),
    }
}

pub fn get_sample_leaf_node() -> Node {
    let path_bytes = vec![0x12, 0x34, 0x56];
    let path_nibbles = get_nibbles_from_bytes(path_bytes);
    let value = hex::decode("c0ffee".to_string()).unwrap();
    Node::new_leaf(path_nibbles, value).unwrap()
}

pub fn get_sample_extension_node() -> Node {
    let path_bytes = vec![0xc0, 0xff, 0xee];
    let path_nibbles = get_nibbles_from_bytes(path_bytes);
    let value = hex::decode("1d237c84432c78d82886cb7d6549c179ca51ebf3b324d2a3fa01af6a563a9377".to_string()).unwrap();
    Node::new_extension(path_nibbles, value).unwrap()
}

pub fn get_sample_branch_node() -> Node {
    let branch_value_1 = hex::decode("4f81663d4c7aeb115e49625430e3fa114445dc0a9ed73a7598a31cd60808a758").unwrap();
    let branch_value_2 = hex::decode("d55a192f93e0576f46019553e2b4c0ff4b8de57cd73020f751aed18958e9ecdb").unwrap();
    let index_1 = 1;
    let index_2 = 2;
    let value = None;
    Node::new_branch(value)
        .and_then(|node| node.update_branch_at_index(Some(branch_value_1), index_1))
        .and_then(|node| node.update_branch_at_index(Some(branch_value_2), index_2))
        .unwrap()
}

pub fn get_thing_to_put_in_trie_hash_map() -> Bytes {
    b"Provable".to_vec()
}

pub fn get_trie_hash_map_with_thing_in_it() -> Result<TrieHashMap> {
    let mut trie_hash_map: TrieHashMap = std::collections::HashMap::new();
    trie_hash_map.insert(
        get_expected_key_of_thing_in_trie_hash_map(),
        get_thing_to_put_in_trie_hash_map(),
    );
    Ok(trie_hash_map)
}

pub fn get_expected_key_of_thing_in_trie_hash_map() -> EthHash {
    EthHash::zero()
}

pub fn get_valid_state_with_invalid_block_and_receipts() -> Result<EthState<TestDB>> {
    match Path::new(&SAMPLE_BLOCK_AND_RECEIPT_JSON).exists() {
        false => Err("✘ Cannot find sample-eth-block-and-receipts-json file!".into()),
        true => {
            let s = read_to_string(SAMPLE_INVALID_BLOCK_AND_RECEIPT_JSON).unwrap();
            let invalid_struct = EthSubmissionMaterial::from_str(&s).unwrap();
            let state = get_valid_eth_state().unwrap();
            let final_state = state.add_eth_submission_material(invalid_struct).unwrap();
            Ok(final_state)
        },
    }
}

pub fn get_sample_invalid_block() -> EthBlock {
    let mut invalid_block = get_sample_eth_submission_material().get_block().unwrap();
    invalid_block.timestamp = U256::from(1234);
    invalid_block
}

pub fn get_sample_eth_submission_material_json() -> Result<EthSubmissionMaterialJson> {
    get_sample_eth_submission_material_string(0)
        .and_then(|eth_submission_material_json_string| Ok(serde_json::from_str(&eth_submission_material_json_string)?))
}

pub fn get_sample_eth_submission_material() -> EthSubmissionMaterial {
    let s = get_sample_eth_submission_material_string(0).unwrap();
    EthSubmissionMaterial::from_str(&s).unwrap()
}

pub fn get_valid_state_with_block_and_receipts() -> Result<EthState<TestDB>> {
    get_valid_eth_state().and_then(|state| state.add_eth_submission_material(get_sample_eth_submission_material()))
}

pub fn get_expected_block() -> EthBlock {
    let s = read_to_string(SAMPLE_BLOCK_JSON_PATH).unwrap();
    let eth_block_json: EthBlockJson = serde_json::from_str(&s).unwrap();
    EthBlock::from_json(&eth_block_json).unwrap()
}

pub fn get_expected_receipt() -> EthReceipt {
    EthReceipt::from_json(&serde_json::from_str(&read_to_string(SAMPLE_RECEIPT_JSON_PATH).unwrap()).unwrap()).unwrap()
}

pub fn get_expected_log() -> EthLog {
    get_expected_receipt().logs.0[0].clone()
}

pub fn get_valid_eth_state() -> Result<EthState<TestDB>> {
    Ok(EthState::init(get_test_database()))
}

pub fn get_sample_unsigned_eth_transaction() -> EthTransaction {
    let data = vec![];
    let nonce = 0;
    let value = 1;
    let to = EthAddress::from_slice(&hex::decode("53c2048dad4fcfab44C3ef3D16E882b5178df42b").unwrap());
    let chain_id = 4; // Rinkeby
    let gas_limit = 100_000;
    let gas_price = 20_000_000_000;
    EthTransaction::new_unsigned(data, nonce, value, to, chain_id, gas_limit, gas_price)
}

mod tests {
    use super::*;
    use crate::chains::eth::eth_utils::convert_hex_to_h256;

    #[test]
    fn should_get_expected_log_correctly() {
        let result = get_expected_log();
        let expected_result = get_expected_log();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_expected_receipt_correctly() {
        let expected_result = get_expected_receipt();
        let result = get_expected_receipt();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_expected_block_correctly() {
        let result = get_expected_block();
        let expected_block = get_expected_block();
        assert_eq!(result, expected_block);
    }

    #[test]
    fn should_get_sample_eth_block_and_receipt_json() {
        let expected_block_field = "block";
        let expected_block_number = "8003897";
        let expected_receipts_field = "receipts";
        let expected_tx_hash = "0x49b980475527f989936ddc8afd1e045612cd567238bb567dbd99b48ad15860dc";
        let expected_block_hash = "0xb626a7546311dd56c6f5e9fd07d00c86074077bbd6d5a4c4f8269a2490aa47c0";
        let result = get_sample_eth_submission_material_string(0).unwrap();
        assert!(result.contains(expected_tx_hash));
        assert!(result.contains(expected_block_hash));
        assert!(result.contains(expected_block_field));
        assert!(result.contains(expected_block_number));
        assert!(result.contains(expected_receipts_field));
    }

    #[test]
    fn should_get_sample_eth_submission_material_json() {
        let expected_block_number = 8503804;
        let result = get_sample_eth_submission_material_json().unwrap().block.unwrap().number;
        assert_eq!(result, expected_block_number);
    }

    #[test]
    fn should_get_sample_eth_submission_material() {
        let expected_receipt = get_expected_receipt();
        let result = get_sample_eth_submission_material();
        let block = result.get_block().unwrap();
        let receipt = result.receipts.0[SAMPLE_RECEIPT_INDEX].clone();
        let expected_block = get_expected_block();
        assert_eq!(receipt, expected_receipt);
        assert_eq!(block, expected_block);
    }

    #[test]
    fn should_get_valid_eth_state() {
        if let Err(e) = get_valid_eth_state() {
            panic!("Error getting state: {}", e);
        }
    }

    #[test]
    fn should_get_valid_state_with_blocks_and_receipts() {
        let result = get_valid_state_with_block_and_receipts().unwrap();
        if let Err(e) = result.get_eth_submission_material() {
            panic!("Error getting eth block and receipt from state: {}", e)
        }
    }

    #[test]
    fn should_get_sample_invalid_block() {
        let invalid_block = get_sample_invalid_block();
        let is_valid = invalid_block.is_valid().unwrap();
        assert!(!is_valid)
    }

    #[test]
    fn should_get_valid_state_with_invalid_block_and_receipts() {
        let state = get_valid_state_with_invalid_block_and_receipts().unwrap();
        let is_valid = state
            .get_eth_submission_material()
            .unwrap()
            .get_block()
            .unwrap()
            .is_valid()
            .unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn should_convert_hex_string_to_nibbles() {
        let bytes = vec![0xc0, 0xff, 0xee];
        let hex_string = "c0ffee".to_string();
        let expected_result = get_nibbles_from_bytes(bytes);
        let result = convert_hex_string_to_nibbles(hex_string).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_offset_hex_string_to_nibbles() {
        let bytes = vec![0xdu8, 0xec, 0xaf];
        let hex_string = "decaf".to_string();
        let expected_result = get_nibbles_from_offset_bytes(bytes);
        let result = convert_hex_string_to_nibbles(hex_string).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn sample_log_with_desired_topic_should_contain_topic() {
        let desired_topic = convert_hex_to_h256(TEMPORARY_CONTRACT_TOPIC).unwrap();
        let result = get_sample_log_with_desired_topic()
            .topics
            .iter()
            .any(|log_topic| *log_topic == desired_topic);
        assert!(result);
    }

    #[test]
    fn sample_log_without_desired_topic_should_contain_topic() {
        let desired_topic = convert_hex_to_h256(TEMPORARY_CONTRACT_TOPIC).unwrap();
        let result = get_sample_log_without_desired_topic()
            .topics
            .iter()
            .any(|log_topic| *log_topic == desired_topic);
        assert!(!result);
    }

    #[test]
    fn sample_logs_with_desired_topic_should_contain_topic() {
        let desired_topic = convert_hex_to_h256(TEMPORARY_CONTRACT_TOPIC).unwrap();
        let result = get_sample_logs_with_desired_topic()
            .0
            .iter()
            .any(|log| log.contains_topic(&desired_topic));
        assert!(result);
    }

    #[test]
    fn sample_logs_without_desired_topic_should_contain_topic() {
        let desired_topic = convert_hex_to_h256(TEMPORARY_CONTRACT_TOPIC).unwrap();
        let result = get_sample_logs_without_desired_topic()
            .0
            .iter()
            .any(|log| log.contains_topic(&desired_topic));
        assert!(!result);
    }

    #[test]
    fn sample_receipts_with_desired_topic_should_contain_topic() {
        let desired_topic = convert_hex_to_h256(TEMPORARY_CONTRACT_TOPIC).unwrap();
        let result = get_sample_receipt_with_desired_topic()
            .logs
            .contain_topic(&desired_topic);
        assert!(result);
    }

    #[test]
    fn sample_receipts_without_desired_topic_should_not_contain_topic() {
        let desired_topic = convert_hex_to_h256(TEMPORARY_CONTRACT_TOPIC).unwrap();
        let result = get_sample_receipt_without_desired_topic()
            .logs
            .contain_topic(&desired_topic);
        assert!(!result);
    }

    #[test]
    fn should_get_sequential_block_and_receipts() {
        let block_and_receipts = get_sequential_eth_blocks_and_receipts();
        block_and_receipts.iter().enumerate().for_each(|(i, block)| {
            assert_eq!(
                block.get_block_number().unwrap().as_usize(),
                SEQUENTIAL_BLOCKS_FIRST_NUMBER + i
            )
        });
    }
}

pub fn get_sample_submission_material_with_erc20_peg_in_event() -> Result<EthSubmissionMaterial> {
    get_sample_eth_submission_material_n(7)
}

pub fn get_sample_receipt_with_erc20_peg_in_event() -> Result<EthReceipt> {
    get_sample_receipt_n(7, 17)
}

pub fn get_sample_log_with_erc20_peg_in_event() -> Result<EthLog> {
    get_sample_log_n(7, 17, 1)
}

pub fn get_sample_log_with_erc20_peg_in_event_2() -> Result<EthLog> {
    get_sample_log_n(9, 16, 1)
}

// TODO The eth->eos decimal conversion makes this a bad example now. Get a better one!
pub fn get_sample_erc20_on_eos_peg_in_info() -> Result<Erc20OnEosPegInInfo> {
    Ok(Erc20OnEosPegInInfo::new(
        U256::from_dec_str("1337").unwrap(),
        EthAddress::from_slice(&hex::decode("fedfe2616eb3661cb8fed2782f5f0cc91d59dcac").unwrap()),
        EthAddress::from_slice(&hex::decode("9f57cb2a4f462a5258a49e88b4331068a391de66").unwrap()),
        "aneosaddress".to_string(),
        EthHash::from_slice(&hex::decode("241f386690b715422102edf42f5c9edcddea16b64f17d02bad572f5f341725c0").unwrap()),
        "SampleToken".to_string(),
        "0.000000000 SAM".to_string(),
    ))
}

pub fn get_sample_erc20_on_eos_peg_in_infos() -> Result<Erc20OnEosPegInInfos> {
    Ok(Erc20OnEosPegInInfos::new(vec![get_sample_erc20_on_eos_peg_in_info()?]))
}

fn get_tx_hash_of_erc777_redeem() -> &'static str {
    "442612aba789ce873bb3804ff62ced770dcecb07d19ddcf9b651c357eebaed40"
}

fn get_sample_block_with_erc777_redeem() -> EthSubmissionMaterial {
    get_sample_eth_submission_material_n(4).unwrap()
}

pub fn get_sample_receipt_with_erc777_redeem() -> EthReceipt {
    let hash = EthHash::from_str(get_tx_hash_of_erc777_redeem()).unwrap();
    get_sample_block_with_erc777_redeem()
        .receipts
        .0
        .iter()
        .filter(|receipt| receipt.transaction_hash == hash)
        .collect::<Vec<&EthReceipt>>()[0]
        .clone()
}

pub fn get_sample_log_with_erc777_redeem() -> EthLog {
    get_sample_receipt_with_erc777_redeem().logs.0[2].clone()
}
