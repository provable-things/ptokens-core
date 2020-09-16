use ethereum_types::{
    U256,
    Bloom,
};
use crate::{
    types::Result,
    btc_on_eth::{
        eth::eth_types::{
            EthBlock,
            EthBlockJson,
        },
        utils::{
            decode_prefixed_hex,
            convert_hex_to_h256,
            convert_hex_to_bytes,
            convert_hex_to_address,
            convert_dec_str_to_u256,
            convert_hex_strings_to_h256s,
        },
    },
};

pub fn parse_eth_block_json(
    eth_block_json: EthBlockJson
) -> Result<EthBlock> {
    Ok(
        EthBlock {
            size: U256::from(eth_block_json.size),
            number: U256::from(eth_block_json.number),
            gas_used: U256::from(eth_block_json.gasUsed),
            gas_limit: U256::from(eth_block_json.gasLimit),
            hash: convert_hex_to_h256(&eth_block_json.hash)?,
            timestamp: U256::from(eth_block_json.timestamp),
            nonce: decode_prefixed_hex(&eth_block_json.nonce)?,
            miner: convert_hex_to_address(&eth_block_json.miner)?,
            mix_hash: convert_hex_to_h256(&eth_block_json.mixHash)?,
            state_root: convert_hex_to_h256(&eth_block_json.stateRoot)?,
            extra_data: convert_hex_to_bytes(&eth_block_json.extraData)?,
            parent_hash: convert_hex_to_h256(&eth_block_json.parentHash)?,
            sha3_uncles: convert_hex_to_h256(&eth_block_json.sha3Uncles)?,
            difficulty: convert_dec_str_to_u256(&eth_block_json.difficulty)?,
            receipts_root: convert_hex_to_h256(&eth_block_json.receiptsRoot)?,
            transactions_root: convert_hex_to_h256(&eth_block_json.transactionsRoot)?,
            total_difficulty: convert_dec_str_to_u256(&eth_block_json.totalDifficulty)?,
            logs_bloom: Bloom::from_slice(&convert_hex_to_bytes(&eth_block_json.logsBloom)?[..]),
            uncles: convert_hex_strings_to_h256s(eth_block_json.uncles.iter().map(AsRef::as_ref).collect())?,
            transactions: convert_hex_strings_to_h256s(eth_block_json.transactions.iter().map(AsRef::as_ref).collect())?,
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_on_eth::eth::eth_test_utils::{
        get_expected_block,
        get_sample_eth_block_and_receipts_json,
    };

    #[test]
    fn should_parse_eth_block_json_to_eth_block() {
        let eth_json = get_sample_eth_block_and_receipts_json().unwrap();
        match parse_eth_block_json(eth_json.block) {
            Ok(block) => assert_eq!(block, get_expected_block()),
            _ => panic!("Failed to get eth block json!"),
        }
    }
}
