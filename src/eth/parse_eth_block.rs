use ethereum_types::{
    U256,
    Bloom,
};
use crate::{
    types::Result,
    eth::eth_types::{
        EthBlock,
        EthBlockJson,
    },
    utils::{
        decode_prefixed_hex,
        convert_hex_to_u256,
        convert_hex_to_h256,
        convert_hex_to_bytes,
        convert_hex_to_address,
        convert_dec_str_to_u256,
        convert_hex_strings_to_h256s,
    },
};

pub fn parse_eth_block_json(
    eth_block_json: EthBlockJson
) -> Result<EthBlock> {
    Ok(
        EthBlock {
            difficulty: convert_dec_str_to_u256(
                &eth_block_json.difficulty
            )?,
            extra_data: convert_hex_to_bytes(
                eth_block_json.extraData
            )?,
            gas_limit: U256::from(
                eth_block_json.gasLimit
            ),
            gas_used: U256::from(
                eth_block_json.gasUsed
            ),
            hash: convert_hex_to_h256(
                eth_block_json.hash
            )?,
            logs_bloom: Bloom::from_slice(
                &convert_hex_to_bytes(eth_block_json.logsBloom)?[..]
            ),
            miner: convert_hex_to_address(
                eth_block_json.miner
            )?,
            mix_hash: convert_hex_to_h256(
                eth_block_json.mixHash
            )?,
            nonce: decode_prefixed_hex(eth_block_json.nonce)?,
            number: U256::from(
                eth_block_json.number
            ),
            parent_hash: convert_hex_to_h256(
                eth_block_json.parentHash
            )?,
            receipts_root: convert_hex_to_h256(
                eth_block_json.receiptsRoot
            )?,
            seal_fields: (
                convert_hex_to_bytes(eth_block_json.sealFields.0)?,
                convert_hex_to_u256(eth_block_json.sealFields.1)?
            ),
            sha3_uncles: convert_hex_to_h256(
                eth_block_json.sha3Uncles
            )?,
            size: U256::from(
                eth_block_json.size
            ),
            state_root: convert_hex_to_h256(
                eth_block_json.stateRoot
            )?,
            timestamp: U256::from(
                eth_block_json.timestamp
            ),
            total_difficulty: convert_dec_str_to_u256(
                &eth_block_json.totalDifficulty
            )?,
            transactions: convert_hex_strings_to_h256s(
                eth_block_json.transactions
            )?,
            transactions_root: convert_hex_to_h256(
                eth_block_json.transactionsRoot
            )?,
            uncles: convert_hex_strings_to_h256s(
                eth_block_json.uncles
            )?,
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth::eth_test_utils::{
        get_expected_block,
        get_sample_eth_block_and_receipts_json,
    };

    #[test]
    fn should_parse_eth_block_json_to_eth_block() {
        let eth_json = get_sample_eth_block_and_receipts_json()
            .unwrap();
        match parse_eth_block_json(eth_json.block) {
            Err(_) => panic!("Failed to get eth block json!"),
            Ok(block) => assert!(block == get_expected_block()),
        }
    }
}
