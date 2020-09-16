use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eth::eth::{
        eth_state::EthState,
        parse_eth_block::parse_eth_block_json,
        parse_eth_receipt::parse_eth_receipt_jsons,
        eth_types::{
            EthBlockAndReceipts,
            EthBlockAndReceiptsJson,
        },
    },
};

fn parse_eth_block_and_receipts_json_string(
    eth_block_and_receipt_json_string: &str
) -> Result<EthBlockAndReceiptsJson> {
    match serde_json::from_str(&eth_block_and_receipt_json_string) {
        Ok(result) => Ok(result),
        Err(err) => Err(err.into())
    }
}

pub fn parse_eth_block_and_receipts_json(
    eth_block_and_receipt_json: EthBlockAndReceiptsJson
) -> Result<EthBlockAndReceipts> {
    Ok(
        EthBlockAndReceipts {
            block: parse_eth_block_json(
                eth_block_and_receipt_json.block.clone()
            )?,
            receipts: parse_eth_receipt_jsons(
                eth_block_and_receipt_json.receipts
            )?,
        }
    )
}

pub fn parse_eth_block_and_receipts(
    eth_block_and_receipts: &str
) -> Result<EthBlockAndReceipts> {
    parse_eth_block_and_receipts_json_string(eth_block_and_receipts)
        .and_then(parse_eth_block_and_receipts_json)
}

pub fn parse_eth_block_and_receipts_and_put_in_state<D>(
    block_json: &str,
    state: EthState<D>,
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    parse_eth_block_and_receipts(&block_json)
        .and_then(|result| state.add_eth_block_and_receipts(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_on_eth::{
        eth::eth_test_utils::{
            get_expected_block,
            get_expected_receipt,
            SAMPLE_RECEIPT_INDEX,
            get_sample_eth_block_and_receipts_string,
        },
    };

    #[test]
    fn should_parse_eth_block_and_receipts_json_string() {
        let json_string = get_sample_eth_block_and_receipts_string(0).unwrap();
        if parse_eth_block_and_receipts_json_string(&json_string).is_err() {
            panic!("SHould parse eth block and json string correctly!");
        }
    }

    #[test]
    fn should_parse_eth_block_and_receipts_json() {
        let json_string = get_sample_eth_block_and_receipts_string(0).unwrap();
        match parse_eth_block_and_receipts(&json_string) {
            Ok(block_and_receipt) => {
                let block = block_and_receipt
                    .block
                    .clone();
                let receipt = block_and_receipt
                    .receipts[SAMPLE_RECEIPT_INDEX].clone();
                let expected_block = get_expected_block();
                let expected_receipt = get_expected_receipt();
                assert_eq!(block, expected_block);
                assert_eq!(receipt, expected_receipt);
            }
            _ => panic!("Should parse block & receipt correctly!"),
        }
    }

    #[test]
    fn should_parse_eth_block_and_receipts() {
        let json_string = get_sample_eth_block_and_receipts_string(0).unwrap();
        match parse_eth_block_and_receipts(&json_string) {
            Ok(block_and_receipt) => {
                let block = block_and_receipt
                    .block
                    .clone();
                let receipt = block_and_receipt
                    .receipts[SAMPLE_RECEIPT_INDEX].clone();
                let expected_block = get_expected_block();
                let expected_receipt = get_expected_receipt();
                assert_eq!(block, expected_block);
                assert_eq!(receipt, expected_receipt);
            }
            _ => panic!("Should parse block & receipt correctly!"),
        }
    }
}
