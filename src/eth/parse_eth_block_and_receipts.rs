use crate::{
    types::Result,
    errors::AppError,
    traits::DatabaseInterface,
    eth::{
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
    eth_block_and_receipt_json_string: &String
) -> Result<EthBlockAndReceiptsJson> {
    match serde_json::from_str(&eth_block_and_receipt_json_string) {
        Ok(result) => Ok(result),
        Err(e) => Err(AppError::Custom(e.to_string()))
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
    eth_block_and_receipts: &String
) -> Result<EthBlockAndReceipts> {
    parse_eth_block_and_receipts_json_string(eth_block_and_receipts)
        .and_then(parse_eth_block_and_receipts_json)
}

pub fn parse_eth_block_and_receipts_and_put_in_state<D>(
    block_json: String,
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
    use crate::{
        eth::eth_test_utils::{
            get_expected_block,
            get_expected_receipt,
            SAMPLE_RECEIPT_INDEX,
            get_sample_eth_block_and_receipts_string,
        },
    };

    #[test]
    fn should_parse_eth_block_and_receipts_json_string() {
        let json_string = get_sample_eth_block_and_receipts_string(0)
            .unwrap();
        if let Err(_) = parse_eth_block_and_receipts_json_string(&json_string) {
            panic!("SHould parse eth block and json string correctly!");
        }
    }

    #[test]
    fn should_parse_eth_block_and_receipts_json() {
        let json_string = get_sample_eth_block_and_receipts_string(0)
            .unwrap();
        match parse_eth_block_and_receipts(&json_string) {
            Err(_) => panic!("Should parse block & receipt correctly!"),
            Ok(block_and_receipt) => {
                let block = block_and_receipt
                    .block
                    .clone();
                let receipt = block_and_receipt
                    .receipts[SAMPLE_RECEIPT_INDEX].clone();
                let expected_block = get_expected_block();
                let expected_receipt = get_expected_receipt();
                assert!(block == expected_block);
                assert!(receipt == expected_receipt);
            }
        }
    }

    #[test]
    fn should_parse_eth_block_and_receipts() {
        let json_string = get_sample_eth_block_and_receipts_string(0)
            .unwrap();
        match parse_eth_block_and_receipts(&json_string) {
            Err(_) => panic!("Should parse block & receipt correctly!"),
            Ok(block_and_receipt) => {
                let block = block_and_receipt
                    .block
                    .clone();
                let receipt = block_and_receipt
                    .receipts[SAMPLE_RECEIPT_INDEX].clone();
                let expected_block = get_expected_block();
                let expected_receipt = get_expected_receipt();
                assert!(block == expected_block);
                assert!(receipt == expected_receipt);
            }
        }
    }
}
