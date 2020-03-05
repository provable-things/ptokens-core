use ethereum_types::H256;
use crate::{
    types::Result,
    errors::AppError,
    traits::DatabaseInterface,
    eth::rlp_codec::get_rlp_encoded_receipts_and_nibble_tuples,
    eth::{
        eth_state::EthState,
        eth_types::{
            EthBlock,
            EthReceipts,
        },
        trie::{
            Trie,
            put_in_trie_recursively,
        },
    },
};

fn get_receipts_root_from_receipts(receipts: &EthReceipts) -> Result<H256> {
    get_rlp_encoded_receipts_and_nibble_tuples(receipts)
        .and_then(|key_value_tuples| {
            info!("✔ Building merkle-patricia trie from receipts...");
            put_in_trie_recursively(
                Trie::get_new_trie()?,
                key_value_tuples,
                0,
            )
        })
        .map(|trie| trie.root)
}

fn receipts_root_is_correct(
    block: &EthBlock,
    receipts: &EthReceipts,
) -> Result<bool> {
    info!("✔ Checking trie root against receipts root...");
    get_receipts_root_from_receipts(receipts)
        .map(|root| root == block.receipts_root)
}

pub fn validate_receipts_in_state<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Validating receipts...");
    match receipts_root_is_correct(
        &state.get_eth_block_and_receipts()?.block,
        &state.get_eth_block_and_receipts()?.receipts,
    )? {
        true => {
            info!("✔ Receipts are valid!");
            Ok(state)
        },
        false => Err(AppError::Custom(
            format!("✘ Not accepting ETH block - receipts root not valid!")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth::eth_test_utils::{
        get_sample_eth_block_and_receipts,
        get_valid_state_with_block_and_receipts,
        get_valid_state_with_invalid_block_and_receipts,
    };

    #[test]
    fn should_get_receipts_root_from_receipts() {
        let block_and_receipts = get_sample_eth_block_and_receipts();
        let result = get_receipts_root_from_receipts(&block_and_receipts.receipts)
            .unwrap();
        let expected_result = block_and_receipts.block.receipts_root;
        assert!(result == expected_result);
    }

    #[test]
    fn should_return_true_if_receipts_root_is_correct() {
        let block_and_receipts = get_sample_eth_block_and_receipts();
        let result = receipts_root_is_correct(
            &block_and_receipts.block,
            &block_and_receipts.receipts,
        ).unwrap();
        assert!(result);
    }

    #[test]
    fn should_return_false_if_receipts_root_is_not_correct() {
        let state = get_valid_state_with_invalid_block_and_receipts()
            .unwrap();
        let block_and_receipts = state.get_eth_block_and_receipts()
            .unwrap();
        let result = receipts_root_is_correct(
            &block_and_receipts.block,
            &block_and_receipts.receipts,
        ).unwrap();
        assert!(!result);
    }

    #[test]
    fn should_validate_receipts_in_state() {
        let state = get_valid_state_with_block_and_receipts()
            .unwrap();
        if let Err(_) = validate_receipts_in_state(state) {
            panic!("Receipts should be valid!")
        }
    }

    #[test]
    fn should_not_validate_invalid_receipts_in_state() {
        let expected_error = "✘ Not accepting ETH block - receipts root not valid!"
            .to_string();
        let state = get_valid_state_with_invalid_block_and_receipts()
            .unwrap();
        match validate_receipts_in_state(state) {
            Err(AppError::Custom(e)) => assert!(e == expected_error),
            Ok(_) => panic!("Receipts should not be valid!"),
            Err(_) => panic!("Wrong error message!"),
        }
    }
}
