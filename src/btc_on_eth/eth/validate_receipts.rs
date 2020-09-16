use ethereum_types::H256;
use crate::{
    types::Result,
    traits::DatabaseInterface,
    constants::{
        DEBUG_MODE,
        CORE_IS_VALIDATING,
        NOT_VALIDATING_WHEN_NOT_IN_DEBUG_MODE_ERROR,
    },
    btc_on_eth::{
        eth::rlp_codec::get_rlp_encoded_receipts_and_nibble_tuples,
        eth::{
            eth_state::EthState,
            eth_types::{
                EthBlock,
                EthReceipt,
            },
            trie::{
                Trie,
                put_in_trie_recursively,
            },
        },
    },
};

fn get_receipts_root_from_receipts(receipts: &[EthReceipt]) -> Result<H256> {
    get_rlp_encoded_receipts_and_nibble_tuples(receipts)
        .and_then(|key_value_tuples| {
            info!("✔ Building merkle-patricia trie from receipts...");
            put_in_trie_recursively(Trie::get_new_trie()?, key_value_tuples, 0)
        })
        .map(|trie| trie.root)
}

fn receipts_root_is_correct(block: &EthBlock, receipts: &[EthReceipt]) -> Result<bool> {
    info!("✔ Checking trie root against receipts root...");
    get_receipts_root_from_receipts(receipts).map(|root| root == block.receipts_root)
}

pub fn validate_receipts_in_state<D>(state: EthState<D>) -> Result<EthState<D>> where D: DatabaseInterface {
    if CORE_IS_VALIDATING {
        info!("✔ Validating receipts...");
        match receipts_root_is_correct(
            &state.get_eth_block_and_receipts()?.block,
            &state.get_eth_block_and_receipts()?.receipts,
        )? {
            true => {
                info!("✔ Receipts are valid!");
                Ok(state)
            },
            false => Err("✘ Not accepting ETH block - receipts root not valid!".into())
        }
    } else {
        info!("✔ Skipping ETH receipts validation!");
        match DEBUG_MODE {
            true =>  Ok(state),
            false => Err(NOT_VALIDATING_WHEN_NOT_IN_DEBUG_MODE_ERROR.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        errors::AppError,
        btc_on_eth::eth::eth_test_utils::{
            get_sample_eth_block_and_receipts,
            get_valid_state_with_block_and_receipts,
            get_valid_state_with_invalid_block_and_receipts,
        },
    };

    #[test]
    fn should_get_receipts_root_from_receipts() {
        let block_and_receipts = get_sample_eth_block_and_receipts();
        let result = get_receipts_root_from_receipts(&block_and_receipts.receipts).unwrap();
        let expected_result = block_and_receipts.block.receipts_root;
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_return_true_if_receipts_root_is_correct() {
        let block_and_receipts = get_sample_eth_block_and_receipts();
        let result = receipts_root_is_correct(&block_and_receipts.block, &block_and_receipts.receipts).unwrap();
        assert!(result);
    }

    #[test]
    fn should_return_false_if_receipts_root_is_not_correct() {
        let state = get_valid_state_with_invalid_block_and_receipts().unwrap();
        let block_and_receipts = state.get_eth_block_and_receipts().unwrap();
        let result = receipts_root_is_correct(&block_and_receipts.block, &block_and_receipts.receipts).unwrap();
        assert!(!result);
    }

    #[test]
    fn should_validate_receipts_in_state() {
        let state = get_valid_state_with_block_and_receipts().unwrap();
        if validate_receipts_in_state(state).is_err() {
            panic!("Receipts should be valid!")
        }
    }

    #[cfg(not(feature="non-validating"))]
    #[test]
    fn should_not_validate_invalid_receipts_in_state() {
        let expected_error = "✘ Not accepting ETH block - receipts root not valid!".to_string();
        let state = get_valid_state_with_invalid_block_and_receipts().unwrap();
        match validate_receipts_in_state(state) {
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            Ok(_) => panic!("Receipts should not be valid!"),
            _ => panic!("Wrong error message!"),
        }
    }
}
