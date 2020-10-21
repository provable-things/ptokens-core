use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::eth::eth_state::EthState,
    constants::{
        DEBUG_MODE,
        CORE_IS_VALIDATING,
        NOT_VALIDATING_WHEN_NOT_IN_DEBUG_MODE_ERROR,
    },
};

pub fn validate_block_in_state<D>(state: EthState<D>) -> Result<EthState<D>> where D: DatabaseInterface {
    if CORE_IS_VALIDATING {
        info!("✔ Validating block header...");
        match state.get_eth_submission_material()?.block.is_valid()? {
            true => Ok(state),
            false => Err("✘ Not accepting ETH block - header hash not valid!".into()),
        }
    } else {
        info!("✔ Skipping ETH block header validaton!");
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
        btc_on_eth::eth::eth_test_utils::get_valid_state_with_block_and_receipts,
    };

    #[test]
    fn should_validate_block_in_state() {
        let state = get_valid_state_with_block_and_receipts()
            .unwrap();
        if validate_block_in_state(state).is_err() {
            panic!("Block in state should be valid!")
        }
    }

    #[cfg(not(feature="non-validating"))]
    #[test]
    fn should_fail_to_validate_invalid_block_in_state() {
        use crate::btc_on_eth::eth::eth_test_utils::{
            get_valid_state_with_invalid_block_and_receipts
        };
        let expected_error = "✘ Not accepting ETH block - header hash not valid!"
            .to_string();
        let state = get_valid_state_with_invalid_block_and_receipts()
            .unwrap();
        match validate_block_in_state(state) {
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            _ => panic!("Should not validate invalid block in state!")
        }
    }
}
