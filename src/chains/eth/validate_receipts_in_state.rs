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

pub fn validate_receipts_in_state<D>(state: EthState<D>) -> Result<EthState<D>> where D: DatabaseInterface {
    if CORE_IS_VALIDATING {
        info!("✔ Validating receipts...");
        match state.get_eth_submission_material()?.receipts_are_valid()? {
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
            get_valid_state_with_block_and_receipts,
            get_valid_state_with_invalid_block_and_receipts,
        },
    };

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
