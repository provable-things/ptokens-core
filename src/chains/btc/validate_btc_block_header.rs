use bitcoin::util::hash::BitcoinHash;
use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::{
        btc_state::BtcState,
        btc_block::BtcBlockAndId,
    },
    constants::{
        DEBUG_MODE,
        CORE_IS_VALIDATING,
        NOT_VALIDATING_WHEN_NOT_IN_DEBUG_MODE_ERROR,
    },
};

fn validate_btc_block_header(btc_block_and_id: &BtcBlockAndId) -> Result<()> {
    match btc_block_and_id.block.bitcoin_hash() == btc_block_and_id.id {
        true => {
            info!("✔ BTC block header valid!");
            Ok(())
        }
        false => Err("✘ Invalid BTC block! Block header hash does not match block id!".into())
    }
}

pub fn validate_btc_block_header_in_state<D>(state: BtcState<D>) -> Result<BtcState<D>> where D: DatabaseInterface {
    if CORE_IS_VALIDATING {
        info!("✔ Validating BTC block header...");
        validate_btc_block_header(state.get_btc_block_and_id()?).map(|_| state)
    } else {
        info!("✔ Skipping BTC block-header validation!");
        match DEBUG_MODE {
            true =>  Ok(state),
            false => Err(NOT_VALIDATING_WHEN_NOT_IN_DEBUG_MODE_ERROR.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use bitcoin_hashes::sha256d;
    use crate::{
        errors::AppError,
        chains::btc::{
            btc_block::BtcBlockAndId,
            deposit_address_info::DepositInfoList,
            btc_test_utils::get_sample_btc_block_and_id,
        },
    };

    #[test]
    fn should_validate_btc_block_header() {
        let block_and_id = get_sample_btc_block_and_id().unwrap();
        if let Err(e) = validate_btc_block_header(&block_and_id) {
            panic!("Sample block should be valid: {}", e);
        }
    }

    #[test]
    fn should_error_on_invalid_block() {
        let expected_error = "✘ Invalid BTC block! Block header hash does not match block id!".to_string();
        let block_and_id = get_sample_btc_block_and_id().unwrap();
        let wrong_block_id = "c0ffee0000000000000c084f2a5fa68ef814144d350a601688248b421258dd3f";
        let invalid_block_and_id = BtcBlockAndId {
            height: 1,
            block: block_and_id.block,
            deposit_address_list: DepositInfoList::new(vec![]),
            id: sha256d::Hash::from_str(&wrong_block_id).unwrap(),
        };
        match validate_btc_block_header(&invalid_block_and_id) {
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            Ok(_) => panic!("Should not be valid!"),
            _ => panic!("Wrong error for invalid btc block!"),
        }
    }
}
