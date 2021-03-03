use bitcoin::blockdata::block::BlockHeader as BtcBlockHeader;

use crate::{
    chains::btc::btc_state::BtcState,
    constants::{CORE_IS_VALIDATING, DEBUG_MODE, NOT_VALIDATING_WHEN_NOT_IN_DEBUG_MODE_ERROR},
    traits::DatabaseInterface,
    types::Result,
};

fn validate_proof_of_work_in_block(btc_block_header: &BtcBlockHeader) -> Result<()> {
    match btc_block_header.validate_pow(&btc_block_header.target()) {
        Ok(_) => {
            info!("✔ BTC block's proof-of-work is valid!");
            Ok(())
        },
        Err(_) => Err("✘ Invalid block! PoW validation error: Block hash > target!".into()),
    }
}

pub fn validate_proof_of_work_of_btc_block_in_state<D>(state: BtcState<D>) -> Result<BtcState<D>>
where
    D: DatabaseInterface,
{
    if CORE_IS_VALIDATING {
        info!("✔ Validating BTC block's proof-of-work...");
        validate_proof_of_work_in_block(&state.get_btc_block_and_id()?.block.header).map(|_| state)
    } else {
        info!("✔ Skipping BTC proof-of-work validation!");
        match DEBUG_MODE {
            true => Ok(state),
            false => Err(NOT_VALIDATING_WHEN_NOT_IN_DEBUG_MODE_ERROR.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::btc::btc_test_utils::get_sample_btc_block_and_id;

    #[test]
    fn should_validate_proof_of_work_in_valid_block() {
        let block_header = get_sample_btc_block_and_id().unwrap().block.header;
        if let Err(e) = validate_proof_of_work_in_block(&block_header) {
            panic!("PoW should be valid in sample block: {}", e);
        }
    }
}
