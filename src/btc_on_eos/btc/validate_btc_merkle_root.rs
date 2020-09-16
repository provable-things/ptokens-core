use bitcoin::blockdata::block::Block as BtcBlock;
use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::btc::btc_state::BtcState,
    constants::{
        DEBUG_MODE,
        CORE_IS_VALIDATING,
        NOT_VALIDATING_WHEN_NOT_IN_DEBUG_MODE_ERROR,
    },
};

fn validate_merkle_root(btc_block: &BtcBlock) -> Result<()> {
    match btc_block.check_merkle_root() {
        true => {
            info!("✔ Merkle-root valid!");
            Ok(())
        }
        false => Err("✘ Invalid block! Merkle root doesn't match calculated merkle root!".into())
    }
}

pub fn validate_btc_merkle_root<D>(state: BtcState<D>) -> Result<BtcState<D>> where D: DatabaseInterface {
    if CORE_IS_VALIDATING {
        info!("✔ Validating merkle-root in BTC block...");
        validate_merkle_root(&state.get_btc_block_and_id()?.block)
            .and(Ok(state))
    } else {
        info!("✔ Skipping BTC merkle root validation!");
        info!("✔ Skipping BTC difficulty validation!");
        match DEBUG_MODE {
            true => Ok(state),
            false => Err(NOT_VALIDATING_WHEN_NOT_IN_DEBUG_MODE_ERROR.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_on_eos::btc::btc_test_utils::get_sample_btc_block_and_id;

    #[test]
    fn should_validate_sample_merkle_root() {
        let block = get_sample_btc_block_and_id()
            .unwrap()
            .block;
        if let Err(e) = validate_merkle_root(&block) {
            panic!("Merkle root should be valid for samle block: {}", e);
        }

    }
}

