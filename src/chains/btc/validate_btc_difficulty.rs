use bitcoin::{blockdata::block::BlockHeader as BtcBlockHeader, network::constants::Network as BtcNetwork};

use crate::{
    chains::btc::{
        btc_database_utils::{get_btc_difficulty_from_db, get_btc_network_from_db},
        btc_state::BtcState,
    },
    constants::{CORE_IS_VALIDATING, DEBUG_MODE, NOT_VALIDATING_WHEN_NOT_IN_DEBUG_MODE_ERROR},
    traits::DatabaseInterface,
    types::Result,
};

fn check_difficulty_is_above_threshold(
    threshold: u64,
    btc_block_header: &BtcBlockHeader,
    network: BtcNetwork,
) -> Result<()> {
    // NOTE: Network not configurable in difficulty calculation ∵ all members
    // of the enum return the same value from underlying lib!
    info!("✔ Checking BTC block difficulty is above threshold...");
    match network {
        BtcNetwork::Bitcoin => match btc_block_header.difficulty(network) > threshold {
            true => {
                info!("✔ BTC block difficulty is above threshold!");
                Ok(())
            },
            false => {
                trace!(
                    "✘ Difficulty of {} is below threshold of {}!",
                    btc_block_header.difficulty(network),
                    threshold,
                );
                Err("✘ Invalid block! Difficulty is below threshold!".into())
            },
        },
        _ => {
            trace!("✔ Not on mainnet - skipping difficulty check!");
            Ok(())
        },
    }
}

pub fn validate_difficulty_of_btc_block_in_state<D: DatabaseInterface>(state: BtcState<D>) -> Result<BtcState<D>> {
    if CORE_IS_VALIDATING {
        info!("✔ Validating BTC block difficulty...");
        check_difficulty_is_above_threshold(
            get_btc_difficulty_from_db(&state.db)?,
            &state.get_btc_block_and_id()?.block.header,
            get_btc_network_from_db(&state.db)?,
        )
        .and(Ok(state))
    } else {
        info!("✔ Skipping BTC block difficulty validation!");
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
    fn should_not_err_if_difficulty_is_above_threshold() {
        let block_header = get_sample_btc_block_and_id().unwrap().block.header;
        let threshold: u64 = 1;
        check_difficulty_is_above_threshold(threshold, &block_header, BtcNetwork::Bitcoin).unwrap();
    }

    #[test]
    fn should_err_if_difficulty_is_below_threshold() {
        let block_header = get_sample_btc_block_and_id().unwrap().block.header;
        let threshold = u64::max_value();
        assert!(check_difficulty_is_above_threshold(threshold, &block_header, BtcNetwork::Bitcoin).is_err());
    }

    #[test]
    fn should_skip_difficulty_check_if_not_on_mainnet() {
        let threshold = 0;
        let block_header = get_sample_btc_block_and_id().unwrap().block.header;
        let network = BtcNetwork::Testnet;
        let difficulty = block_header.difficulty(network);
        assert!(difficulty > threshold);
        assert!(check_difficulty_is_above_threshold(threshold, &block_header, network,).is_ok());
    }
}
