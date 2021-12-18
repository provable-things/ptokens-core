use crate::{
    chains::evm::{eth_database_utils::get_eth_chain_id_from_db, eth_state::EthState},
    constants::{CORE_IS_VALIDATING, DEBUG_MODE, NOT_VALIDATING_WHEN_NOT_IN_DEBUG_MODE_ERROR},
    traits::DatabaseInterface,
    types::Result,
};

pub fn validate_block_in_state<D>(state: EthState<D>) -> Result<EthState<D>>
where
    D: DatabaseInterface,
{
    if CORE_IS_VALIDATING {
        info!("✔ Validating block header...");
        match state
            .get_eth_submission_material()?
            .get_block()?
            .is_valid(&get_eth_chain_id_from_db(&state.db)?)?
        {
            true => Ok(state),
            false => Err("✘ Not accepting ETH block - header hash not valid!".into()),
        }
    } else {
        info!("✔ Skipping ETH block header validaton!");
        match DEBUG_MODE {
            true => Ok(state),
            false => Err(NOT_VALIDATING_WHEN_NOT_IN_DEBUG_MODE_ERROR.into()),
        }
    }
}
