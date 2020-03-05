use bitcoin::blockdata::block::BlockHeader as BtcBlockHeader;
use crate::{
    types::Result,
    errors::AppError,
    btc::btc_state::BtcState,
    traits::DatabaseInterface,
};

fn validate_proof_of_work_in_block(
    btc_block_header: &BtcBlockHeader
) -> Result<()> {
    match btc_block_header.validate_pow(&btc_block_header.target()) {
        Ok(_) => {
            info!("✔ BTC block's proof-of-work is valid!");
            Ok(())
        }
        Err(_) => Err(AppError::Custom(
            "✘ Invalid block! PoW validation error: Block hash > target!"
                .to_string()
        ))
    }
}

pub fn validate_proof_of_work_of_btc_block_in_state<D>(
    state: BtcState<D>,
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Validating BTC block's proof-of-work...");
    validate_proof_of_work_in_block(&state.get_btc_block_and_id()?.block.header)
        .and_then(|_| Ok(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc::btc_test_utils::get_sample_btc_block_and_id;

    #[test]
    fn should_validate_proof_of_work_in_valid_block() {
        let block_header = get_sample_btc_block_and_id()
            .unwrap()
            .block
            .header;
        if let Err(e) = validate_proof_of_work_in_block(&block_header) {
            panic!("PoW should be valid in sample block: {}", e);
        }
    }
}
