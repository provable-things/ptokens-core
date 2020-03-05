use bitcoin::blockdata::block::Block as BtcBlock;
use crate::{
    types::Result,
    errors::AppError,
    btc::btc_state::BtcState,
    traits::DatabaseInterface,
};

fn validate_merkle_root(btc_block: &BtcBlock) -> Result<()> {
    match btc_block.check_merkle_root() {
        true => {
            info!("✔ Merkle-root valid!");
            Ok(())
        }
        false => Err(AppError::Custom(
            "✘ Invalid block! Merkle root doesn't match calculated merkle root!"
                .to_string()
        ))
    }
}

pub fn validate_btc_merkle_root<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Validating merkle-root in BTC block...");
    validate_merkle_root(&state.get_btc_block_and_id()?.block)
        .and_then(|_| Ok(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc::btc_test_utils::get_sample_btc_block_and_id;

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

