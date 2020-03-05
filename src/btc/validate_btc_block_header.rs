use bitcoin::util::hash::BitcoinHash;
use crate::{
    types::Result,
    errors::AppError,
    traits::DatabaseInterface,
    btc::{
        btc_state::BtcState,
        btc_types::BtcBlockAndId,
    },
};

fn validate_btc_block_header(btc_block_and_id: &BtcBlockAndId) -> Result<()> {
    match btc_block_and_id.block.bitcoin_hash() == btc_block_and_id.id {
        true => {
            info!("✔ BTC block header valid!");
            Ok(())
        }
        false => Err(AppError::Custom(
            "✘ Invalid BTC block! Block header hash does not match block id!"
                .to_string()
        ))
    }
}

pub fn validate_btc_block_header_in_state<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Validating BTC block header...");
    validate_btc_block_header(state.get_btc_block_and_id()?)
        .and_then(|_| Ok(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use bitcoin_hashes::sha256d;
    use crate::btc::{
        btc_types::BtcBlockAndId,
        btc_test_utils::get_sample_btc_block_and_id,
    };

    #[test]
    fn should_validate_btc_block_header() {
        let block_and_id = get_sample_btc_block_and_id()
            .unwrap();
        if let Err(e) = validate_btc_block_header(&block_and_id) {
            panic!("Sample block should be valid: {}", e);
        }
    }

    #[test]
    fn should_error_on_invalid_block() {
        let expected_error =
            "✘ Invalid BTC block! Block header hash does not match block id!"
                .to_string();
        let block_and_id = get_sample_btc_block_and_id()
            .unwrap();
        let wrong_block_id =
            "c0ffee0000000000000c084f2a5fa68ef814144d350a601688248b421258dd3f";
        let invalid_block_and_id = BtcBlockAndId {
            height: 1,
            deposit_address_list: Vec::new(),
            block: block_and_id.block.clone(),
            id: sha256d::Hash::from_str(&wrong_block_id).unwrap(),
        };
        match validate_btc_block_header(&invalid_block_and_id) {
            Err(AppError::Custom(e)) => assert!(e == expected_error),
            Ok(_) => panic!("Should not be valid!"),
            Err(_) => panic!("Wrong error for invalid btc block!"),
        }
    }
}
