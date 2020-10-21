use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::btc_constants::MINIMUM_REQUIRED_SATOSHIS,
    btc_on_eos::{
        utils::convert_eos_asset_to_u64,
        btc::{
            btc_state::BtcState,
            btc_types::{
                MintingParams,
                MintingParamStruct
            },
        },
    },
};

fn filter_minting_params(
    minting_params: &[MintingParamStruct],
) -> Result<MintingParams> {
    Ok(
        minting_params
            .iter()
            .map(|params| convert_eos_asset_to_u64(&params.amount))
            .collect::<Result<Vec<u64>>>()?
            .into_iter()
            .zip(minting_params.iter())
            .filter(|(amount, params)| {
                match amount >= &MINIMUM_REQUIRED_SATOSHIS {
                    true => true,
                    false => {
                        info!(
                            "✘ Filtering minting params ∵ value too low: {:?}",
                            params,
                        );
                        false
                    }
                }
            })
            .map(|(_, params)| params)
            .cloned()
            .collect::<Vec<MintingParamStruct>>()
    )
}

pub fn maybe_filter_minting_params_in_state<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Filtering out any minting params below minimum # of Satoshis...");
    filter_minting_params(&state.minting_params)
        .and_then(|new_params| state.replace_minting_params(new_params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_on_eos::btc::btc_test_utils::get_sample_minting_params;

    #[test]
    fn should_filter_minting_params() {
        let expected_length_before = 3;
        let expected_length_after = 2;
        let minting_params = get_sample_minting_params();
        let length_before = minting_params.len();
        assert_eq!(length_before, expected_length_before);
        let result = filter_minting_params(&minting_params).unwrap();
        let length_after = result.len();
        assert_eq!(length_after, expected_length_after);
        result
            .iter()
            .map(|params| assert!(convert_eos_asset_to_u64(&params.amount).unwrap() >= MINIMUM_REQUIRED_SATOSHIS))
            .for_each(drop);
    }
}
