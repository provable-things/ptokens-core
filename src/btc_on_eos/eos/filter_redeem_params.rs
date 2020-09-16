use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::btc_constants::MINIMUM_REQUIRED_SATOSHIS,
    btc_on_eos::eos::{
        eos_state::EosState,
        eos_types::RedeemParams,
    },
};

fn filter_redeem_params(
    redeem_params: &[RedeemParams],
) -> Result<Vec<RedeemParams>> {
    Ok(
        redeem_params
            .iter()
            .map(|params| params.amount)
            .zip(redeem_params.iter())
            .filter(|(amount, params)| {
                match amount >= &MINIMUM_REQUIRED_SATOSHIS {
                    true => true,
                    false => {
                        info!(
                            "✘ Filtering redeem params ∵ value too low: {:?}",
                            params,
                        );
                        false
                    }
                }
            })
            .map(|(_, params)| params)
            .cloned()
            .collect::<Vec<RedeemParams>>()
    )
}

pub fn maybe_filter_value_too_low_redeem_params_in_state<D>(
    state: EosState<D>
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    info!("✔ Filtering out any redeem params below minimum # of Satoshis...");
    filter_redeem_params(&state.redeem_params)
        .and_then(|new_params| state.replace_redeem_params(new_params))
}
