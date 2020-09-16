use ethereum_types::U256;
use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::btc_constants::MINIMUM_REQUIRED_SATOSHIS,
    btc_on_eth::eth::{
        eth_state::EthState,
        eth_types::RedeemParams,
    },
};

fn filter_redeem_params(
    redeem_params: &[RedeemParams]
) -> Result<Vec<RedeemParams>> {
    Ok(
        redeem_params
            .iter()
            .filter(|params| {
                match params.amount >= U256::from(MINIMUM_REQUIRED_SATOSHIS) {
                    true => true,
                    false => {
                        trace!(
                            "✘ Filtering redeem params ∵ amount too low: {:?}",
                            params,
                        );
                        false
                    }
                }
            })
            .cloned()
            .collect::<Vec<RedeemParams>>()
    )
}

pub fn maybe_filter_redeem_params_in_state<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe filtering any redeem params below minimum # of Satoshis...");
    filter_redeem_params(&state.redeem_params)
        .and_then(|new_params| state.replace_redeem_params(new_params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use ethereum_types::U256;
    use crate::btc_on_eth::eth::eth_types::{
        EthHash,
        EthAddress,
    };

    #[test]
    fn should_filter_redeem_params() {
        let expected_length = 2;
        let params = vec![
            RedeemParams {
                amount: U256::from_dec_str("4999").unwrap(),
                from: EthAddress::from_str(
                    "edb86cd455ef3ca43f0e227e00469c3bdfa40628"
                ).unwrap(),
                recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
                originating_tx_hash: EthHash::from_slice(
                    &hex::decode("17f84a414c183bfafa4cd05e9ad13185e5eb6983085c222cae5afa4bba212da5")
                    .unwrap()[..]
                ),
            },
            RedeemParams {
                amount: U256::from_dec_str("5000").unwrap(),
                from: EthAddress::from_str(
                    "edb86cd455ef3ca43f0e227e00469c3bdfa40628"
                ).unwrap(),
                recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
                originating_tx_hash: EthHash::from_slice(
                    &hex::decode("17f84a414c183bfafa4cd05e9ad13185e5eb6983085c222cae5afa4bba212da5")
                    .unwrap()[..]
                ),
            },
            RedeemParams {
                amount: U256::from_dec_str("5001").unwrap(),
                from: EthAddress::from_str(
                    "edb86cd455ef3ca43f0e227e00469c3bdfa40628"
                ).unwrap(),
                recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
                originating_tx_hash: EthHash::from_slice(
                    &hex::decode("17f84a414c183bfafa4cd05e9ad13185e5eb6983085c222cae5afa4bba212da5")
                    .unwrap()[..]
                ),
            },
        ];
        let length_before = params.len();
        let result = filter_redeem_params(&params)
            .unwrap();
        let length_after = result.len();
        assert!(length_before > length_after);
        assert_eq!(length_after, expected_length);
    }
}
