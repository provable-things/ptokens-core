use ethereum_types::U256;

use crate::{
    btc_on_eth::eth::redeem_info::{BtcOnEthRedeemInfo, BtcOnEthRedeemInfos},
    chains::{btc::btc_constants::MINIMUM_REQUIRED_SATOSHIS, eth::eth_state::EthState},
    traits::DatabaseInterface,
    types::Result,
};

fn filter_redeem_infos(redeem_infos: &BtcOnEthRedeemInfos) -> BtcOnEthRedeemInfos {
    BtcOnEthRedeemInfos::new(
        redeem_infos
            .0
            .iter()
            .filter(|infos| match infos.amount >= U256::from(MINIMUM_REQUIRED_SATOSHIS) {
                true => true,
                false => {
                    trace!("✘ Filtering redeem infos ∵ amount too low: {:?}", infos);
                    false
                },
            })
            .cloned()
            .collect::<Vec<BtcOnEthRedeemInfo>>(),
    )
}

pub fn maybe_filter_redeem_infos_in_state<D>(state: EthState<D>) -> Result<EthState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Filtering any `btc-on-eth` redeem infos for amounts below minimum # of Satoshis...");
    let new_infos = filter_redeem_infos(&state.btc_on_eth_redeem_infos);
    state.replace_btc_on_eth_redeem_infos(new_infos)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ethereum_types::U256;

    use super::*;
    use crate::{
        btc_on_eth::eth::redeem_info::BtcOnEthRedeemInfo,
        chains::eth::eth_types::{EthAddress, EthHash},
    };

    #[test]
    fn should_filter_redeem_infos() {
        let expected_length = 2;
        let infos = BtcOnEthRedeemInfos::new(vec![
            BtcOnEthRedeemInfo {
                amount: U256::from_dec_str("4999").unwrap(),
                from: EthAddress::from_str("edb86cd455ef3ca43f0e227e00469c3bdfa40628").unwrap(),
                recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
                originating_tx_hash: EthHash::from_slice(
                    &hex::decode("17f84a414c183bfafa4cd05e9ad13185e5eb6983085c222cae5afa4bba212da5").unwrap()[..],
                ),
            },
            BtcOnEthRedeemInfo {
                amount: U256::from_dec_str("5000").unwrap(),
                from: EthAddress::from_str("edb86cd455ef3ca43f0e227e00469c3bdfa40628").unwrap(),
                recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
                originating_tx_hash: EthHash::from_slice(
                    &hex::decode("17f84a414c183bfafa4cd05e9ad13185e5eb6983085c222cae5afa4bba212da5").unwrap()[..],
                ),
            },
            BtcOnEthRedeemInfo {
                amount: U256::from_dec_str("5001").unwrap(),
                from: EthAddress::from_str("edb86cd455ef3ca43f0e227e00469c3bdfa40628").unwrap(),
                recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
                originating_tx_hash: EthHash::from_slice(
                    &hex::decode("17f84a414c183bfafa4cd05e9ad13185e5eb6983085c222cae5afa4bba212da5").unwrap()[..],
                ),
            },
        ]);
        let length_before = infos.len();
        let result = filter_redeem_infos(&infos);
        let length_after = result.len();
        assert!(length_before > length_after);
        assert_eq!(length_after, expected_length);
    }
}
