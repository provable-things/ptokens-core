#![cfg(test)]
use ethereum_types::{Address as EthAddress, H256 as EthHash};

use crate::btc_on_eth::eth::redeem_info::{BtcOnEthRedeemInfo, BtcOnEthRedeemInfos};

pub fn get_sample_btc_on_eth_redeem_info_1() -> BtcOnEthRedeemInfo {
    BtcOnEthRedeemInfo {
        amount_in_satoshis: 123456789,
        recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
        from: EthAddress::from_slice(&hex::decode("7d39fb393c5597dddccf1c428f030913fe7f67ab").unwrap()),
        originating_tx_hash: EthHash::from_slice(
            &hex::decode("01920b62cd2e77204b2fa59932f9d6dd54fd43c99095aee808b700ed2b6ee9cf").unwrap(),
        ),
    }
}

fn get_sample_btc_on_eth_redeem_info_2() -> BtcOnEthRedeemInfo {
    BtcOnEthRedeemInfo {
        amount_in_satoshis: 987654321,
        recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
        from: EthAddress::from_slice(&hex::decode("7d39fb393c5597dddccf1c428f030913fe7f67ab").unwrap()),
        originating_tx_hash: EthHash::from_slice(
            &hex::decode("01920b62cd2e77204b2fa59932f9d6dd54fd43c99095aee808b700ed2b6ee9cf").unwrap(),
        ),
    }
}

pub fn get_sample_btc_on_eth_redeem_infos() -> BtcOnEthRedeemInfos {
    BtcOnEthRedeemInfos::new(vec![
        get_sample_btc_on_eth_redeem_info_1(),
        get_sample_btc_on_eth_redeem_info_2(),
    ])
}
