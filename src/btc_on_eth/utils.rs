use ethereum_types::U256;

use crate::constants::{BTC_NUM_DECIMALS, PTOKEN_ERC777_NUM_DECIMALS};

pub fn convert_satoshis_to_wei(satoshis: u64) -> U256 {
    U256::from(satoshis) * U256::from(10u64.pow(PTOKEN_ERC777_NUM_DECIMALS - BTC_NUM_DECIMALS as u32))
}

pub fn convert_wei_to_satoshis(ptoken: U256) -> u64 {
    match ptoken.checked_div(U256::from(
        10u64.pow(PTOKEN_ERC777_NUM_DECIMALS - BTC_NUM_DECIMALS as u32),
    )) {
        Some(amount) => amount.as_u64(),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_convert_satoshis_to_wei() {
        let satoshis = 1337;
        let expected_result = U256::from_dec_str("13370000000000").unwrap();
        let result = convert_satoshis_to_wei(satoshis);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_wei_to_satoshis() {
        let ptoken = U256::from_dec_str("13370000000000").unwrap();
        let expected_result = 1337;
        let result = convert_wei_to_satoshis(ptoken);
        assert_eq!(result, expected_result);
    }
}
