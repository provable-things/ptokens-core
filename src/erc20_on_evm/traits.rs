use ethereum_types::{Address as EthAddress, U256};

use crate::{
    constants::FEE_BASIS_POINTS_DIVISOR,
    dictionaries::eth_evm::EthEvmTokenDictionary,
    fees::fee_utils::sanity_check_basis_points_value,
    types::Result,
};

pub trait FeeCalculator {
    fn get_amount(&self) -> U256;

    fn get_token_address(&self) -> EthAddress;

    fn subtract_amount(&self, subtrahend: U256) -> Result<Self>
    where
        Self: Sized;

    fn calculate_fee(&self, fee_basis_points: u64) -> U256 {
        if fee_basis_points > 0 {
            debug!("Calculating fee using `fee_basis_points` of {}", fee_basis_points);
            (self.get_amount() * U256::from(fee_basis_points)) / U256::from(FEE_BASIS_POINTS_DIVISOR)
        } else {
            debug!("Not calculating fee because `fee_basis_points` are zero!");
            U256::zero()
        }
    }

    fn calculate_fee_via_dictionary(&self, dictionary: &EthEvmTokenDictionary) -> Result<(EthAddress, U256)> {
        let token_address = self.get_token_address();
        Ok((
            token_address,
            self.calculate_fee(sanity_check_basis_points_value(
                dictionary.get_fee_basis_points(&token_address)?,
            )?),
        ))
    }
}

pub trait FeesCalculator {
    fn get_fees(&self, dictionary: &EthEvmTokenDictionary) -> Result<Vec<(EthAddress, U256)>>;

    fn subtract_fees(&self, dictionary: &EthEvmTokenDictionary) -> Result<Self>
    where
        Self: Sized;
}
