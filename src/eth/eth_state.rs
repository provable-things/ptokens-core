use crate::{
    types::Result,
    errors::AppError,
    traits::{
        DatabaseInterface,
    },
    eth::eth_types::{
        EthHash,
        RedeemParams,
        EthBlockAndReceipts,
    },
    btc::btc_types::{
        BtcTransactions,
        BtcUtxosAndValues,
    },
    utils::{
        get_not_in_state_err,
        get_no_overwrite_state_err,
    },
};

#[derive(Clone, PartialEq, Eq)]
pub struct EthState<D: DatabaseInterface> {
    pub db: D,
    pub misc: Option<String>,
    pub redeem_params: Vec<RedeemParams>,
    pub btc_transactions: Option<BtcTransactions>,
    pub btc_utxos_and_values: Option<BtcUtxosAndValues>,
    pub eth_block_and_receipts: Option<EthBlockAndReceipts>,
}

impl<D> EthState<D> where D: DatabaseInterface {
    pub fn init(db: D) -> EthState<D> {
        EthState {
            db,
            misc: None,
            btc_transactions: None,
            redeem_params: Vec::new(),
            btc_utxos_and_values: None,
            eth_block_and_receipts: None,
        }
    }

    pub fn add_eth_block_and_receipts(
        mut self,
        eth_block_and_receipts: EthBlockAndReceipts
    ) -> Result<EthState<D>> {
        match self.eth_block_and_receipts {
            Some(_) => Err(AppError::Custom(
                get_no_overwrite_state_err("eth_block_and_receipts"))
            ),
            None => {
                self.eth_block_and_receipts = Some(eth_block_and_receipts);
                Ok(self)
            }
        }
    }

    pub fn add_redeem_params(
        mut self,
        mut new_redeem_params: Vec<RedeemParams>,
    ) -> Result<EthState<D>> {
        self.redeem_params
            .append(&mut new_redeem_params);
        Ok(self)
    }

    pub fn replace_redeem_params(
        mut self,
        replacement_params: Vec<RedeemParams>,
    ) -> Result<EthState<D>> {
        self.redeem_params = replacement_params;
        Ok(self)
    }

    pub fn add_misc_string_to_state(
        mut self,
        misc_string: String
    ) -> Result<EthState<D>> {
        match self.misc {
            Some(_) => Err(AppError::Custom(
                get_no_overwrite_state_err("misc_string"))
            ),
            None => {
                self.misc = Some(misc_string);
                Ok(self)
            }
        }
    }

    pub fn add_btc_transactions(
        mut self,
        btc_transactions: BtcTransactions
    ) -> Result<EthState<D>> {
        match self.btc_transactions {
            Some(_) => Err(AppError::Custom(
                get_no_overwrite_state_err("btc_transaction"))
            ),
            None => {
                self.btc_transactions = Some(btc_transactions);
                Ok(self)
            }
        }
    }

    pub fn add_btc_utxos_and_values(
        mut self,
        btc_utxos_and_values: BtcUtxosAndValues,
    ) -> Result<EthState<D>> {
        match self.btc_utxos_and_values {
            Some(_) => Err(AppError::Custom(
                get_no_overwrite_state_err("btc_utxos_and_values"))
            ),
            None => {
                self.btc_utxos_and_values = Some(btc_utxos_and_values);
                Ok(self)
            }
        }
    }

    pub fn update_eth_block_and_receipts(
        mut self,
        new_eth_block_and_receipts: EthBlockAndReceipts
    ) -> Result<EthState<D>> {
        self.eth_block_and_receipts = Some(new_eth_block_and_receipts);
        Ok(self)
    }

    pub fn get_eth_block_and_receipts(
        &self
    ) -> Result<&EthBlockAndReceipts> {
        match &self.eth_block_and_receipts {
            Some(eth_block_and_receipts) => Ok(&eth_block_and_receipts),
            None => Err(AppError::Custom(
                get_not_in_state_err("eth_block_and_receipts"))
            )
        }
    }

    pub fn get_misc_string(&self) -> Result<String> {
        match &self.misc {
            None => Ok("".to_string()),
            Some(misc) => Ok(misc.to_string()),
        }
    }

    pub fn get_parent_hash(&self) -> Result<EthHash> {
        Ok(
            self
                .get_eth_block_and_receipts()?
                .block
                .parent_hash
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::get_test_database,
        eth::eth_test_utils::{
            get_expected_block,
            get_expected_receipt,
            SAMPLE_RECEIPT_INDEX,
            get_sample_eth_block_and_receipts,
            get_sample_eth_block_and_receipts_n,
            get_valid_state_with_block_and_receipts,
        },
    };

    #[test]
    fn should_fail_to_get_eth_block_and_receipts_in_state() {
        let expected_error = get_not_in_state_err("eth_block_and_receipts");
        let initial_state = EthState::init(get_test_database());
        match initial_state.get_eth_block_and_receipts() {
            Err(AppError::Custom(e)) => assert!(e == expected_error),
            Ok(_) => panic!("Eth block should not be in state yet!"),
            Err(_) => panic!("Wrong error received!")
        };
    }

    #[test]
    fn should_add_eth_block_and_receipts_state() {
        let expected_error = get_not_in_state_err("eth_block_and_receipts");
        let eth_block_and_receipts = get_sample_eth_block_and_receipts();
        let initial_state = EthState::init(get_test_database());
        match initial_state.get_eth_block_and_receipts() {
            Err(AppError::Custom(e)) => assert!(e == expected_error),
            Ok(_) => panic!("Eth block should not be in state yet!"),
            Err(_) => panic!("Wrong error received!")
        };
        let updated_state = initial_state.add_eth_block_and_receipts(
            eth_block_and_receipts
        ).unwrap();
        match updated_state.get_eth_block_and_receipts() {
            Err(_) => panic!("Eth block & receipts should be in state!"),
            Ok(block_and_receipt) => {
                let block = block_and_receipt
                    .block
                    .clone();
                let receipt = block_and_receipt
                    .receipts[SAMPLE_RECEIPT_INDEX]
                    .clone();
                let expected_block = get_expected_block();
                let expected_receipt = get_expected_receipt();
                assert!(block == expected_block);
                assert!(receipt == expected_receipt);
            }
        }
    }

    #[test]
    fn should_err_when_overwriting_eth_block_and_receipts_in_state() {
        let expected_error = get_no_overwrite_state_err(
            "eth_block_and_receipts");
        let eth_block_and_receipts = get_sample_eth_block_and_receipts();
        let initial_state = EthState::init(get_test_database());
        let updated_state = initial_state.add_eth_block_and_receipts(
            eth_block_and_receipts.clone()
        ).unwrap();

        match updated_state.add_eth_block_and_receipts(
            eth_block_and_receipts
        ) {
            Ok(_) => panic!("Overwriting state should not have succeeded!"),
            Err(AppError::Custom(e)) => assert!(e == expected_error),
            Err(_) => panic!("Wrong error recieved!")
        }
    }

    #[test]
    fn should_update_eth_block_and_receipts() {
        let eth_block_and_receipts_1 = get_sample_eth_block_and_receipts_n(0)
            .unwrap();
        let eth_block_and_receipts_2 = get_sample_eth_block_and_receipts_n(1)
            .unwrap();
        let initial_state = EthState::init(get_test_database());
        let updated_state = initial_state.add_eth_block_and_receipts(
            eth_block_and_receipts_1
        ).unwrap();
        let initial_state_block_num = updated_state.get_eth_block_and_receipts()
            .unwrap()
            .block
            .number
            .clone();
        let final_state = updated_state.update_eth_block_and_receipts(
            eth_block_and_receipts_2
        ).unwrap();
        let final_state_block_number = final_state.get_eth_block_and_receipts()
            .unwrap()
            .block
            .number;
        assert_ne!(final_state_block_number, initial_state_block_num);
    }

    #[test]
    fn should_get_eth_parent_hash() {
        let expected_result = get_sample_eth_block_and_receipts()
            .block
            .parent_hash;
        let state = get_valid_state_with_block_and_receipts()
            .unwrap();
        let result = state
            .get_parent_hash()
            .unwrap();
        assert!(result == expected_result);
    }
}
