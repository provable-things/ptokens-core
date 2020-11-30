use ethereum_types::H256 as EthHash;
use crate::{
    types::Result,
    traits::DatabaseInterface,
    utils::{
        get_not_in_state_err,
        get_no_overwrite_state_err,
    },
    btc_on_eth::eth::redeem_info::BtcOnEthRedeemInfos,
    erc20_on_eos::eth::peg_in_info::Erc20OnEosPegInInfos,
    chains::{
        eth::eth_submission_material::EthSubmissionMaterial,
        btc::{
            btc_types::BtcTransactions,
            utxo_manager::utxo_types::BtcUtxosAndValues,
        },
        eos::{
            eos_types::EosSignedTransactions,
            eos_erc20_dictionary::EosErc20Dictionary,
        },
    },
};

#[derive(Clone, PartialEq, Eq)]
pub struct EthState<D: DatabaseInterface> {
    pub db: D,
    pub misc: Option<String>,
    pub btc_transactions: Option<BtcTransactions>,
    pub btc_on_eth_redeem_infos: BtcOnEthRedeemInfos,
    pub eos_transactions: Option<EosSignedTransactions>,
    pub erc20_on_eos_peg_in_infos: Erc20OnEosPegInInfos,
    pub btc_utxos_and_values: Option<BtcUtxosAndValues>,
    pub eos_erc20_dictionary: Option<EosErc20Dictionary>,
    pub eth_submission_material: Option<EthSubmissionMaterial>,
}

impl<D> EthState<D> where D: DatabaseInterface {
    pub fn init(db: D) -> EthState<D> {
        EthState {
            db,
            misc: None,
            btc_transactions: None,
            eos_transactions: None,
            btc_utxos_and_values: None,
            eos_erc20_dictionary: None,
            eth_submission_material: None,
            btc_on_eth_redeem_infos: BtcOnEthRedeemInfos::new(vec![]),
            erc20_on_eos_peg_in_infos: Erc20OnEosPegInInfos::new(vec![]),
        }
    }

    pub fn add_eth_submission_material(mut self, eth_submission_material: EthSubmissionMaterial) -> Result<EthState<D>> {
        match self.eth_submission_material {
            Some(_) => Err(get_no_overwrite_state_err("eth_submission_material").into()),
            None => {
                self.eth_submission_material = Some(eth_submission_material);
                Ok(self)
            }
        }
    }

    pub fn add_btc_on_eth_redeem_infos(self, mut infos: BtcOnEthRedeemInfos) -> Result<EthState<D>> {
        let mut new_infos = self.btc_on_eth_redeem_infos.clone().0;
        new_infos.append(&mut infos.0);
        self.replace_btc_on_eth_redeem_infos(BtcOnEthRedeemInfos::new(new_infos))
    }

    pub fn add_erc20_on_eos_peg_in_infos(self, mut infos: Erc20OnEosPegInInfos) -> Result<EthState<D>> {
        let mut new_infos = self.erc20_on_eos_peg_in_infos.clone().0;
        new_infos.append(&mut infos.0);
        self.replace_erc20_on_eos_peg_in_infos(Erc20OnEosPegInInfos::new(new_infos))
    }

    pub fn replace_btc_on_eth_redeem_infos(mut self, replacements: BtcOnEthRedeemInfos) -> Result<EthState<D>> {
        self.btc_on_eth_redeem_infos = replacements;
        Ok(self)
    }

    pub fn replace_erc20_on_eos_peg_in_infos(mut self, replacements: Erc20OnEosPegInInfos) -> Result<EthState<D>> {
        self.erc20_on_eos_peg_in_infos = replacements;
        Ok(self)
    }

    pub fn add_misc_string_to_state(mut self, misc_string: String) -> Result<EthState<D>> {
        match self.misc {
            Some(_) => Err(get_no_overwrite_state_err("misc_string").into()),
            None => {
                self.misc = Some(misc_string);
                Ok(self)
            }
        }
    }

    pub fn add_btc_transactions(mut self, btc_transactions: BtcTransactions) -> Result<EthState<D>> {
        match self.btc_transactions {
            Some(_) => Err(get_no_overwrite_state_err("btc_transaction").into()),
            None => {
                self.btc_transactions = Some(btc_transactions);
                Ok(self)
            }
        }
    }

    pub fn add_eos_transactions(mut self, eos_transactions: EosSignedTransactions) -> Result<EthState<D>> {
        match self.eos_transactions {
            Some(_) => Err(get_no_overwrite_state_err("eos_transaction").into()),
            None => {
                self.eos_transactions = Some(eos_transactions);
                Ok(self)
            }
        }
    }

    pub fn add_btc_utxos_and_values(mut self, btc_utxos_and_values: BtcUtxosAndValues) -> Result<EthState<D>> {
        match self.btc_utxos_and_values {
            Some(_) => Err(get_no_overwrite_state_err("btc_utxos_and_values").into()),
            None => {
                self.btc_utxos_and_values = Some(btc_utxos_and_values);
                Ok(self)
            }
        }
    }

    pub fn update_eth_submission_material(
        mut self,
        new_eth_submission_material: EthSubmissionMaterial
    ) -> Result<EthState<D>> {
        self.eth_submission_material = Some(new_eth_submission_material);
        Ok(self)
    }

    pub fn get_eth_submission_material(&self) -> Result<&EthSubmissionMaterial> {
        match self.eth_submission_material {
            Some(ref eth_submission_material) => Ok(&eth_submission_material),
            None => Err(get_not_in_state_err("eth_submission_material").into())
        }
    }

    pub fn get_misc_string(&self) -> Result<String> {
        Ok(self.misc.clone().unwrap_or_default())
    }

    pub fn get_parent_hash(&self) -> Result<EthHash> {
        Ok(self.get_eth_submission_material()?.get_parent_hash()?)
    }

    pub fn get_num_eos_txs(&self) -> usize {
        match self.eos_transactions {
            None => 0,
            Some(ref txs) => txs.len(),
        }
    }

    pub fn add_eos_erc20_dictionary(mut self, dictionary: EosErc20Dictionary) -> Result<EthState<D>> {
        match self.eos_erc20_dictionary {
            Some(_) => Err(get_no_overwrite_state_err("eos_erc20_dictionary").into()),
            None => {
                self.eos_erc20_dictionary = Some(dictionary);
                Ok(self)
            }
        }
    }

    pub fn get_eos_erc20_dictionary(&self) -> Result<&EosErc20Dictionary> {
        match self.eos_erc20_dictionary {
            Some(ref dictionary) => Ok(dictionary),
            None => Err(get_not_in_state_err("eos_erc20_dictionary").into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        errors::AppError,
        test_utils::get_test_database,
        chains::eth::eth_test_utils::{
            get_sample_erc20_on_eos_peg_in_infos
        },
        btc_on_eth::eth::eth_test_utils::{
            get_expected_block,
            get_expected_receipt,
            SAMPLE_RECEIPT_INDEX,
            get_sample_eth_submission_material,
            get_sample_eth_submission_material_n,
            get_valid_state_with_block_and_receipts,
        },
    };

    #[test]
    fn should_fail_to_get_eth_submission_material_in_state() {
        let expected_error = get_not_in_state_err("eth_submission_material");
        let initial_state = EthState::init(get_test_database());
        match initial_state.get_eth_submission_material() {
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            Ok(_) => panic!("Eth block should not be in state yet!"),
            _ => panic!("Wrong error received!")
        };
    }

    #[test]
    fn should_add_eth_submission_material_state() {
        let expected_error = get_not_in_state_err("eth_submission_material");
        let eth_submission_material = get_sample_eth_submission_material();
        let initial_state = EthState::init(get_test_database());
        match initial_state.get_eth_submission_material() {
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            Ok(_) => panic!("Eth block should not be in state yet!"),
            _ => panic!("Wrong error received!")
        };
        let updated_state = initial_state.add_eth_submission_material(eth_submission_material).unwrap();
        let submission_material = updated_state.get_eth_submission_material().unwrap();
        let block = submission_material.get_block().unwrap();
        let receipt = submission_material.receipts.0[SAMPLE_RECEIPT_INDEX].clone();
        let expected_block = get_expected_block();
        let expected_receipt = get_expected_receipt();
        assert_eq!(block, expected_block);
        assert_eq!(receipt, expected_receipt);
    }

    #[test]
    fn should_err_when_overwriting_eth_submission_material_in_state() {
        let expected_error = get_no_overwrite_state_err("eth_submission_material");
        let eth_submission_material = get_sample_eth_submission_material();
        let initial_state = EthState::init(get_test_database());
        let updated_state = initial_state.add_eth_submission_material(eth_submission_material.clone()).unwrap();
        match updated_state.add_eth_submission_material(eth_submission_material) {
            Ok(_) => panic!("Overwriting state should not have succeeded!"),
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            _ => panic!("Wrong error recieved!")
        }
    }

    #[test]
    fn should_update_eth_submission_material() {
        let eth_submission_material_1 = get_sample_eth_submission_material_n(0).unwrap();
        let eth_submission_material_2 = get_sample_eth_submission_material_n(1).unwrap();
        let initial_state = EthState::init(get_test_database());
        let updated_state = initial_state.add_eth_submission_material(eth_submission_material_1).unwrap();
        let initial_state_block_num = updated_state.get_eth_submission_material().unwrap().get_block_number().unwrap();
        let final_state = updated_state.update_eth_submission_material(eth_submission_material_2).unwrap();
        let final_state_block_number = final_state.get_eth_submission_material().unwrap().get_block_number().unwrap();
        assert_ne!(final_state_block_number, initial_state_block_num);
    }

    #[test]
    fn should_get_eth_parent_hash() {
        let expected_result = get_sample_eth_submission_material().get_parent_hash().unwrap();
        let state = get_valid_state_with_block_and_receipts().unwrap();
        let result = state.get_parent_hash().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_add_erc20_on_eos_peg_in_info() {
        let info = get_sample_erc20_on_eos_peg_in_infos().unwrap();
        let state = get_valid_state_with_block_and_receipts().unwrap();
        let new_state = state.add_erc20_on_eos_peg_in_infos(info.clone()).unwrap();
        let mut len = new_state.erc20_on_eos_peg_in_infos.len();
        assert_eq!(len, 1);
        let final_state = new_state.add_erc20_on_eos_peg_in_infos(info).unwrap();
        len = final_state.erc20_on_eos_peg_in_infos.len();
        assert_eq!(len, 2);

    }
}
