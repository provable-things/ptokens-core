use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::{
        deposit_address_info::DepositInfoHashMap,
        utxo_manager::utxo_types::BtcUtxosAndValues,
    },
    btc_on_eth::{
        eth::eth_types::{
            EthTransactions,
            RelayTransactions,
        },
        btc::{
            btc_types::{
                BtcBlockAndId,
                MintingParams,
                MintingParamStruct,
                BtcTransaction,
                BtcTransactions,
                BtcBlockInDbFormat,
            },
            parse_submission_material_json::BtcSubmissionMaterialJson,
        },
        utils::{
            get_not_in_state_err,
            get_no_overwrite_state_err,
        },
    },
};

#[derive(Clone, PartialEq, Eq)]
pub struct BtcState<D: DatabaseInterface> {
    pub db: D,
    pub minting_params: MintingParams,
    pub output_json_string: Option<String>,
    pub utxos_and_values: BtcUtxosAndValues,
    pub submission_json: Option<BtcSubmissionMaterialJson>,
    pub btc_block_and_id: Option<BtcBlockAndId>,
    pub eth_signed_txs: Option<EthTransactions>,
    pub p2sh_deposit_txs: Option<BtcTransactions>,
    pub op_return_deposit_txs: Option<BtcTransactions>,
    pub deposit_info_hash_map: Option<DepositInfoHashMap>,
    pub btc_block_in_db_format: Option<BtcBlockInDbFormat>,
    pub any_sender: Option<bool>,
    pub any_sender_signed_txs: Option<RelayTransactions>,
}

impl<D> BtcState<D> where D: DatabaseInterface {
    pub fn init(db: D) -> BtcState<D> {
        BtcState {
            db,
            eth_signed_txs: None,
            submission_json: None,
            btc_block_and_id: None,
            p2sh_deposit_txs: None,
            output_json_string: None,
            minting_params: Vec::new(),
            op_return_deposit_txs: None,
            deposit_info_hash_map: None,
            btc_block_in_db_format: None,
            utxos_and_values: Vec::new(),
            any_sender: None,
            any_sender_signed_txs: None,
        }
    }

    pub fn add_btc_block_and_id(
        mut self,
        btc_block_and_id: BtcBlockAndId,
    ) -> Result<BtcState<D>> {
        match self.btc_block_and_id {
            Some(_) => Err(get_no_overwrite_state_err("btc_block_and_id").into()),
            None => {
                info!("✔ Adding BTC block and ID to BTC state...");
                self.btc_block_and_id = Some(btc_block_and_id);
                Ok(self)
            }
        }
    }

    pub fn add_p2sh_deposit_txs(
        mut self,
        p2sh_deposit_txs: BtcTransactions,
    ) -> Result<BtcState<D>> {
        match self.p2sh_deposit_txs {
            Some(_) => Err(get_no_overwrite_state_err("p2sh_deposit_txs").into()),
            None => {
                info!("✔ Adding `p2sh` deposit txs to BTC state...");
                self.p2sh_deposit_txs = Some(p2sh_deposit_txs);
                Ok(self)
            }
        }
    }

    pub fn add_output_json_string(
        mut self,
        output_json_string: String,
    ) -> Result<BtcState<D>> {
        match self.output_json_string {
            Some(_) => Err(get_no_overwrite_state_err("output_json_string").into()),
            None => {
                info!("✔ Adding BTC output JSON to BTC state...");
                self.output_json_string = Some(output_json_string);
                Ok(self)
            }
        }
    }

    pub fn add_btc_block_in_db_format(
        mut self,
        btc_block_in_db_format: BtcBlockInDbFormat,
    ) -> Result<BtcState<D>> {
        match self.btc_block_in_db_format {
            Some(_) => Err(get_no_overwrite_state_err("btc_block_in_db_format").into()),
            None => {
                info!("✔ Adding BTC block in DB format to BTC state...");
                self.btc_block_in_db_format = Some(btc_block_in_db_format);
                Ok(self)
            }
        }
    }

    pub fn add_op_return_deposit_txs(
        mut self,
        op_return_deposit_txs: BtcTransactions,
    ) -> Result<BtcState<D>> {
        match self.op_return_deposit_txs {
            Some(_) => Err(get_no_overwrite_state_err("op_return_deposit_txs").into()),
            None => {
                info!("✔ Adding `op_return` deposit txs to BTC state...");
                self.op_return_deposit_txs = Some(op_return_deposit_txs);
                Ok(self)
            }
        }
    }

    pub fn add_deposit_info_hash_map(
        mut self,
        deposit_info_hash_map: DepositInfoHashMap,
    ) -> Result<BtcState<D>> {
        match self.deposit_info_hash_map {
            Some(_) => Err(get_no_overwrite_state_err("deposit_info_hash_map").into()),
            None => {
                info!("✔ Adding deposit info hash map to BTC state...");
                self.deposit_info_hash_map = Some(deposit_info_hash_map);
                Ok(self)
            }
        }
    }

    pub fn add_minting_params(
        mut self,
        mut new_minting_params: MintingParams,
    ) -> Result<BtcState<D>> {
        info!("✔ Adding minting params to state...");
        self.minting_params
            .append(&mut new_minting_params);
        Ok(self)
    }

    pub fn replace_utxos_and_values(
        mut self,
        replacement_params: BtcUtxosAndValues,
    ) -> Result<BtcState<D>> {
        info!("✔ Replacing UTXOs in state...");
        self.utxos_and_values = replacement_params;
        Ok(self)
    }

    pub fn replace_minting_params(
        mut self,
        replacement_params: MintingParams
    ) -> Result<BtcState<D>> {
        info!("✔ Replacing minting params in state...");
        self.minting_params = replacement_params;
        Ok(self)
    }

    pub fn add_eth_signed_txs(
        mut self,
        eth_signed_txs: EthTransactions,
    ) -> Result<BtcState<D>> {
        match self.eth_signed_txs {
            Some(_) => Err(get_no_overwrite_state_err("eth_signed_txs").into()),
            None => {
                info!("✔ Adding ETH signed txs to BTC state...");
                self.eth_signed_txs = Some(eth_signed_txs);
                Ok(self)
            }
        }
    }

    pub fn add_any_sender_signed_txs(
        mut self,
        any_sender_signed_txs: RelayTransactions,
    ) -> Result<BtcState<D>> {
        match self.any_sender_signed_txs {
            Some(_) => Err(get_no_overwrite_state_err("any_sender_signed_txs").into()),
            None => {
                info!("✔ Adding AnySender signed txs to BTC state...");
                self.any_sender_signed_txs = Some(any_sender_signed_txs);
                Ok(self)
            }
        }
    }

    pub fn add_utxos_and_values(
        mut self,
        mut utxos_and_values: BtcUtxosAndValues,
    ) -> Result<BtcState<D>> {
        info!("✔ Adding UTXOs & values to BTC state...");
        self.utxos_and_values
            .append(&mut utxos_and_values);
        Ok(self)
    }

    pub fn get_btc_block_and_id(
        &self
    ) -> Result<&BtcBlockAndId> {
        match &self.btc_block_and_id {
            Some(btc_block_and_id) => {
                info!("✔ Getting BTC block & ID from BTC state...");
                Ok(&btc_block_and_id)
            }
            None => Err(get_not_in_state_err("btc_block_and_id").into())
        }
    }

    pub fn get_eth_signed_txs(
        &self
    ) -> Result<&EthTransactions> {
        match &self.eth_signed_txs {
            Some(eth_signed_txs) => {
                info!("✔ Getting ETH signed txs from BTC state...");
                Ok(&eth_signed_txs)
            }
            None => Err(get_not_in_state_err("eth_signed_txs").into())
        }
    }

    pub fn get_minting_params(
        &self
    ) -> Result<&[MintingParamStruct]> {
        Ok(&self.minting_params)
    }

    pub fn get_deposit_info_hash_map(
        &self
    ) -> Result<&DepositInfoHashMap> {
        match &self.deposit_info_hash_map {
            Some(deposit_info_hash_map) => {
                info!("✔ Getting deposit info hash map from BTC state...");
                Ok(&deposit_info_hash_map)
            }
            None => Err(get_not_in_state_err("deposit_info_hash_map").into())
        }
    }

    pub fn get_op_return_deposit_txs(
        &self
    ) -> Result<&[BtcTransaction]> {
        match &self.op_return_deposit_txs {
            Some(op_return_deposit_txs) => {
                info!("✔ Getting `op_return` deposit txs from BTC state...");
                Ok(&op_return_deposit_txs)
            }
            None => Err(get_not_in_state_err("op_return_deposit_txs").into())
        }
    }

    pub fn get_p2sh_deposit_txs(
        &self
    ) -> Result<&[BtcTransaction]> {
        match &self.p2sh_deposit_txs {
            Some(p2sh_deposit_txs) => {
                info!("✔ Getting `p2sh` deposit txs from BTC state...");
                Ok(&p2sh_deposit_txs)
            }
            None => Err(get_not_in_state_err("p2sh_deposit_txs").into())
        }
    }

    pub fn get_btc_block_in_db_format(
        &self
    ) -> Result<&BtcBlockInDbFormat> {
        match &self.btc_block_in_db_format {
            Some(btc_block_in_db_format) => {
                info!("✔ Getting BTC block in DB format from BTC state...");
                Ok(&btc_block_in_db_format)
            }
            None => Err(get_not_in_state_err("btc_block_in_db_format").into())
        }
    }

    pub fn get_output_json_string(
        &self
    ) -> Result<&str> {
        match &self.output_json_string {
            Some(output_json_string) => {
                info!("✔ Getting BTC output json string from state...");
                Ok(&output_json_string)
            }
            None => Err(get_not_in_state_err("output_json_string").into())
        }
    }

    pub fn use_any_sender_tx_type(&self) -> bool {
        self.any_sender == Some(true)
    }

    pub fn add_btc_submission_json(
        mut self,
        submission_json: BtcSubmissionMaterialJson,
    ) -> Result<BtcState<D>> {
        info!("✔ Adding BTC submission json to BTC state...");
        self.submission_json = Some(submission_json);
        Ok(self)
    }

    pub fn get_btc_submission_json(
        &self
    ) -> Result<&BtcSubmissionMaterialJson> {
        match self.submission_json {
            Some(ref submission_json) => {
                info!("✔ Getting BTC submission json from BTC state...");
                Ok(submission_json)
            }
            None => Err(get_not_in_state_err("submission_json").into())
        }
    }

    pub fn add_any_sender_flag(
        mut self,
        any_sender: Option<bool>,
    ) -> Result<BtcState<D>> {
        info!("✔ Adding AnySender flag to BTC state...");
        self.any_sender = any_sender;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        errors::AppError,
        test_utils::get_test_database,
    };

    #[test]
    fn should_fail_to_get_btc_block_and_receipts_in_state() {
        let expected_error = get_not_in_state_err("btc_block_and_id");
        let initial_state = BtcState::init(get_test_database());
        match initial_state.get_btc_block_and_id() {
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            Ok(_) => panic!("Block should not be in state yet!"),
            _ => panic!("Wrong error received!")
        };
    }
}
