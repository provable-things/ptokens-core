use crate::{
    btc_on_eos::btc::minting_params::BtcOnEosMintingParams,
    btc_on_eth::btc::minting_params::BtcOnEthMintingParams,
    chains::{
        btc::{
            btc_block::{BtcBlockAndId, BtcBlockInDbFormat},
            btc_submission_material::{BtcSubmissionMaterial, BtcSubmissionMaterialJson},
            btc_types::{BtcTransaction, BtcTransactions},
            deposit_address_info::{DepositInfoHashMap, DepositInfoList},
            utxo_manager::utxo_types::BtcUtxosAndValues,
        },
        eos::eos_crypto::eos_transaction::EosSignedTransactions,
        eth::eth_types::{EthTransactions, RelayTransactions},
    },
    traits::DatabaseInterface,
    types::{NoneError, Result},
    utils::{get_no_overwrite_state_err, get_not_in_state_err},
};

#[derive(Clone, PartialEq, Eq)]
pub struct BtcState<D: DatabaseInterface> {
    pub db: D,
    pub any_sender: Option<bool>,
    pub ref_block_num: Option<u16>,
    pub ref_block_prefix: Option<u32>,
    pub signed_txs: EosSignedTransactions,
    pub output_json_string: Option<String>,
    pub utxos_and_values: BtcUtxosAndValues,
    pub eth_signed_txs: Option<EthTransactions>,
    pub btc_block_and_id: Option<BtcBlockAndId>,
    pub p2sh_deposit_txs: Option<BtcTransactions>,
    pub p2pkh_deposit_txs: Option<BtcTransactions>,
    pub btc_on_eos_minting_params: BtcOnEosMintingParams,
    pub btc_on_eth_minting_params: BtcOnEthMintingParams,
    pub deposit_info_hash_map: Option<DepositInfoHashMap>,
    pub any_sender_signed_txs: Option<RelayTransactions>,
    pub btc_block_in_db_format: Option<BtcBlockInDbFormat>,
    pub submission_json: Option<BtcSubmissionMaterialJson>,
}

impl<D> BtcState<D>
where
    D: DatabaseInterface,
{
    pub fn init(db: D) -> BtcState<D> {
        BtcState {
            db,
            any_sender: None,
            ref_block_num: None,
            eth_signed_txs: None,
            submission_json: None,
            btc_block_and_id: None,
            ref_block_prefix: None,
            p2sh_deposit_txs: None,
            output_json_string: None,
            any_sender_signed_txs: None,
            p2pkh_deposit_txs: None,
            deposit_info_hash_map: None,
            btc_block_in_db_format: None,
            utxos_and_values: vec![].into(),
            signed_txs: EosSignedTransactions::new(vec![]),
            btc_on_eos_minting_params: BtcOnEosMintingParams::new(vec![]),
            btc_on_eth_minting_params: BtcOnEthMintingParams::new(vec![]),
        }
    }

    pub fn add_btc_submission_json(mut self, submission_json: BtcSubmissionMaterialJson) -> Result<BtcState<D>> {
        info!("✔ Adding BTC submission json to BTC state...");
        self.submission_json = Some(submission_json);
        Ok(self)
    }

    pub fn add_p2pkh_deposit_txs(mut self, p2pkh_deposit_txs: BtcTransactions) -> Result<BtcState<D>> {
        match self.p2pkh_deposit_txs {
            Some(_) => Err(get_no_overwrite_state_err("p2pkh_deposit_txs").into()),
            None => {
                info!("✔ Adding `p2pkh` deposit txs to BTC state...");
                self.p2pkh_deposit_txs = Some(p2pkh_deposit_txs);
                Ok(self)
            },
        }
    }

    pub fn get_p2pkh_deposit_txs(&self) -> Result<&[BtcTransaction]> {
        match &self.p2pkh_deposit_txs {
            Some(ref p2pkh_deposit_txs) => {
                info!("✔ Getting `p2pkh` deposit txs from BTC state...");
                Ok(p2pkh_deposit_txs)
            },
            None => Err(get_not_in_state_err("p2pkh_deposit_txs").into()),
        }
    }

    pub fn add_btc_block_and_id(mut self, btc_block_and_id: BtcBlockAndId) -> Result<BtcState<D>> {
        match self.btc_block_and_id {
            Some(_) => Err(get_no_overwrite_state_err("btc_block_and_id").into()),
            None => {
                info!("✔ Adding BTC block and ID to BTC state...");
                self.btc_block_and_id = Some(btc_block_and_id);
                Ok(self)
            },
        }
    }

    pub fn add_eth_signed_txs(mut self, eth_signed_txs: EthTransactions) -> Result<BtcState<D>> {
        match self.eth_signed_txs {
            Some(_) => Err(get_no_overwrite_state_err("eth_signed_txs").into()),
            None => {
                info!("✔ Adding ETH signed txs to BTC state...");
                self.eth_signed_txs = Some(eth_signed_txs);
                Ok(self)
            },
        }
    }

    pub fn get_eth_signed_txs(&self) -> Result<&EthTransactions> {
        match self.eth_signed_txs {
            Some(ref eth_signed_txs) => {
                info!("✔ Getting ETH signed txs from BTC state...");
                Ok(eth_signed_txs)
            },
            None => Err(get_not_in_state_err("eth_signed_txs").into()),
        }
    }

    pub fn add_btc_submission_material(mut self, submission_material: BtcSubmissionMaterial) -> Result<BtcState<D>> {
        match self.btc_block_and_id {
            Some(_) => Err(get_no_overwrite_state_err("btc_block_and_id").into()),
            None => {
                info!("✔ Adding BTC submission material to state...");
                self.ref_block_num = submission_material.ref_block_num;
                self.ref_block_prefix = submission_material.ref_block_prefix;
                self.btc_block_and_id = Some(submission_material.block_and_id);
                Ok(self)
            },
        }
    }

    pub fn add_p2sh_deposit_txs(mut self, p2sh_deposit_txs: BtcTransactions) -> Result<BtcState<D>> {
        match self.p2sh_deposit_txs {
            Some(_) => Err(get_no_overwrite_state_err("p2sh_deposit_txs").into()),
            None => {
                info!("✔ Adding `p2sh` deposit txs to BTC state...");
                self.p2sh_deposit_txs = Some(p2sh_deposit_txs);
                Ok(self)
            },
        }
    }

    pub fn add_output_json_string(mut self, output_json_string: String) -> Result<BtcState<D>> {
        match self.output_json_string {
            Some(_) => Err(get_no_overwrite_state_err("output_json_string").into()),
            None => {
                info!("✔ Adding BTC output JSON to BTC state...");
                self.output_json_string = Some(output_json_string);
                Ok(self)
            },
        }
    }

    pub fn add_btc_block_in_db_format(mut self, btc_block_in_db_format: BtcBlockInDbFormat) -> Result<BtcState<D>> {
        match self.btc_block_in_db_format {
            Some(_) => Err(get_no_overwrite_state_err("btc_block_in_db_format").into()),
            None => {
                info!("✔ Adding BTC block in DB format to BTC state...");
                self.btc_block_in_db_format = Some(btc_block_in_db_format);
                Ok(self)
            },
        }
    }

    pub fn add_deposit_info_hash_map(mut self, deposit_info_hash_map: DepositInfoHashMap) -> Result<BtcState<D>> {
        match self.deposit_info_hash_map {
            Some(_) => Err(get_no_overwrite_state_err("deposit_info_hash_map").into()),
            None => {
                info!("✔ Adding deposit info hash map to BTC state...");
                self.deposit_info_hash_map = Some(deposit_info_hash_map);
                Ok(self)
            },
        }
    }

    pub fn add_btc_on_eos_minting_params(mut self, mut params: BtcOnEosMintingParams) -> Result<BtcState<D>> {
        info!("✔ Adding `btc-on-eos` minting params to state...");
        self.btc_on_eos_minting_params.append(&mut params);
        Ok(self)
    }

    pub fn add_btc_on_eth_minting_params(mut self, mut params: BtcOnEthMintingParams) -> Result<BtcState<D>> {
        info!("✔ Adding `btc-on-eth` minting params to state...");
        self.btc_on_eth_minting_params.append(&mut params);
        Ok(self)
    }

    pub fn replace_utxos_and_values(mut self, replacement_utxos: BtcUtxosAndValues) -> Result<BtcState<D>> {
        info!("✔ Replacing UTXOs in state...");
        self.utxos_and_values = replacement_utxos;
        Ok(self)
    }

    pub fn replace_btc_on_eth_minting_params(
        mut self,
        replacement_params: BtcOnEthMintingParams,
    ) -> Result<BtcState<D>> {
        info!("✔ Replacing `btc-on-eth` minting params in state...");
        self.btc_on_eth_minting_params = replacement_params;
        Ok(self)
    }

    pub fn add_signed_txs(mut self, signed_txs: EosSignedTransactions) -> Result<BtcState<D>> {
        match self.signed_txs.len() {
            0 => {
                info!("✔ Adding signed txs to state...");
                self.signed_txs = signed_txs;
                Ok(self)
            },
            _ => Err(get_no_overwrite_state_err("signed_txs").into()),
        }
    }

    pub fn add_utxos_and_values(mut self, utxos_and_values: BtcUtxosAndValues) -> Result<BtcState<D>> {
        info!("✔ Adding UTXOs & values to BTC state...");
        self.utxos_and_values.extend(utxos_and_values);
        Ok(self)
    }

    pub fn get_btc_block_and_id(&self) -> Result<&BtcBlockAndId> {
        match &self.btc_block_and_id {
            Some(btc_block_and_id) => {
                info!("✔ Getting BTC block & ID from BTC state...");
                Ok(&btc_block_and_id)
            },
            None => Err(get_not_in_state_err("btc_block_and_id").into()),
        }
    }

    pub fn get_deposit_info_list(&self) -> Result<&DepositInfoList> {
        self.get_btc_block_and_id()
            .map(|block_and_id| &block_and_id.deposit_address_list)
    }

    pub fn get_deposit_info_hash_map(&self) -> Result<&DepositInfoHashMap> {
        match &self.deposit_info_hash_map {
            Some(deposit_info_hash_map) => {
                info!("✔ Getting deposit info hash map from BTC state...");
                Ok(&deposit_info_hash_map)
            },
            None => Err(get_not_in_state_err("deposit_info_hash_map").into()),
        }
    }

    pub fn get_p2sh_deposit_txs(&self) -> Result<&[BtcTransaction]> {
        match &self.p2sh_deposit_txs {
            Some(p2sh_deposit_txs) => {
                info!("✔ Getting `p2sh` deposit txs from BTC state...");
                Ok(&p2sh_deposit_txs)
            },
            None => Err(get_not_in_state_err("p2sh_deposit_txs").into()),
        }
    }

    pub fn get_btc_block_in_db_format(&self) -> Result<&BtcBlockInDbFormat> {
        match &self.btc_block_in_db_format {
            Some(btc_block_in_db_format) => {
                info!("✔ Getting BTC block in DB format from BTC state...");
                Ok(&btc_block_in_db_format)
            },
            None => Err(get_not_in_state_err("btc_block_in_db_format").into()),
        }
    }

    pub fn get_output_json_string(&self) -> Result<&str> {
        match &self.output_json_string {
            Some(output_json_string) => {
                info!("✔ Getting BTC output json string from state...");
                Ok(&output_json_string)
            },
            None => Err(get_not_in_state_err("output_json_string").into()),
        }
    }

    pub fn add_any_sender_flag(mut self, any_sender: Option<bool>) -> Result<BtcState<D>> {
        info!("✔ Adding AnySender flag to BTC state...");
        self.any_sender = any_sender;
        Ok(self)
    }

    pub fn use_any_sender_tx_type(&self) -> bool {
        self.any_sender == Some(true)
    }

    pub fn add_any_sender_signed_txs(mut self, any_sender_signed_txs: RelayTransactions) -> Result<BtcState<D>> {
        match self.any_sender_signed_txs {
            Some(_) => Err(get_no_overwrite_state_err("any_sender_signed_txs").into()),
            None => {
                info!("✔ Adding AnySender signed txs to BTC state...");
                self.any_sender_signed_txs = Some(any_sender_signed_txs);
                Ok(self)
            },
        }
    }

    pub fn get_btc_submission_json(&self) -> Result<&BtcSubmissionMaterialJson> {
        match self.submission_json {
            Some(ref submission_json) => {
                info!("✔ Getting BTC submission json from BTC state...");
                Ok(submission_json)
            },
            None => Err(get_not_in_state_err("submission_json").into()),
        }
    }

    pub fn get_eos_ref_block_num(&self) -> Result<u16> {
        self.ref_block_num
            .ok_or(NoneError("No `ref_block_num` in submission material!"))
    }

    pub fn get_eos_ref_block_prefix(&self) -> Result<u32> {
        self.ref_block_prefix
            .ok_or(NoneError("No `ref_block_prefix` in submission material!"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{errors::AppError, test_utils::get_test_database};

    #[test]
    fn should_fail_to_get_btc_block_and_receipts_in_state() {
        let expected_error = get_not_in_state_err("btc_block_and_id");
        let initial_state = BtcState::init(get_test_database());
        match initial_state.get_btc_block_and_id() {
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            Ok(_) => panic!("Block should not be in state yet!"),
            _ => panic!("Wrong error received!"),
        };
    }
}
