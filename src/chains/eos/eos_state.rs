pub use bitcoin::blockdata::transaction::Transaction as BtcTransaction;

use crate::{
    btc_on_eos::eos::redeem_info::BtcOnEosRedeemInfos,
    chains::{
        btc::utxo_manager::utxo_types::BtcUtxosAndValues,
        eos::{
            eos_action_proofs::EosActionProofs,
            eos_block_header::EosBlockHeaderV2,
            eos_eth_token_dictionary::EosEthTokenDictionary,
            eos_global_sequences::{GlobalSequences, ProcessedGlobalSequences},
            eos_merkle_utils::Incremerkle,
            eos_producer_schedule::EosProducerScheduleV2,
            eos_submission_material::EosSubmissionMaterial,
            eos_types::Checksum256s,
            protocol_features::EnabledFeatures,
        },
        eth::eth_types::EthTransactions,
    },
    eos_on_eth::eos::eos_tx_info::EosOnEthEosTxInfos,
    erc20_on_eos::eos::redeem_info::Erc20OnEosRedeemInfos,
    traits::DatabaseInterface,
    types::Result,
    utils::{get_no_overwrite_state_err, get_not_in_state_err},
};

#[derive(Clone, Debug, PartialEq)]
pub struct EosState<D: DatabaseInterface> {
    pub db: D,
    pub block_num: Option<u64>,
    pub incremerkle: Incremerkle,
    pub producer_signature: String,
    pub action_proofs: EosActionProofs,
    pub interim_block_ids: Checksum256s,
    pub eth_signed_txs: EthTransactions,
    pub block_header: Option<EosBlockHeaderV2>,
    pub processed_tx_ids: ProcessedGlobalSequences,
    pub btc_on_eos_signed_txs: Vec<BtcTransaction>,
    pub enabled_protocol_features: EnabledFeatures,
    pub eos_on_eth_eos_tx_infos: EosOnEthEosTxInfos,
    pub btc_on_eos_redeem_infos: BtcOnEosRedeemInfos,
    pub active_schedule: Option<EosProducerScheduleV2>,
    pub btc_utxos_and_values: Option<BtcUtxosAndValues>,
    pub erc20_on_eos_redeem_infos: Erc20OnEosRedeemInfos,
    pub eos_eth_token_dictionary: Option<EosEthTokenDictionary>,
}

impl<D> EosState<D>
where
    D: DatabaseInterface,
{
    pub fn init(db: D) -> EosState<D> {
        EosState {
            db,
            block_num: None,
            block_header: None,
            action_proofs: vec![],
            active_schedule: None,
            eth_signed_txs: vec![],
            interim_block_ids: vec![],
            btc_utxos_and_values: None,
            eos_eth_token_dictionary: None,
            btc_on_eos_signed_txs: vec![],
            producer_signature: String::new(),
            incremerkle: Incremerkle::default(),
            enabled_protocol_features: EnabledFeatures::init(),
            processed_tx_ids: ProcessedGlobalSequences::new(vec![]),
            eos_on_eth_eos_tx_infos: EosOnEthEosTxInfos::new(vec![]),
            btc_on_eos_redeem_infos: BtcOnEosRedeemInfos::new(vec![]),
            erc20_on_eos_redeem_infos: Erc20OnEosRedeemInfos::new(vec![]),
        }
    }

    pub fn add_btc_utxos_and_values(mut self, btc_utxos_and_values: BtcUtxosAndValues) -> Result<EosState<D>> {
        match self.btc_utxos_and_values {
            Some(_) => Err(get_no_overwrite_state_err("btc_utxos_and_values").into()),
            None => {
                self.btc_utxos_and_values = Some(btc_utxos_and_values);
                Ok(self)
            },
        }
    }

    pub fn add_active_schedule(mut self, active_schedule: EosProducerScheduleV2) -> Result<EosState<D>> {
        match self.active_schedule {
            Some(_) => Err(get_no_overwrite_state_err("active_schedule").into()),
            None => {
                self.active_schedule = Some(active_schedule);
                Ok(self)
            },
        }
    }

    pub fn add_btc_on_eos_signed_txs(mut self, btc_on_eos_signed_txs: Vec<BtcTransaction>) -> Result<EosState<D>>
    where
        D: DatabaseInterface,
    {
        self.btc_on_eos_signed_txs = btc_on_eos_signed_txs;
        Ok(self)
    }

    pub fn add_eth_signed_txs(mut self, txs: EthTransactions) -> Result<EosState<D>>
    where
        D: DatabaseInterface,
    {
        self.eth_signed_txs = txs;
        Ok(self)
    }

    pub fn add_incremerkle(mut self, incremerkle: Incremerkle) -> EosState<D>
    where
        D: DatabaseInterface,
    {
        self.incremerkle = incremerkle;
        self
    }

    pub fn add_submission_material(mut self, submission_material: EosSubmissionMaterial) -> Result<EosState<D>> {
        self.block_num = Some(submission_material.block_num);
        self.action_proofs = submission_material.action_proofs;
        self.block_header = Some(submission_material.block_header);
        self.interim_block_ids = submission_material.interim_block_ids;
        self.producer_signature = submission_material.producer_signature;
        Ok(self)
    }

    pub fn add_btc_on_eos_redeem_infos(mut self, infos: BtcOnEosRedeemInfos) -> Result<EosState<D>> {
        self.btc_on_eos_redeem_infos = infos;
        Ok(self)
    }

    pub fn add_eos_on_eth_eos_tx_info(mut self, infos: EosOnEthEosTxInfos) -> Result<EosState<D>> {
        self.eos_on_eth_eos_tx_infos = infos;
        Ok(self)
    }

    pub fn add_erc20_on_eos_redeem_infos(mut self, infos: Erc20OnEosRedeemInfos) -> Result<EosState<D>> {
        self.erc20_on_eos_redeem_infos = infos;
        Ok(self)
    }

    pub fn add_processed_tx_ids(mut self, tx_ids: ProcessedGlobalSequences) -> Result<Self> {
        self.processed_tx_ids = tx_ids;
        Ok(self)
    }

    pub fn add_enabled_protocol_features(mut self, enabled_protocol_features: EnabledFeatures) -> Result<Self> {
        self.enabled_protocol_features = enabled_protocol_features;
        Ok(self)
    }

    pub fn get_eos_block_header(&self) -> Result<&EosBlockHeaderV2> {
        match self.block_header {
            Some(ref block_header) => Ok(block_header),
            None => Err(get_not_in_state_err("block_header").into()),
        }
    }

    pub fn add_eos_eth_token_dictionary(mut self, dictionary: EosEthTokenDictionary) -> Result<EosState<D>> {
        match self.eos_eth_token_dictionary {
            Some(_) => Err(get_no_overwrite_state_err("eos_eth_token_dictionary").into()),
            None => {
                self.eos_eth_token_dictionary = Some(dictionary);
                Ok(self)
            },
        }
    }

    pub fn get_eos_eth_token_dictionary(&self) -> Result<&EosEthTokenDictionary> {
        match self.eos_eth_token_dictionary {
            Some(ref dictionary) => Ok(dictionary),
            None => Err(get_not_in_state_err("eos_eth_token_dictionary").into()),
        }
    }

    pub fn get_eos_block_num(&self) -> Result<u64> {
        match self.block_num {
            Some(num) => Ok(num),
            None => Err(get_not_in_state_err("block_num").into()),
        }
    }

    pub fn get_active_schedule(&self) -> Result<&EosProducerScheduleV2> {
        match self.active_schedule {
            Some(ref active_schedule) => Ok(active_schedule),
            None => Err(get_not_in_state_err("active_schedule").into()),
        }
    }

    pub fn replace_btc_on_eos_redeem_infos(mut self, replacements: BtcOnEosRedeemInfos) -> Result<EosState<D>> {
        info!("✔ Replacing redeem infos in state...");
        self.btc_on_eos_redeem_infos = replacements;
        Ok(self)
    }

    pub fn replace_eos_on_eth_eos_tx_infos(mut self, replacements: EosOnEthEosTxInfos) -> Result<EosState<D>> {
        info!("✔ Replacing `EosOnEthEosTxInfos` in state...");
        self.eos_on_eth_eos_tx_infos = replacements;
        Ok(self)
    }

    pub fn replace_action_proofs(mut self, replacements: EosActionProofs) -> Result<EosState<D>> {
        info!("✔ Replacing `action_proofs` in state...");
        self.action_proofs = replacements;
        Ok(self)
    }

    pub fn get_global_sequences(&self) -> GlobalSequences {
        GlobalSequences::new(
            vec![
                self.eos_on_eth_eos_tx_infos.get_global_sequences().to_vec(),
                self.btc_on_eos_redeem_infos.get_global_sequences().to_vec(),
                self.erc20_on_eos_redeem_infos.get_global_sequences().to_vec(),
            ]
            .concat(),
        )
    }
}
