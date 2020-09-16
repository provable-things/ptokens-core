use eos_primitives::{
    BlockHeader as EosBlockHeader,
    ProducerScheduleV2 as EosProducerScheduleV2,
};
use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::utxo_manager::utxo_types::BtcUtxosAndValues,
    btc_on_eos::{
        btc::btc_types::BtcTransactions,
        eos::{
            eos_merkle_utils::Incremerkle,
            protocol_features::EnabledFeatures,
            parse_submission_material::EosSubmissionMaterial,
            eos_types::{
                ActionProofs,
                Checksum256s,
                RedeemParams,
                ProcessedTxIds,
            },
        },
        utils::{
            get_not_in_state_err,
            get_no_overwrite_state_err,
        },
    },
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EosState<D: DatabaseInterface> {
    pub db: D,
    pub block_num: Option<u64>,
    pub incremerkle: Incremerkle,
    pub producer_signature: String,
    pub action_proofs: ActionProofs,
    pub signed_txs: BtcTransactions,
    pub interim_block_ids: Checksum256s,
    pub redeem_params: Vec<RedeemParams>,
    pub processed_tx_ids: ProcessedTxIds,
    pub block_header: Option<EosBlockHeader>,
    pub enabled_protocol_features: EnabledFeatures,
    pub active_schedule: Option<EosProducerScheduleV2>,
    pub btc_utxos_and_values: Option<BtcUtxosAndValues>,
}

impl<D> EosState<D> where D: DatabaseInterface {
    pub fn init(db: D) -> EosState<D> {
        EosState {
            db,
            block_num: None,
            block_header: None,
            signed_txs: vec![],
            action_proofs: vec![],
            redeem_params: vec![],
            active_schedule: None,
            interim_block_ids: vec![],
            btc_utxos_and_values: None,
            producer_signature: String::new(),
            incremerkle: Incremerkle::default(),
            processed_tx_ids: ProcessedTxIds::init(),
            enabled_protocol_features: EnabledFeatures::init(),
        }
    }

    pub fn add_btc_utxos_and_values(
        mut self,
        btc_utxos_and_values: BtcUtxosAndValues,
    ) -> Result<EosState<D>> {
        match self.btc_utxos_and_values {
            Some(_) => Err(get_no_overwrite_state_err("btc_utxos_and_values").into()),
            None => {
                self.btc_utxos_and_values = Some(btc_utxos_and_values);
                Ok(self)
            }
        }
    }

    pub fn add_active_schedule(
        mut self,
        active_schedule: EosProducerScheduleV2,
    ) -> Result<EosState<D>> {
        match self.active_schedule {
            Some(_) => Err(get_no_overwrite_state_err("active_schedule").into()),
            None => {
                self.active_schedule = Some(active_schedule);
                Ok(self)
            }
        }
    }

    pub fn add_signed_txs(
        mut self,
        signed_txs: BtcTransactions,
    ) -> Result<EosState<D>>
        where D: DatabaseInterface
    {
        self.signed_txs = signed_txs;
        Ok(self)
    }

    pub fn add_incremerkle(
        mut self,
        incremerkle: Incremerkle,
    ) -> EosState<D>
        where D: DatabaseInterface
    {
        self.incremerkle = incremerkle;
        self
    }

    pub fn add_submission_material(
        mut self,
        submission_material: EosSubmissionMaterial,
    ) -> Result<EosState<D>> {
        self.block_num = Some(submission_material.block_num);
        self.action_proofs = submission_material.action_proofs;
        self.block_header = Some(submission_material.block_header);
        self.interim_block_ids = submission_material.interim_block_ids;
        self.producer_signature = submission_material.producer_signature;
        Ok(self)
    }

    pub fn add_redeem_params(
        mut self,
        redeem_params: Vec<RedeemParams>,
    ) -> Result<EosState<D>> {
        self.redeem_params = redeem_params;
        Ok(self)
    }

    pub fn add_processed_tx_ids(
        mut self,
        tx_ids: ProcessedTxIds,
    ) -> Result<Self> {
        self.processed_tx_ids = tx_ids;
        Ok(self)
    }

    pub fn add_enabled_protocol_features(
        mut self,
        enabled_protocol_features: EnabledFeatures,
    ) -> Result<Self> {
        self.enabled_protocol_features = enabled_protocol_features;
        Ok(self)
    }

    pub fn get_eos_block_header(&self) -> Result<&EosBlockHeader> {
        match &self.block_header{
            Some(block_header) => Ok(&block_header),
            None => Err(get_not_in_state_err("block_header").into())
        }
    }

    pub fn get_eos_block_num(&self) -> Result<u64> {
        match self.block_num {
            Some(num) => Ok(num),
            None => Err(get_not_in_state_err("block_num").into())
        }
    }

    pub fn get_active_schedule(&self) -> Result<&EosProducerScheduleV2> {
        match &self.active_schedule{
            Some(active_schedule) => Ok(&active_schedule),
            None => Err(get_not_in_state_err("active_schedule").into())
        }
    }

    pub fn replace_redeem_params(
        mut self,
        replacement_params: Vec<RedeemParams>,
    ) -> Result<EosState<D>> {
        info!("✔ Replacing redeem params in state...");
        self.redeem_params = replacement_params;
        Ok(self)
    }

    pub fn replace_action_proofs(
        mut self,
        replacements: ActionProofs,
    ) -> Result<EosState<D>> {
        info!("✔ Replacing `action_proofs` in state...");
        self.action_proofs = replacements;
        Ok(self)
    }
}
