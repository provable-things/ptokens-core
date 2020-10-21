use derive_more::{
    Deref,
    Constructor,
};
use eos_primitives::{
    Checksum256,
    AccountName as EosAccountName,
};
use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::{
        btc::btc_constants::MINIMUM_REQUIRED_SATOSHIS,
        eos::{
            eos_state::EosState,
            eos_action_proofs::EosActionProof,
            eos_types::{
                ProcessedTxIds,
                GlobalSequence,
                GlobalSequences,
            },
        },
    },
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtcOnEosRedeemInfo {
    pub amount: u64,
    pub recipient: String,
    pub from: EosAccountName,
    pub originating_tx_id: Checksum256,
    pub global_sequence: GlobalSequence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Deref, Constructor)]
pub struct BtcOnEosRedeemInfos(pub Vec<BtcOnEosRedeemInfo>);

impl BtcOnEosRedeemInfos {
    pub fn sum(&self) -> u64 {
        self.0.iter().fold(0, |acc, infos| acc + infos.amount)
    }

    pub fn get_global_sequences(&self) -> GlobalSequences {
        self.0.iter().map(|infos| infos.global_sequence).collect()
    }

    pub fn from_action_proofs(action_proofs: &[EosActionProof]) -> Result<BtcOnEosRedeemInfos> {
        Ok(BtcOnEosRedeemInfos::new(
            action_proofs
                .iter()
                .map(|action_proof| action_proof.to_btc_on_eos_redeem_info())
                .collect::<Result<Vec<BtcOnEosRedeemInfo>>>()?
        ))
    }

    pub fn filter_out_already_processed_txs(&self, processed_tx_ids: &ProcessedTxIds) -> Result<BtcOnEosRedeemInfos> {
        Ok(BtcOnEosRedeemInfos::new(
            self
                .iter()
                .filter(|info| !processed_tx_ids.contains(&info.global_sequence))
                .cloned()
                .collect::<Vec<BtcOnEosRedeemInfo>>()
        ))
    }
}

pub fn maybe_parse_redeem_infos_and_put_in_state<D>(
    state: EosState<D>
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    info!("✔ Parsing redeem params from actions data...");
    BtcOnEosRedeemInfos::from_action_proofs(&state.action_proofs)
        .and_then(|redeem_infos| {
            info!("✔ Parsed {} sets of redeem info!", redeem_infos.len());
            state.add_btc_on_eos_redeem_infos(redeem_infos)
        })
}

pub fn filter_out_value_too_low_btc_on_eos_redeem_infos(
    redeem_infos: &BtcOnEosRedeemInfos
) -> Result<BtcOnEosRedeemInfos> {
    Ok(BtcOnEosRedeemInfos::new(
        redeem_infos
            .iter()
            .map(|redeem_info| redeem_info.amount)
            .zip(redeem_infos.0.iter())
            .filter_map(|(amount, redeem_info)| {
                match amount >= MINIMUM_REQUIRED_SATOSHIS {
                    true => Some(redeem_info),
                    false => {
                        info!("✘ Filtering redeem redeem info ∵ value too low: {:?}", redeem_info);
                        None
                    }
                }
            })
            .cloned()
            .collect::<Vec<BtcOnEosRedeemInfo>>()
    ))
}


pub fn maybe_filter_value_too_low_redeem_infos_in_state<D>(
    state: EosState<D>
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    info!("✔ Filtering out any redeem infos below minimum # of Satoshis...");
    filter_out_value_too_low_btc_on_eos_redeem_infos(&state.btc_on_eos_redeem_infos)
        .and_then(|new_infos| state.replace_btc_on_eos_redeem_infos(new_infos))
}

pub fn maybe_filter_out_already_processed_tx_ids_from_state<D>(
    state: EosState<D>
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    info!("✔ Filtering out already processed tx IDs...");
    state.btc_on_eos_redeem_infos.filter_out_already_processed_txs(&state.processed_tx_ids)
        .and_then(|filtered| state.add_btc_on_eos_redeem_infos(filtered))
}
