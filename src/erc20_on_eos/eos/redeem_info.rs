use ethereum_types::{
    U256,
    Address as EthAddress,
};
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
    chains::eos::{
        eos_state::EosState,
        eos_action_proofs::EosActionProof,
        eos_erc20_dictionary::EosErc20Dictionary,
        eos_types::{
            ProcessedTxIds,
            GlobalSequence,
            GlobalSequences,
        },
    },
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Constructor)]
pub struct Erc20OnEosRedeemInfo {
    pub amount: U256,
    pub from: EosAccountName,
    pub recipient: EthAddress,
    pub eth_token_address: EthAddress,
    pub originating_tx_id: Checksum256,
    pub global_sequence: GlobalSequence,
    pub eos_token_address: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Deref, Constructor)]
pub struct Erc20OnEosRedeemInfos(pub Vec<Erc20OnEosRedeemInfo>);

impl Erc20OnEosRedeemInfos {
    pub fn get_global_sequences(&self) -> GlobalSequences {
        self.iter().map(|infos| infos.global_sequence).collect()
    }

    pub fn from_action_proofs(
        action_proofs: &[EosActionProof],
        dictionary: &EosErc20Dictionary,
    ) -> Result<Erc20OnEosRedeemInfos> {
        Ok(Erc20OnEosRedeemInfos::new(
            action_proofs
                .iter()
                .map(|action_proof| action_proof.to_erc20_on_eos_redeem_info(dictionary))
                .collect::<Result<Vec<Erc20OnEosRedeemInfo>>>()?
        ))
    }

    pub fn filter_out_already_processed_txs(&self, processed_tx_ids: &ProcessedTxIds) -> Result<Self> {
        Ok(Erc20OnEosRedeemInfos::new(
            self
                .iter()
                .filter(|info| !processed_tx_ids.contains(&info.global_sequence))
                .cloned()
                .collect::<Vec<Erc20OnEosRedeemInfo>>()
        ))
    }
}

pub fn maybe_parse_redeem_infos_and_put_in_state<D>(
    state: EosState<D>
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    info!("✔ Parsing redeem params from actions data...");
    Erc20OnEosRedeemInfos::from_action_proofs(&state.action_proofs, state.get_eos_erc20_dictionary()?)
        .and_then(|redeem_infos| {
            info!("✔ Parsed {} sets of redeem info!", redeem_infos.len());
            state.add_erc20_on_eos_redeem_infos(redeem_infos)
        })
}

pub fn maybe_filter_out_already_processed_tx_ids_from_state<D>(
    state: EosState<D>
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    info!("✔ Filtering out already processed tx IDs...");
    state.erc20_on_eos_redeem_infos.filter_out_already_processed_txs(&state.processed_tx_ids)
        .and_then(|filtered| state.add_erc20_on_eos_redeem_infos(filtered))
}
