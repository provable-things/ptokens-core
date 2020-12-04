use crate::{
    btc_on_eos::eos::redeem_info::BtcOnEosRedeemInfos,
    chains::eos::{eos_database_utils::put_processed_tx_ids_in_db, eos_state::EosState, eos_types::ProcessedTxIds},
    traits::DatabaseInterface,
    types::Result,
};

pub fn add_tx_ids_to_processed_tx_ids<D>(
    db: &D,
    redeem_infos: &BtcOnEosRedeemInfos,
    processed_tx_ids: &ProcessedTxIds,
) -> Result<()>
where
    D: DatabaseInterface,
{
    put_processed_tx_ids_in_db(
        db,
        &processed_tx_ids
            .clone()
            .add_multi(&mut redeem_infos.get_global_sequences())?,
    )
}

pub fn maybe_add_global_sequences_to_processed_list_and_return_state<D>(state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    let global_sequences = state.get_global_sequences_from_redeem_info();
    match global_sequences.len() {
        0 => {
            info!("✔ No `global_sequences` to add to processed tx list!");
            Ok(state)
        },
        _ => {
            info!("✔ Adding `global_sequences` to processed tx list...");
            add_tx_ids_to_processed_tx_ids(&state.db, &state.btc_on_eos_redeem_infos, &state.processed_tx_ids)
                .and(Ok(state))
        },
    }
}
