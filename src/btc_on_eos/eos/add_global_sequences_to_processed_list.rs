use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::eos::{
        eos_state::EosState,
        eos_database_utils::put_processed_tx_ids_in_db,
        eos_types::{
            RedeemParams,
            ProcessedTxIds,
            GlobalSequences,
        },
    },
};

fn get_global_sequences_from_redeem_params(
    redeem_params: &[RedeemParams]
) -> GlobalSequences {
    redeem_params
        .iter()
        .map(|params| params.global_sequence)
        .collect::<GlobalSequences>()
}

fn add_tx_ids_to_processed_tx_ids<D>(
    db: &D,
    redeem_params: &[RedeemParams],
    processed_tx_ids: &ProcessedTxIds,
) -> Result<()>
    where D: DatabaseInterface
{
    put_processed_tx_ids_in_db(
        db,
        &processed_tx_ids
            .clone()
            .add_multi(
                &mut get_global_sequences_from_redeem_params(redeem_params)
            )?
    )
}

pub fn maybe_add_global_sequences_to_processed_list<D>(
    state: EosState<D>
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    match &state.redeem_params.len() {
        0 => {
            info!("✔ No `global_sequences` to add to processed tx list!");
            Ok(state)
        }
        _ => {
            info!("✔ Adding `global_sequences` to processed tx list...");
            add_tx_ids_to_processed_tx_ids(
                &state.db,
                &state.redeem_params,
                &state.processed_tx_ids,
            )
                .map(|_| state)
        }
    }
}
