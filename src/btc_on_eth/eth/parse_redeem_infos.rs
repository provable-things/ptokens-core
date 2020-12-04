use crate::{
    chains::eth::{eth_database_utils::get_eth_canon_block_from_db, eth_state::EthState},
    traits::DatabaseInterface,
    types::Result,
};

pub fn maybe_parse_redeem_infos_and_add_to_state<D>(state: EthState<D>) -> Result<EthState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Maybe parsing redeem infos...");
    get_eth_canon_block_from_db(&state.db).and_then(|submission_material| {
        match submission_material.receipts.is_empty() {
            true => {
                info!("✔ No receipts in canon block ∴ no infos to parse!");
                Ok(state)
            },
            false => {
                info!(
                    "✔ Receipts in canon block #{}∴ parsing infos...",
                    submission_material.get_block_number()?
                );
                submission_material
                    .get_btc_on_eth_redeem_infos()
                    .and_then(|infos| state.add_btc_on_eth_redeem_infos(infos))
            },
        }
    })
}
