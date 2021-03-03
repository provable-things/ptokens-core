use crate::{
    chains::eth::{
        eth_constants::BTC_ON_ETH_REDEEM_EVENT_TOPIC,
        eth_database_utils::get_erc777_contract_address_from_db,
        eth_state::EthState,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn filter_receipts_for_btc_on_eth_redeem_events_in_state<D: DatabaseInterface>(
    state: EthState<D>,
) -> Result<EthState<D>> {
    info!("✔ Filtering receipts for those containing `btc-on-eth` redeem events...");
    state
        .get_eth_submission_material()?
        .get_receipts_containing_log_from_address_and_with_topics(
            &get_erc777_contract_address_from_db(&state.db)?,
            &BTC_ON_ETH_REDEEM_EVENT_TOPIC.to_vec(),
        )
        .and_then(|filtered_block_and_receipts| state.update_eth_submission_material(filtered_block_and_receipts))
}
