use crate::{
    chains::eth::{eth_constants::EOS_ON_ETH_ETH_TX_INFO_EVENT_TOPIC, eth_state::EthState},
    traits::DatabaseInterface,
    types::Result,
};

pub fn filter_receipts_for_eos_on_eth_eth_tx_info_in_state<D: DatabaseInterface>(
    state: EthState<D>,
) -> Result<EthState<D>> {
    info!("✔ Filtering receipts for those containing `eos-on-eth` tx info...");
    state
        .get_eth_submission_material()?
        .get_receipts_containing_log_from_addresses_and_with_topics(
            &state.get_eos_eth_token_dictionary()?.to_eth_addresses(),
            &EOS_ON_ETH_ETH_TX_INFO_EVENT_TOPIC.to_vec(),
        )
        .and_then(|filtered_submission_material| state.update_eth_submission_material(filtered_submission_material))
}
