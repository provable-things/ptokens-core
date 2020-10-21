use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::eth::{
        eth_state::EthState,
        eth_constants::{
            BTC_ON_ETH_REDEEM_EVENT_TOPIC,
            ERC20_ON_EOS_PEG_IN_EVENT_TOPIC,
        },
        eth_database_utils::{
            get_erc777_contract_address_from_db,
            get_erc20_on_eos_smart_contract_address_from_db,
        },
    },
};

pub fn filter_receipts_for_btc_on_eth_redeem_events_in_state<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Filtering receipts for those containing `btc-on-eth` redeem events...");
    state
        .get_eth_submission_material()?
        .filter_for_receipts_containing_log_with_address_and_topics(
            &get_erc777_contract_address_from_db(&state.db)?,
            &BTC_ON_ETH_REDEEM_EVENT_TOPIC.to_vec(),
        )
        .and_then(|filtered_block_and_receipts| state.update_eth_submission_material(filtered_block_and_receipts))
}

pub fn filter_receipts_for_erc20_on_eos_peg_in_events_in_state<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Filtering receipts for those containing `erc20-on-eos` peg in events...");
    state
        .get_eth_submission_material()?
        .filter_for_receipts_containing_log_with_address_and_topics(
            &get_erc20_on_eos_smart_contract_address_from_db(&state.db)?,
            &ERC20_ON_EOS_PEG_IN_EVENT_TOPIC.to_vec(),
        )
        .and_then(|filtered|
            filtered.filter_receipts_containing_supported_erc20_peg_ins(state.get_eos_erc20_dictionary()?)
        )
        .and_then(|filtered_submission_material| state.update_eth_submission_material(filtered_submission_material))
}
