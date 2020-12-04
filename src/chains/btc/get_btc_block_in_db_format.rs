use crate::{
    chains::btc::{btc_block::BtcBlockInDbFormat, btc_state::BtcState},
    traits::DatabaseInterface,
    types::Result,
};

pub fn create_btc_block_in_db_format_and_put_in_state<D: DatabaseInterface>(state: BtcState<D>) -> Result<BtcState<D>> {
    info!("✔ Creating DB formatted BTC block from block in state...");
    let block = state.get_btc_block_and_id()?.clone();
    let eth_minting_params = state.btc_on_eth_minting_params.clone();
    let eos_minting_params = state.btc_on_eos_minting_params.clone();
    let extra_data = vec![];
    state.add_btc_block_in_db_format(BtcBlockInDbFormat::new(
        block.height,
        block.id,
        extra_data,
        Some(eos_minting_params),
        Some(eth_minting_params),
        block.block.header.prev_blockhash,
    ))
}
