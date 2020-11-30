use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::{
        btc_state::BtcState,
        btc_block::BtcBlockInDbFormat,
    },
};

pub fn create_btc_block_in_db_format_and_put_in_state<D: DatabaseInterface>(state: BtcState<D>) -> Result<BtcState<D>> {
    info!("✔ Creating DB formatted BTC block from block in state...");
    let block = state.get_btc_block_and_id()?.clone();
    let eth_minting_params = state.btc_on_eth_minting_params.clone();
    let eos_minting_params = state.btc_on_eos_minting_params.clone();
    state.add_btc_block_in_db_format(
        BtcBlockInDbFormat::new(
            block.height,
            block.id,
            vec![],
            Some(eos_minting_params),
            Some(eth_minting_params),
            block.block.header.prev_blockhash,
        )
    )
}
