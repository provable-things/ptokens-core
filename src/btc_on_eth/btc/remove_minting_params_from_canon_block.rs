use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eth::btc::{
        btc_state::BtcState,
        btc_types::BtcBlockInDbFormat,
        btc_database_utils::{
            put_btc_canon_block_in_db,
            get_btc_canon_block_from_db,
        },
    },
};

fn remove_minting_params_from_canon_block<D>(
    db: &D
) -> Result<()>
    where D: DatabaseInterface
{
    get_btc_canon_block_from_db(db)
        .and_then(|canon_block|
            BtcBlockInDbFormat::new(
                canon_block.height,
                canon_block.id,
                vec![],
                canon_block.block,
                canon_block.extra_data,
            )
        )
        .and_then(|canon_block_with_no_minting_params|
             put_btc_canon_block_in_db(db, &canon_block_with_no_minting_params)
         )
}

pub fn remove_minting_params_from_canon_block_and_return_state<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Removing minting params from canon block...");
    remove_minting_params_from_canon_block(&state.db)
        .map(|_| state)
}
