use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc::{
        btc_state::BtcState,
        btc_database_utils::{
            put_btc_address_in_db,
            get_btc_private_key_from_db,
        },
    },
};

pub fn generate_and_store_btc_address<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    get_btc_private_key_from_db(&state.db)
        .and_then(|btc_private_key|
            put_btc_address_in_db(
                &state.db,
                &btc_private_key.to_p2pkh_btc_address()
            )
        )
        .map(|_| state)
}
