use crate::{
    chains::{
        btc::{btc_state::BtcState, core_initialization::check_btc_core_is_initialized::check_btc_core_is_initialized},
        eos::{core_initialization::check_eos_core_is_initialized::check_eos_core_is_initialized, eos_state::EosState},
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn check_core_is_initialized<D: DatabaseInterface>(db: &D) -> Result<()> {
    check_btc_core_is_initialized(db).and_then(|_| check_eos_core_is_initialized(db))
}

pub fn check_core_is_initialized_and_return_eos_state<D: DatabaseInterface>(state: EosState<D>) -> Result<EosState<D>> {
    check_core_is_initialized(&state.db).and(Ok(state))
}

pub fn check_core_is_initialized_and_return_btc_state<D: DatabaseInterface>(state: BtcState<D>) -> Result<BtcState<D>> {
    check_core_is_initialized(&state.db).and(Ok(state))
}
