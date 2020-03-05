#![feature(try_trait)]
#![recursion_limit="128"] // NOTE: For the format! macro in block parsing.
#![cfg(feature="btc-on-eth")]

pub mod btc;
pub mod eth;
pub mod utils;
pub mod types;
pub mod base58;
pub mod errors;
pub mod traits;
pub mod constants;
pub mod test_utils;
pub mod utxo_manager;
pub mod crypto_utils;
pub mod database_utils;
pub mod debug_functions;
pub mod check_debug_mode;
pub mod get_enclave_state;
pub mod get_latest_block_numbers;
pub mod check_enclave_is_initialized;

#[macro_use] extern crate log;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate serde_derive;

pub use {
    traits::DatabaseInterface,
    errors::AppError as PbtcCoreError,
    get_enclave_state::get_enclave_state,
    get_latest_block_numbers::get_latest_block_numbers,
    types::{
        Bytes,
        Result as PbtcResult,
    },
    debug_functions::{
        debug_get_all_utxos,
        debug_get_key_from_db,
        debug_set_key_in_db_to_value,
    },
    eth::{
        submit_eth_block::submit_eth_block_to_enclave,
        initialize_eth::initialize_eth_enclave::maybe_initialize_eth_enclave,
    },
    btc::{
        submit_btc_block::submit_btc_block_to_enclave,
        initialize_btc::initialize_btc_enclave::maybe_initialize_btc_enclave,
    },
};
