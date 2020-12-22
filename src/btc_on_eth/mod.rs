//! # The `pBTC-on-ETH` pToken Core
//!
//! Here lies the functionality required for the cross-chain conversions between
//! native bitcoins and the `pBTC` pToken on the host ETH blockchain. This core
//! consists of two light clients that manage the state of the two chains, along
//! with the creation and signing of transactions related to each chain.
//!
//! __NOTE:__ All `debug_` prefixed functions can only be used if the core is
//! built with the `debug` feaure flag enabled in the `Cargo.toml`:
//!
//! ```no_compile
//! ptokens_core = { version = "1.0.0", features = ["debug"] }
//! ```

pub use crate::btc_on_eth::{
    btc::{initialize_btc_enclave::maybe_initialize_btc_enclave, submit_btc_block::submit_btc_block_to_enclave},
    debug_functions::{
        debug_add_multiple_utxos,
        debug_clear_all_utxos,
        debug_consolidate_utxos,
        debug_get_all_db_keys,
        debug_get_all_utxos,
        debug_get_child_pays_for_parent_btc_tx,
        debug_get_key_from_db,
        debug_get_signed_erc777_change_pnetwork_tx,
        debug_get_signed_erc777_proxy_change_pnetwork_by_proxy_tx,
        debug_get_signed_erc777_proxy_change_pnetwork_tx,
        debug_maybe_add_utxo_to_db,
        debug_mint_pbtc,
        debug_remove_utxo,
        debug_reprocess_btc_block,
        debug_reprocess_eth_block,
        debug_set_key_in_db_to_value,
    },
    eth::{initialize_eth_core::maybe_initialize_eth_enclave, submit_eth_block::submit_eth_block_to_enclave},
    get_enclave_state::get_enclave_state,
    get_latest_block_numbers::get_latest_block_numbers,
};

pub mod btc;
pub mod debug_functions;
pub mod eth;
pub mod get_enclave_state;
pub mod get_latest_block_numbers;

mod check_core_is_initialized;

pub(crate) mod utils;
