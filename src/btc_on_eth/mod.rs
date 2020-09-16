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

pub use get_enclave_state::get_enclave_state;
pub use debug_functions::{
    debug_mint_pbtc,
    debug_get_all_utxos,
    debug_get_all_db_keys,
    debug_get_key_from_db,
    debug_clear_all_utxos,
    debug_reprocess_btc_block,
    debug_reprocess_eth_block,
    debug_maybe_add_utxo_to_db,
    debug_set_key_in_db_to_value,
    debug_get_signed_erc777_change_pnetwork_tx,
    debug_get_signed_erc777_proxy_change_pnetwork_tx,
    debug_get_signed_erc777_proxy_change_pnetwork_by_proxy_tx,
};
pub use btc::submit_btc_block::submit_btc_block_to_enclave;
pub use eth::submit_eth_block::submit_eth_block_to_enclave;
pub use eth::initialize_eth::initialize_eth_enclave::{
    maybe_initialize_eth_enclave,
};
pub use btc::initialize_btc::initialize_btc_enclave::{
    maybe_initialize_btc_enclave,
};

pub mod btc;
pub mod eth;
pub mod debug_functions;
pub mod get_enclave_state;
pub mod get_latest_block_numbers;

mod database_utils;
mod check_core_is_initialized;

// TODO Fix the chains dependencies on these so they can be fully private!
pub(crate) mod utils;
pub(crate) mod constants;
