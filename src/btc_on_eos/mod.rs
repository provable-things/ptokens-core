//! # The `pBTC-on-EOS` pToken Core
//!
//! Here lies the functionality required for the cross-chain conversions between
//! native bitcoins and the `pBTC` pToken on the host EOS blockchain. This core
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
pub use btc::submit_btc_block::submit_btc_block_to_core;
pub use eos::submit_eos_block::submit_eos_block_to_core;
pub use get_latest_block_numbers::get_latest_block_numbers;
pub use eos::enable_protocol_feature::enable_eos_protocol_feature;
pub use eos::disable_protocol_feature::disable_eos_protocol_feature;
pub use debug_functions::{
    debug_get_all_utxos,
    debug_get_all_db_keys,
    debug_clear_all_utxos,
    debug_get_key_from_db,
    debug_update_incremerkle,
    debug_add_new_eos_schedule,
    debug_reprocess_eos_block,
    debug_set_key_in_db_to_value,
    debug_reprocess_btc_block_for_stale_eos_tx,
};
pub use eos::initialize_eos_core::maybe_initialize_eos_core;
pub use btc::initialize_btc::initialize_btc_core::maybe_initialize_btc_core;

pub mod eos;
pub mod btc;
pub mod debug_functions;
pub mod get_enclave_state;
pub mod get_latest_block_numbers;

mod utils;
mod crypto_utils;
mod check_core_is_initialized;
