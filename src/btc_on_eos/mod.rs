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

pub use crate::{
    btc_on_eos::{
        btc::submit_btc_block::submit_btc_block_to_core,
        debug_functions::{
            debug_add_multiple_utxos,
            debug_add_new_eos_schedule,
            debug_clear_all_utxos,
            debug_consolidate_utxos,
            debug_get_all_db_keys,
            debug_get_all_utxos,
            debug_get_child_pays_for_parent_btc_tx,
            debug_get_key_from_db,
            debug_get_processed_actions_list,
            debug_remove_utxo,
            debug_reprocess_btc_block_for_stale_eos_tx,
            debug_reprocess_eos_block,
            debug_set_key_in_db_to_value,
            debug_update_incremerkle,
        },
        eos::submit_eos_block::submit_eos_block_to_core,
        get_enclave_state::get_enclave_state,
        get_latest_block_numbers::get_latest_block_numbers,
    },
    chains::{
        btc::core_initialization::initialize_btc_core::maybe_initialize_btc_core,
        eos::{
            core_initialization::initialize_eos_core::maybe_initialize_eos_core_with_eos_account_and_symbol as maybe_initialize_eos_core,
            disable_protocol_feature::disable_eos_protocol_feature,
            enable_protocol_feature::enable_eos_protocol_feature,
            eos_debug_functions::{
                debug_add_global_sequences_to_processed_list,
                debug_remove_global_sequences_from_processed_list,
            },
        },
    },
};

pub mod btc;
pub mod debug_functions;
pub mod eos;
pub mod get_enclave_state;
pub mod get_latest_block_numbers;

pub(crate) mod check_core_is_initialized;
pub(crate) mod utils;
