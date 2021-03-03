//! # The `pEOS-on-ETH` pToken Core
//!
//! Here lies the functionality required for the cross-chain conversions between
//! native EOS tokens and ETH ERC777 pToken equivalents. This core consists of two
//! light clients that manage the state of the two chains, along with the creation
//! and signing of transactions related to each chain.
//!
//! __NOTE:__ All `debug_` prefixed functions can only be used if the core is
//! built with the `debug` feaure flag enabled in the `Cargo.toml`:
//!
//! ```no_compile
//! ptokens_core = { version = "4.5.0", features = ["debug"] }
//! ```

pub mod debug_functions;
pub mod eos;
pub mod eth;
pub mod get_enclave_state;
pub mod get_latest_block_numbers;

pub(crate) mod check_core_is_initialized;
pub(crate) mod constants;
pub(crate) mod test_utils;

pub use crate::{
    chains::{
        eos::{
            core_initialization::initialize_eos_core::maybe_initialize_eos_core_with_eos_account_without_symbol as maybe_initialize_eos_core,
            disable_protocol_feature::{disable_eos_protocol_feature, disable_protocol_feature},
            enable_protocol_feature::enable_eos_protocol_feature,
            eos_debug_functions::{
                debug_add_global_sequences_to_processed_list,
                debug_remove_global_sequences_from_processed_list,
            },
        },
        eth::eth_message_signer::{sign_ascii_msg_with_eth_key_with_no_prefix, sign_hex_msg_with_eth_key_with_prefix},
    },
    eos_on_eth::{
        debug_functions::{
            debug_add_eos_eth_token_dictionary_entry,
            debug_add_new_eos_schedule,
            debug_get_all_db_keys,
            debug_get_key_from_db,
            debug_remove_eos_eth_token_dictionary_entry,
            debug_reprocess_eos_block,
            debug_reprocess_eth_block,
            debug_set_key_in_db_to_value,
            debug_update_incremerkle,
        },
        eos::submit_eos_block::submit_eos_block_to_core,
        eth::{initialize_eth_core::maybe_initialize_eth_core, submit_eth_block::submit_eth_block_to_core},
        get_enclave_state::get_enclave_state,
        get_latest_block_numbers::get_latest_block_numbers,
    },
};
