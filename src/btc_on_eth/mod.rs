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

pub use crate::{
    btc_on_eth::{
        btc::submit_btc_block::submit_btc_block_to_enclave,
        debug_functions::{
            block_reprocessors::{
                debug_reprocess_btc_block,
                debug_reprocess_btc_block_with_fee_accrual,
                debug_reprocess_eth_block,
                debug_reprocess_eth_block_with_fee_accrual,
            },
            debug_add_multiple_utxos,
            debug_clear_all_utxos,
            debug_consolidate_utxos,
            debug_get_all_db_keys,
            debug_get_all_utxos,
            debug_get_child_pays_for_parent_btc_tx,
            debug_get_fee_withdrawal_tx,
            debug_get_key_from_db,
            debug_get_signed_erc777_change_pnetwork_tx,
            debug_get_signed_erc777_proxy_change_pnetwork_by_proxy_tx,
            debug_get_signed_erc777_proxy_change_pnetwork_tx,
            debug_maybe_add_utxo_to_db,
            debug_mint_pbtc,
            debug_put_btc_on_eth_peg_in_basis_points_in_db,
            debug_put_btc_on_eth_peg_out_basis_points_in_db,
            debug_remove_utxo,
            debug_set_btc_fee,
            debug_set_eth_gas_price,
            debug_set_key_in_db_to_value,
        },
        eth::{
            add_erc777_contract_address::maybe_add_erc777_contract_address,
            initialize_eth_core::maybe_initialize_eth_enclave,
            submit_eth_block::submit_eth_block_to_enclave,
        },
        get_enclave_state::get_enclave_state,
        get_latest_block_numbers::get_latest_block_numbers,
    },
    chains::{
        btc::{
            btc_debug_functions::{debug_set_btc_account_nonce, debug_set_btc_utxo_nonce},
            core_initialization::initialize_btc_core::maybe_initialize_btc_core as maybe_initialize_btc_enclave,
        },
        eth::{
            core_initialization::reset_eth_chain::debug_reset_eth_chain,
            eth_debug_functions::{debug_set_eth_account_nonce, debug_set_eth_any_sender_nonce},
            eth_message_signer::{
                sign_ascii_msg_with_eth_key_with_no_prefix,
                sign_ascii_msg_with_eth_key_with_prefix,
                sign_hex_msg_with_eth_key_with_prefix,
            },
        },
    },
};

pub mod btc;
pub mod debug_functions;
pub mod eth;
pub mod get_enclave_state;
pub mod get_latest_block_numbers;

mod check_core_is_initialized;

pub(crate) mod test_utils;
pub(crate) mod utils;
