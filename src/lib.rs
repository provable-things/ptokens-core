//! # The __`pToken`__ Core
//!
//! Herein lies the functionality required for the cross-chain conversions
//! between various blockchains allowing for decentalized swaps between a native
//! asset and a host chain's pTokenized version of that asset.
//!
//! __Note:__ When compiling the core, you may provide an optional environment
//! variable __`DB_KEY_PREFIX`__, which when used will prefix all database keys
//! with the provided argument. Via this, database key clashes can be avoided
//! if running multiple instances on one machine.

#![allow(clippy::match_bool)]
#![allow(clippy::too_many_arguments)]

pub use types::{
    Bytes,
    Result
};
pub use errors::AppError;
pub use traits::DatabaseInterface;

pub mod types;
pub mod traits;
pub mod chains;
pub mod errors;
pub mod btc_on_eth;
pub mod btc_on_eos;
pub mod erc20_on_eos;

mod utils;
mod base58;
mod constants;
mod crypto_utils;
mod database_utils;
mod check_debug_mode;
mod debug_database_utils;

#[cfg(test)]
mod test_utils;
#[cfg(test)]
extern crate simple_logger;

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate quick_error;
