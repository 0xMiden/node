//! The genesis tool: builds the genesis xUSDC faucet and its distributor offline, then builds the
//! genesis block that commits to them. Five commands, in launch order: `new-distributor`, `faucet`,
//! `prefund`, `record-nonces`, `build`. See the crate README for usage and the file schemas.

pub mod accounts;
pub mod build;
pub mod cli;
pub mod config;
pub mod output;
