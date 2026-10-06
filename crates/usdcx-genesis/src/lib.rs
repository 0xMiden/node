//! The xUSDC genesis tool: builds the genesis xUSDC faucet and its distributor offline and writes
//! their `.mac` account files. Five commands, in launch order: `new-distributor`, `faucet`,
//! `prefund`, `record-nonces`, `upgrade-policy-manager`. See the crate README for usage and the
//! file schemas.

pub mod accounts;
pub mod config;
pub mod output;
