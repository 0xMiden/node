use std::path::Path;

use figment::Figment;
use figment::providers::{Format, Toml};
use serde::Deserialize;

pub const DEFAULT_NODE_RPC_PORT: u16 = 57291;
pub const DEFAULT_BLOCK_PRODUCER_PORT: u16 = 48046;
pub const DEFAULT_STORE_PORT: u16 = 28943;
pub const DEFAULT_FAUCET_SERVER_PORT: u16 = 8080;

/// Loads the user configuration.
///
/// This function will look for the configuration file at the provided path. If the path is
/// relative, searches in parent directories all the way to the root as well.
///
/// The above configuration options are indented to support easy of packaging and deployment.
#[expect(clippy::result_large_err, reason = "This error crashes the node")]
pub fn load_config<T: for<'a> Deserialize<'a>>(
    config_file: impl AsRef<Path>,
) -> figment::Result<T> {
    Figment::from(Toml::file(config_file.as_ref())).extract()
}
