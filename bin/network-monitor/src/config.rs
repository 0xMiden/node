//! Network monitor configuration.
//!
//! This module contains the configuration structures and constants for the network monitor.
//! Configuration for the monitor.

use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey as ValidatorPublicKey;
use miden_protocol::utils::serde::Deserializable;
use url::Url;

// MONITOR CONFIGURATION CONSTANTS
// ================================================================================================

const DEFAULT_RPC_URL: &str = "http://0.0.0.0:57291";
const DEFAULT_PORT: u16 = 3000;
/// Amount of tokens, in base units, requested by each faucet check by default.
const DEFAULT_FAUCET_MINT_AMOUNT: u64 = 1_000;

/// Configuration for the monitor.
///
/// This struct contains the configuration for the monitor.
#[derive(Debug, Clone, Parser)]
pub struct MonitorConfig {
    /// The URL of the RPC service.
    #[arg(
        long = "rpc-url",
        env = "MIDEN_MONITOR_RPC_URL",
        default_value = DEFAULT_RPC_URL,
        help = "The URL of the RPC service"
    )]
    pub rpc_url: Url,

    /// The display name of the network (e.g., "Testnet", "Devnet").
    #[arg(
        long = "network-name",
        env = "MIDEN_MONITOR_NETWORK_NAME",
        default_value = "Localhost",
        help = "The display name of the network (e.g., Testnet, Devnet)"
    )]
    pub network_name: String,

    /// The URLs of the remote provers for status checking (comma-separated).
    #[arg(
        long = "remote-prover-urls",
        env = "MIDEN_MONITOR_REMOTE_PROVER_URLS",
        value_delimiter = ',',
        help = "The URLs of the remote provers for status checking (comma-separated)"
    )]
    pub remote_prover_urls: Vec<Url>,

    /// The URL of the faucet service for testing (optional).
    #[arg(
        long = "faucet-url",
        env = "MIDEN_MONITOR_FAUCET_URL",
        help = "The URL of the faucet service for testing (optional)"
    )]
    pub faucet_url: Option<Url>,

    /// The URL of the funding service (optional).
    #[arg(
        long = "funding-service-url",
        env = "MIDEN_MONITOR_FUNDING_SERVICE_URL",
        help = "The URL of the funding service (optional)"
    )]
    pub funding_service_url: Option<Url>,

    /// Timeout for a funding request to the funding service.
    #[arg(
        long = "funding-request-timeout",
        env = "MIDEN_MONITOR_FUNDING_REQUEST_TIMEOUT",
        default_value = "2m",
        value_parser = humantime::parse_duration,
        help = "Timeout for a funding request to the funding service"
    )]
    pub funding_request_timeout: Duration,

    /// The interval at which to test the remote provers services.
    #[arg(
        long = "remote-prover-test-interval",
        env = "MIDEN_MONITOR_REMOTE_PROVER_TEST_INTERVAL",
        default_value = "2m",
        value_parser = humantime::parse_duration,
        help = "The interval at which to test the remote provers services"
    )]
    pub remote_prover_test_interval: Duration,

    /// The interval at which to test the faucet services.
    #[arg(
        long = "faucet-test-interval",
        env = "MIDEN_MONITOR_FAUCET_TEST_INTERVAL",
        default_value = "2m",
        value_parser = humantime::parse_duration,
        help = "The interval at which to test the faucet services"
    )]
    pub faucet_test_interval: Duration,

    /// Amount of tokens, in base units, that each faucet check requests.
    #[arg(
        long = "faucet-mint-amount",
        env = "MIDEN_MONITOR_FAUCET_MINT_AMOUNT",
        default_value_t = DEFAULT_FAUCET_MINT_AMOUNT,
        value_parser = clap::value_parser!(u64).range(1..),
        help = "Amount of tokens, in base units, that each faucet check requests. It must not \
                exceed the faucet's maximum claimable amount"
    )]
    pub faucet_mint_amount: u64,

    /// The interval at which to check the status of the services.
    #[arg(
        long = "status-check-interval",
        env = "MIDEN_MONITOR_STATUS_CHECK_INTERVAL",
        default_value = "3s",
        value_parser = humantime::parse_duration,
        help = "The interval at which to check the status of the services"
    )]
    pub status_check_interval: Duration,

    /// The port of the monitor.
    #[arg(
        long = "port",
        short = 'p',
        env = "MIDEN_MONITOR_PORT",
        default_value_t = DEFAULT_PORT,
        help = "The port of the monitor"
    )]
    pub port: u16,

    /// Whether to disable the network transaction service checks (enabled by default). The network
    /// transaction service is a network account with a counter deployed at startup and incremented
    /// by sending a transaction to it.
    #[arg(
        long = "disable-ntx-service",
        env = "MIDEN_MONITOR_DISABLE_NTX_SERVICE",
        action = clap::ArgAction::SetTrue,
        default_value_t = false,
        help = "Whether to disable the network transaction service checks (enabled by default). The
        network transaction service is a network account with a counter deployed at startup and
        incremented by sending a transaction to it."
    )]
    pub disable_ntx_service: bool,

    /// Hex-encoded validator signing public keys trusted to attest the transaction encryption key.
    ///
    /// Accepts repeated arguments or a comma-separated list.
    /// Required when network transaction checks are enabled.
    #[arg(
        long = "validator-signing-public-key",
        env = "MIDEN_MONITOR_VALIDATOR_SIGNING_PUBLIC_KEY",
        value_delimiter = ',',
        value_name = "HEX"
    )]
    pub validator_signing_public_keys: Vec<String>,

    /// The interval at which to send the increment counter transaction.
    #[arg(
        long = "counter-increment-interval",
        env = "MIDEN_MONITOR_COUNTER_INCREMENT_INTERVAL",
        default_value = "30s",
        value_parser = humantime::parse_duration,
        help = "The interval at which to send the increment counter transaction"
    )]
    pub counter_increment_interval: Duration,

    /// Maximum time to wait for the counter update after submitting a transaction.
    #[arg(
        long = "counter-latency-timeout",
        env = "MIDEN_MONITOR_COUNTER_LATENCY_TIMEOUT",
        default_value = "2m",
        value_parser = humantime::parse_duration,
        help = "Maximum time to wait for a counter update after submitting a transaction"
    )]
    pub counter_latency_timeout: Duration,

    /// Maximum allowed gap between the expected and observed counter values before the Network
    /// Transactions card is flipped to unhealthy. A small backlog while transactions are in flight
    /// is expected; this threshold guards against the network silently dropping notes.
    #[arg(
        long = "counter-pending-unhealthy-threshold",
        env = "MIDEN_MONITOR_COUNTER_PENDING_UNHEALTHY_THRESHOLD",
        default_value_t = 5,
        help = "Mark the counter card unhealthy when the gap between expected and observed values \
                stays above this threshold for several consecutive polls"
    )]
    pub counter_pending_unhealthy_threshold: u64,

    /// The timeout for the outgoing requests.
    #[arg(
        long = "request-timeout",
        env = "MIDEN_MONITOR_REQUEST_TIMEOUT",
        default_value = "10s",
        value_parser = humantime::parse_duration,
        help = "The timeout for the outgoing requests"
    )]
    pub request_timeout: Duration,

    /// The URL of the explorer service.
    #[arg(
        long = "explorer-url",
        env = "MIDEN_MONITOR_EXPLORER_URL",
        help = "The URL of the explorer service"
    )]
    pub explorer_url: Option<Url>,

    /// The URL of the note transport service.
    #[arg(
        long = "note-transport-url",
        env = "MIDEN_MONITOR_NOTE_TRANSPORT_URL",
        help = "The URL of the note transport service"
    )]
    pub note_transport_url: Option<Url>,

    /// Named validators, as repeated arguments or a comma-separated list of NAME=URL pairs.
    #[arg(
        long = "validators",
        env = "MIDEN_MONITOR_VALIDATORS",
        value_delimiter = ',',
        value_name = "NAME=URL",
        conflicts_with = "validator_url"
    )]
    pub validators: Vec<ValidatorConfig>,

    /// The URL of a single validator service. Use `--validators` to provide display names.
    #[arg(
        long = "validator-url",
        env = "MIDEN_MONITOR_VALIDATOR_URL",
        help = "The URL of the validator service"
    )]
    pub validator_url: Option<Url>,

    /// The base URL of the agglayer-monitor API.
    ///
    /// The monitor reads the Agglayer bridge status from `GET /v1/status` on this URL.
    #[arg(
        long = "agglayer-monitor-url",
        env = "MIDEN_MONITOR_AGGLAYER_MONITOR_URL",
        help = "The base URL of the agglayer-monitor API"
    )]
    pub agglayer_monitor_url: Option<Url>,

    /// Maximum time without a chain tip update before marking RPC as unhealthy.
    ///
    /// If the chain tip does not increment within this duration, the RPC service will be
    /// marked as unhealthy with a stale chain tip error.
    #[arg(
        long = "stale-chain-tip-threshold",
        env = "MIDEN_MONITOR_STALE_CHAIN_TIP_THRESHOLD",
        default_value = "1m",
        value_parser = humantime::parse_duration,
        help = "Maximum time without a chain tip update before marking RPC as unhealthy"
    )]
    pub stale_chain_tip_threshold: Duration,
}

/// A validator endpoint identified by an operator-provided display name.
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    pub name: String,
    pub url: Url,
}

impl FromStr for ValidatorConfig {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (name, url) = value.split_once('=').context("expected a NAME=URL pair")?;
        let name = name.trim();
        anyhow::ensure!(!name.is_empty(), "validator name must not be empty");
        let url = Url::parse(url).context("invalid validator URL")?;
        anyhow::ensure!(
            matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
            "validator URL must use http or https and include a host"
        );
        Ok(Self { name: name.to_string(), url })
    }
}

impl MonitorConfig {
    /// Decodes the validator signing keys required by transaction submission checks.
    pub fn trusted_validator_signing_keys(&self) -> Result<Vec<ValidatorPublicKey>> {
        anyhow::ensure!(
            !self.validator_signing_public_keys.is_empty(),
            "--validator-signing-public-key is required when network transaction checks are enabled"
        );
        self.validator_signing_public_keys
            .iter()
            .map(|encoded| {
                let bytes = hex::decode(encoded)
                    .context("validator signing public key must be hex encoded")?;
                ValidatorPublicKey::read_from_bytes(&bytes)
                    .context("validator signing public key must be a valid K256 public key")
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SigningKey;
    use miden_protocol::utils::serde::Serializable;

    use super::*;

    #[test]
    fn accepts_named_validators_as_a_list_or_repeated_arguments() {
        for args in [
            vec!["--validators", "Miden=https://miden.example,Gateway=https://gateway.example"],
            vec![
                "--validators",
                "Miden=https://miden.example",
                "--validators",
                "Gateway=https://gateway.example",
            ],
        ] {
            let config =
                MonitorConfig::try_parse_from(["miden-network-monitor"].into_iter().chain(args))
                    .unwrap();
            assert_eq!(config.validators.len(), 2);
            assert_eq!(config.validators[0].name, "Miden");
            assert_eq!(config.validators[0].url.as_str(), "https://miden.example/");
            assert_eq!(config.validators[1].name, "Gateway");
            assert_eq!(config.validators[1].url.as_str(), "https://gateway.example/");
        }
    }

    #[test]
    fn rejects_invalid_named_validators() {
        for value in [
            "https://validator.example",
            "=https://validator.example",
            "  =https://validator.example",
            "Miden=",
            "Miden=invalid",
            "Miden=file:///tmp/validator",
        ] {
            assert!(MonitorConfig::try_parse_from(["monitor", "--validators", value]).is_err());
        }
    }

    #[test]
    fn legacy_validator_configuration_remains_supported() {
        let config = MonitorConfig::try_parse_from([
            "monitor",
            "--validator-url",
            "https://validator.example",
        ])
        .unwrap();
        assert_eq!(config.validator_url.unwrap().as_str(), "https://validator.example/");
        assert!(config.validators.is_empty());
        assert!(
            MonitorConfig::try_parse_from([
                "monitor",
                "--validator-url",
                "https://validator.example",
                "--validators",
                "Miden=https://miden.example",
            ])
            .is_err()
        );
    }

    #[test]
    fn accepts_all_configured_validator_keys() {
        let keys =
            [1, 3, 4].map(|seed| SigningKey::read_from_bytes(&[seed; 32]).unwrap().public_key());
        let encoded = keys.each_ref().map(|key| hex::encode(key.to_bytes()));
        for arguments in [
            vec!["--validator-signing-public-key".to_owned(), encoded.join(",")],
            encoded
                .iter()
                .flat_map(|key| ["--validator-signing-public-key".to_owned(), key.clone()])
                .collect(),
        ] {
            let config = MonitorConfig::parse_from(
                ["miden-network-monitor".to_owned()].into_iter().chain(arguments),
            );
            assert_eq!(config.trusted_validator_signing_keys().unwrap(), keys);
        }
    }

    #[test]
    fn rejects_missing_or_invalid_validator_keys() {
        let missing = MonitorConfig::parse_from(["miden-network-monitor"]);
        assert!(missing.trusted_validator_signing_keys().is_err());

        for key in ["not-hex", "00"] {
            let config = MonitorConfig::parse_from([
                "miden-network-monitor",
                "--validator-signing-public-key",
                key,
            ]);
            assert!(config.trusted_validator_signing_keys().is_err());
        }
    }
}
