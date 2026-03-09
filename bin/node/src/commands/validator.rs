use anyhow::Context;
use miden_node_utils::clap::GrpcOptionsInternal;
use miden_node_utils::grpc::UrlExt;
use miden_node_validator::Validator;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_protocol::utils::Deserializable;
use url::Url;

use crate::commands::{
    ENV_ENABLE_OTEL,
    ENV_VALIDATOR_INSECURE_SECRET_KEY,
    ENV_VALIDATOR_URL,
    INSECURE_VALIDATOR_KEY_HEX,
};

#[derive(clap::Subcommand)]
pub enum ValidatorCommand {
    /// Starts the validator component.
    Start {
        /// Url at which to serve the gRPC API.
        #[arg(env = ENV_VALIDATOR_URL)]
        url: Url,

        /// Enables the exporting of traces for OpenTelemetry.
        ///
        /// This can be further configured using environment variables as defined in the official
        /// OpenTelemetry documentation. See our operator manual for further details.
        #[arg(long = "enable-otel", default_value_t = true, env = ENV_ENABLE_OTEL, value_name = "BOOL")]
        enable_otel: bool,

        #[command(flatten)]
        grpc_options: GrpcOptionsInternal,

        /// Insecure, hex-encoded validator secret key for development and testing purposes.
        ///
        /// If not provided, a predefined key is used.
        #[arg(long = "insecure.secret-key", env = ENV_VALIDATOR_INSECURE_SECRET_KEY, value_name = "INSECURE_SECRET_KEY", default_value = INSECURE_VALIDATOR_KEY_HEX)]
        insecure_secret_key: String,
    },
}

impl ValidatorCommand {
    pub async fn handle(self) -> anyhow::Result<()> {
        let Self::Start {
            url, grpc_options, insecure_secret_key, ..
        } = self;

        let address =
            url.to_socket().context("Failed to extract socket address from validator URL")?;

        let signer = SecretKey::read_from_bytes(hex::decode(insecure_secret_key)?.as_ref())?;

        Validator { address, grpc_options, signer }
            .serve()
            .await
            .context("failed while serving validator component")
    }

    pub fn is_open_telemetry_enabled(&self) -> bool {
        let Self::Start { enable_otel, .. } = self;
        *enable_otel
    }
}
