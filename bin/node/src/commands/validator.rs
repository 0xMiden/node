use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use miden_node_utils::clap::GrpcOptions;
use miden_node_utils::grpc::UrlExt;
use miden_node_validator::{Validator, ValidatorSigner};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::SecretKey;
use miden_protocol::utils::Deserializable;
use url::Url;

use crate::commands::{
    ENV_DATA_DIRECTORY,
    ENV_ENABLE_OTEL,
    ENV_VALIDATOR_KEY,
    ENV_VALIDATOR_KMS_KEY_ID,
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
        grpc_options: GrpcOptions,

        /// Directory in which to store the validator's data.
        #[arg(long, env = ENV_DATA_DIRECTORY, value_name = "DIR")]
        data_directory: PathBuf,

        /// Insecure, hex-encoded validator secret key for development and testing purposes.
        ///
        /// If not provided, a predefined key is used.
        ///
        /// Cannot be used with `key.kms-id`.
        #[arg(
            long = "key.hex",
            env = ENV_VALIDATOR_KEY,
            value_name = "VALIDATOR_KEY",
            default_value = INSECURE_VALIDATOR_KEY_HEX,
            group = "key"
        )]
        validator_key: String,

        /// Key ID for the KMS key used by validator to sign blocks.
        ///
        /// Cannot be used with `key.hex`.
        #[arg(
            long = "key.kms-id",
            env = ENV_VALIDATOR_KMS_KEY_ID,
            value_name = "VALIDATOR_KMS_KEY_ID",
            group = "key"
        )]
        kms_key_id: Option<String>,
    },
}

impl ValidatorCommand {
    /// Runs the validator command.
    pub async fn handle(self) -> anyhow::Result<()> {
        let Self::Start {
            url,
            grpc_options,
            validator_key,
            data_directory,
            kms_key_id,
            ..
        } = self;

        let address =
            url.to_socket().context("Failed to extract socket address from validator URL")?;

        // Run validator with KMS key backend if key id provided.
        if let Some(kms_key_id) = kms_key_id {
            let signer = ValidatorSigner::new_kms(kms_key_id).await?;
            Self::serve(address, grpc_options, signer, data_directory).await
        } else {
            let signer = SecretKey::read_from_bytes(hex::decode(validator_key)?.as_ref())?;
            let signer = ValidatorSigner::new_local(signer);
            Self::serve(address, grpc_options, signer, data_directory).await
        }
    }

    /// Runs the validator component until failure.
    async fn serve(
        address: SocketAddr,
        grpc_options: GrpcOptions,
        signer: ValidatorSigner,
        data_directory: PathBuf,
    ) -> anyhow::Result<()> {
        Validator {
            address,
            grpc_options,
            signer,
            data_directory,
        }
        .serve()
        .await
        .context("failed while serving validator component")
    }

    pub fn is_open_telemetry_enabled(&self) -> bool {
        let Self::Start { enable_otel, .. } = self;
        *enable_otel
    }
}
