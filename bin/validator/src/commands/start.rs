use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Arc;

use anyhow::Context;
use miden_node_utils::clap::GrpcOptions;
use miden_node_utils::shutdown::CancellationToken;
use miden_node_utils::tasks::Tasks;
use miden_validator::{
    DataDirectory,
    GoldenOperatorKey,
    PrivateRecordSealer,
    TransactionInputDecrypter,
    ValidatorAdminServer,
    ValidatorServer,
    ValidatorSigner,
};

pub(crate) struct ValidatorKeys {
    pub(crate) signer: ValidatorSigner,
    pub(crate) decrypter: Arc<dyn TransactionInputDecrypter>,
    pub(crate) operator_key: GoldenOperatorKey,
}

/// Database location, connection pool size, and proving input retention for startup.
pub(crate) struct ValidatorDatabaseOptions {
    pub(crate) data_directory: DataDirectory,
    pub(crate) connection_pool_size: NonZeroUsize,
    pub(crate) proving_input_retention_blocks: NonZeroU32,
}

// Starts the validator component.
pub async fn start(
    address: SocketAddr,
    admin_address: Option<SocketAddr>,
    grpc_options: GrpcOptions,
    keys: ValidatorKeys,
    database_options: ValidatorDatabaseOptions,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let db = miden_validator::db::load_with_retention(
        database_options.data_directory.database_path(),
        database_options.connection_pool_size,
        database_options.proving_input_retention_blocks,
    )
    .await
    .context("failed to initialize validator database")?;
    let private_record_sealer = PrivateRecordSealer::from_operator_key(&keys.operator_key);
    let public_server = ValidatorServer {
        address,
        grpc_options,
        signer: keys.signer,
        decrypter: keys.decrypter,
        private_record_sealer,
        db,
        signing_lock: Arc::default(),
    };
    let admin_server = admin_address
        .map(|address| ValidatorAdminServer::new(address, keys.operator_key, &public_server));

    let mut tasks = Tasks::new();
    tasks.spawn("validator public API", public_server.serve(shutdown.clone()));
    if let Some(admin_server) = admin_server {
        tasks.spawn("validator admin API", admin_server.serve(shutdown.clone()));
    }

    tasks
        .join_next_or_cancelled(shutdown)
        .await
        .context("failed while serving validator component")
}
