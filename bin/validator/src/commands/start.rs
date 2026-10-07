use std::net::SocketAddr;
use std::num::NonZeroUsize;
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

// Starts the validator component.
pub async fn start(
    address: SocketAddr,
    admin_address: Option<SocketAddr>,
    grpc_options: GrpcOptions,
    keys: ValidatorKeys,
    data_directory: DataDirectory,
    sqlite_connection_pool_size: NonZeroUsize,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    // The pool is opened once here and shared: the public API owns the sole writer, and both
    // servers read through cloned read handles.
    let db = miden_validator::db::load_with_pool_size(
        data_directory.database_path(),
        sqlite_connection_pool_size,
    )
    .await
    .context("failed to initialize validator database")?;
    let reader = db.reader();
    let private_record_sealer = PrivateRecordSealer::from_operator_key(&keys.operator_key);
    let public_server = ValidatorServer {
        address,
        grpc_options,
        signer: keys.signer,
        decrypter: keys.decrypter,
        private_record_sealer,
        data_directory,
        db,
    };

    let mut tasks = Tasks::new();
    tasks.spawn("validator public API", public_server.serve(shutdown.clone()));
    if let Some(address) = admin_address {
        let admin_server = ValidatorAdminServer {
            address,
            operator_key: keys.operator_key,
            reader,
        };
        tasks.spawn("validator admin API", admin_server.serve(shutdown.clone()));
    }

    tasks
        .join_next_or_cancelled(shutdown)
        .await
        .context("failed while serving validator component")
}
