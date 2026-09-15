use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use miden_node_tracing::{OpenTelemetry, info};
use miden_node_utils::clap::GrpcOptions;
use miden_node_utils::shutdown::run_with_shutdown;
use miden_note_transport::server::{Config, Server};
use miden_note_transport::{COMPONENT, LOG_TARGET, db};

#[derive(Parser)]
#[command(version, about = "Miden note transport service")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Creates a new database and applies the schema.
    Bootstrap(DatabaseArgs),
    /// Applies pending migrations to an existing database.
    Migrate(DatabaseArgs),
    /// Serves gRPC and gRPC-Web requests.
    Start(StartArgs),
    /// Deletes one bounded batch of expired notes.
    Cleanup(CleanupArgs),
}

#[derive(Args)]
struct DatabaseArgs {
    /// Path to the SQLite database file.
    #[arg(long, env = "MIDEN_NOTE_TRANSPORT_DATABASE", value_name = "FILE")]
    database: PathBuf,
}

#[derive(Args)]
struct StartArgs {
    #[command(flatten)]
    database: DatabaseArgs,
    #[command(flatten)]
    grpc: GrpcOptions,
    /// Address for gRPC and gRPC-Web requests.
    #[arg(long, env = "MIDEN_NOTE_TRANSPORT_LISTEN", default_value = "127.0.0.1:57292")]
    listen: SocketAddr,
    /// Maximum canonical header and detail bytes in one note.
    #[arg(long, env = "MIDEN_NOTE_TRANSPORT_MAX_NOTE_SIZE", default_value_t = 512_000)]
    max_note_size: usize,
    /// Maximum number of concurrent requests.
    #[arg(long, env = "MIDEN_NOTE_TRANSPORT_MAX_CONNECTIONS", default_value_t = 4096)]
    max_connections: usize,
    /// Maximum retained canonical header and detail bytes.
    #[arg(long, env = "MIDEN_NOTE_TRANSPORT_MAX_STORAGE_BYTES")]
    max_storage_bytes: u64,
    /// Enables OpenTelemetry trace export.
    #[arg(long)]
    enable_otel: bool,
}

#[derive(Args)]
struct CleanupArgs {
    #[command(flatten)]
    database: DatabaseArgs,
    /// Number of days to retain notes.
    #[arg(long, env = "MIDEN_NOTE_TRANSPORT_RETENTION_DAYS", default_value_t = 30)]
    retention_days: u32,
    /// Maximum number of notes to delete.
    #[arg(long, env = "MIDEN_NOTE_TRANSPORT_CLEANUP_MAX_ROWS", default_value_t = 1000)]
    max_rows: u32,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let otel = if matches!(&cli.command, Command::Start(args) if args.enable_otel) {
        OpenTelemetry::enabled()
    } else {
        OpenTelemetry::from_env()
    };
    let _otel_guard = miden_node_tracing::setup_tracing(otel.with_name(COMPONENT))?;
    run_with_shutdown(COMPONENT, |shutdown| async move {
        match cli.command {
            Command::Bootstrap(args) => db::bootstrap(&args.database)?,
            Command::Migrate(args) => db::migrate(&args.database)?,
            Command::Cleanup(args) => {
                let (writer, _reader) = db::load(&args.database.database)?;
                let deleted = db::cleanup(&writer, args.retention_days, args.max_rows).await?;
                info!(target: LOG_TARGET, "Note cleanup complete", note_transport.deleted = deleted);
            },
            Command::Start(args) => {
                let (writer, reader) = db::load(&args.database.database)?;
                let server = Server::new(Config {
                    max_note_size: args.max_note_size,
                    max_connections: args.max_connections,
                    max_storage_bytes: args.max_storage_bytes,
                    grpc: args.grpc,
                }, writer, reader)?;
                let listener = tokio::net::TcpListener::bind(args.listen).await?;
                server.serve_on(listener, shutdown).await?;
            },
        }
        Ok(())
    }).await
}
