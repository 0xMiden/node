use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use miden_node_tracing::OpenTelemetry;
use miden_node_utils::clap::GrpcOptions;
use miden_node_utils::fs::ensure_empty_directory;
use miden_node_utils::shutdown::run_with_shutdown;
use miden_note_transport::server::{Config, Server};
use miden_note_transport::{COMPONENT, db};

#[derive(Parser)]
#[command(version, about = "Miden note transport service")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Creates a new database and applies the schema.
    Bootstrap(DataDirectoryArgs),
    /// Applies pending migrations to an existing database.
    Migrate(DataDirectoryArgs),
    /// Serves gRPC and gRPC-Web requests.
    Start(StartArgs),
}

#[derive(Args)]
struct DataDirectoryArgs {
    /// Directory that contains the service data.
    #[arg(long, env = "MIDEN_NOTE_TRANSPORT_DATA_DIRECTORY", value_name = "DIR")]
    data_directory: PathBuf,
}

#[derive(Args)]
struct StartArgs {
    #[command(flatten)]
    storage: DataDirectoryArgs,
    #[command(flatten)]
    grpc: GrpcOptions,
    /// Address for gRPC and gRPC-Web requests.
    #[arg(long, env = "MIDEN_NOTE_TRANSPORT_LISTEN", default_value = "127.0.0.1:57292")]
    listen: SocketAddr,
    /// Maximum canonical header and detail bytes in one note.
    #[arg(long, env = "MIDEN_NOTE_TRANSPORT_MAX_NOTE_SIZE", default_value = "512000")]
    max_note_size: NonZeroUsize,
    /// Maximum number of concurrent requests.
    #[arg(long, env = "MIDEN_NOTE_TRANSPORT_MAX_CONNECTIONS", default_value = "4096")]
    max_connections: NonZeroUsize,
    /// Maximum retained canonical header and detail bytes.
    #[arg(long, env = "MIDEN_NOTE_TRANSPORT_MAX_STORAGE_BYTES")]
    max_storage_bytes: NonZeroU64,
    /// Number of days to retain notes.
    #[arg(long, env = "MIDEN_NOTE_TRANSPORT_RETENTION_DAYS", default_value = "30")]
    retention_days: NonZeroU32,
    /// Enables OpenTelemetry trace export.
    #[arg(long)]
    enable_otel: bool,
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
            Command::Bootstrap(args) => {
                ensure_empty_directory(&args.data_directory)?;
                db::bootstrap(&args.data_directory.join("notes.sqlite3"))?;
            },
            Command::Migrate(args) => db::migrate(&args.data_directory.join("notes.sqlite3"))?,
            Command::Start(args) => {
                let (writer, reader) =
                    db::load(&args.storage.data_directory.join("notes.sqlite3"))?;
                let server = Server::new(
                    Config {
                        max_note_size: args.max_note_size,
                        max_connections: args.max_connections,
                        max_storage_bytes: args.max_storage_bytes,
                        retention_days: args.retention_days,
                        grpc: args.grpc,
                    },
                    writer,
                    reader,
                )?;
                let listener = tokio::net::TcpListener::bind(args.listen).await?;
                server.serve_on(listener, shutdown).await?;
            },
        }
        Ok(())
    })
    .await
}
