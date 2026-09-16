use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use miden_node_tracing::OpenTelemetry;
use miden_node_utils::clap::GrpcOptions;
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
    Bootstrap(DatabaseArgs),
    /// Applies pending migrations to an existing database.
    Migrate(DatabaseArgs),
    /// Serves gRPC and gRPC-Web requests.
    Start(StartArgs),
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
    /// Number of days to retain notes.
    #[arg(long, env = "MIDEN_NOTE_TRANSPORT_RETENTION_DAYS", default_value_t = 30)]
    retention_days: u32,
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
            Command::Bootstrap(args) => db::bootstrap(&args.database)?,
            Command::Migrate(args) => db::migrate(&args.database)?,
            Command::Start(args) => {
                let (writer, reader) = db::load(&args.database.database)?;
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
