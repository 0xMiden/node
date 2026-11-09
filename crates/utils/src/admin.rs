//! Optional private administration listeners for services without an existing admin API.

use std::future::Future;
use std::net::SocketAddr;

use anyhow::Context as _;
use miden_node_tracing::info_v2;
use tokio::net::TcpListener;

use crate::shutdown::CancellationToken;

/// Configures a private administration listener.
#[derive(clap::Args, Clone, Copy, Debug, Default)]
pub struct AdminOptions {
    /// Address for the private administration API. Require external authentication and network
    /// isolation.
    #[arg(
        id = "admin_listen",
        long = "admin.listen",
        env = "MIDEN_ADMIN_LISTEN",
        value_name = "IP:PORT"
    )]
    pub listen: Option<SocketAddr>,
}

impl AdminOptions {
    /// Runs a service alongside its optional administration listener.
    ///
    /// The listener is bound before the service starts. Either completion cancels the shared
    /// shutdown token and waits for the other future to finish, preserving service errors.
    pub fn run(
        self,
        shutdown: CancellationToken,
        service: impl Future<Output = anyhow::Result<()>>,
    ) -> impl Future<Output = anyhow::Result<()>> {
        // Service startup futures can be large; keep their state out of the supervisor future.
        let service = Box::pin(service);
        async move {
            let Some(address) = self.listen else {
                return service.await;
            };
            let listener = TcpListener::bind(address)
                .await
                .with_context(|| format!("failed to bind admin listener to {address}"))?;
            serve(listener, shutdown, service).await
        }
    }
}

async fn serve(
    listener: TcpListener,
    shutdown: CancellationToken,
    service: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    info_v2!(
        "Admin server ready",
        admin.listen = listener
            .local_addr()
            .context("failed to read admin listen address")?
            .to_string()
    );
    let server = axum::serve(listener, miden_node_tracing::admin::router())
        .with_graceful_shutdown(shutdown.clone().cancelled_owned())
        .into_future();
    tokio::pin!(server);
    tokio::pin!(service);
    tokio::select! {
        result = &mut service => {
            shutdown.cancel();
            let server_result = server.await.context("failed to serve admin API");
            result.and(server_result)
        },
        result = &mut server => {
            let expected = shutdown.is_cancelled();
            shutdown.cancel();
            let service_result = service.await;
            result.context("failed to serve admin API")?;
            service_result?;
            anyhow::ensure!(expected, "admin API stopped unexpectedly");
            Ok(())
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[arg(long)]
        listen: Option<SocketAddr>,
        #[command(flatten)]
        admin: AdminOptions,
    }

    #[test]
    fn listener_is_opt_in_and_requires_a_socket_address() {
        assert!(Cli::try_parse_from(["test"]).unwrap().admin.listen.is_none());
        let cli = Cli::try_parse_from([
            "test",
            "--listen",
            "127.0.0.1:50000",
            "--admin.listen",
            "127.0.0.1:50100",
        ])
        .unwrap();
        assert_eq!(cli.listen.unwrap(), "127.0.0.1:50000".parse().unwrap());
        assert_eq!(cli.admin.listen.unwrap(), "127.0.0.1:50100".parse().unwrap());
        assert!(Cli::try_parse_from(["test", "--admin.listen", "invalid"]).is_err());
    }

    #[tokio::test]
    async fn disabled_listener_preserves_the_service_result() {
        let error = AdminOptions::default()
            .run(CancellationToken::new(), async { anyhow::bail!("service failed") })
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "service failed");
    }

    #[tokio::test]
    async fn bind_failure_prevents_service_startup() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let polled = AtomicBool::new(false);
        let error = AdminOptions {
            listen: Some(listener.local_addr().unwrap()),
        }
        .run(CancellationToken::new(), async {
            polled.store(true, Ordering::Relaxed);
            Ok(())
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("failed to bind admin listener"));
        assert!(!polled.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn serves_tracing_routes_and_stops_after_cancellation() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let service = async {
            let response =
                reqwest::get(format!("http://{address}/admin/tracing/targets")).await.unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            assert!(response.text().await.unwrap().contains("\"targets\""));
            shutdown.cancel();
            Ok(())
        };
        tokio::time::timeout(Duration::from_secs(5), serve(listener, shutdown.clone(), service))
            .await
            .unwrap()
            .unwrap();
        assert!(TcpListener::bind(address).await.is_ok());
    }

    #[tokio::test]
    async fn cancellation_waits_for_the_service_to_finish() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let shutdown = CancellationToken::new();
        let finished = AtomicBool::new(false);
        let service = async {
            shutdown.cancelled().await;
            tokio::task::yield_now().await;
            finished.store(true, Ordering::Relaxed);
            Ok(())
        };
        let cancel = async {
            tokio::task::yield_now().await;
            shutdown.cancel();
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(serve(listener, shutdown.clone(), service), cancel)
        })
        .await
        .unwrap();
        result.unwrap();
        assert!(finished.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn service_failure_cancels_and_closes_the_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let error = serve(listener, shutdown.clone(), async { anyhow::bail!("service failed") })
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "service failed");
        assert!(shutdown.is_cancelled());
        assert!(TcpListener::bind(address).await.is_ok());
    }
}
