use std::sync::{Arc, Mutex};
use std::time::Duration;

use miden_node_utils::shutdown::CancellationToken;
use tracing::instrument::WithSubscriber;
use tracing::{Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};

use super::super::{Builder, GrpcClient, RemoteProverProxyStatusClient, ValidatorClient};

struct ConnectionEvents {
    events: Arc<Mutex<Vec<(&'static str, Level)>>>,
    shutdown: CancellationToken,
}

impl<S: Subscriber> Layer<S> for ConnectionEvents {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        if metadata.fields().field("dependency.name").is_some() {
            self.events.lock().unwrap().push((metadata.target(), *metadata.level()));
            if metadata.fields().field("dependency.endpoint").is_some() {
                self.shutdown.cancel();
            }
        }
    }
}

async fn connection_target<T: GrpcClient + Send + 'static>(url: url::Url) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let shutdown = CancellationToken::new();
    let subscriber = tracing_subscriber::registry().with(ConnectionEvents {
        events: events.clone(),
        shutdown: shutdown.clone(),
    });
    let builder = Builder::new(url)
        .without_tls()
        .without_timeout()
        .without_metadata_version()
        .without_metadata_genesis()
        .without_auth_header()
        .without_otel_context_injection();

    tokio::time::timeout(
        Duration::from_secs(10),
        async {
            miden_node_tracing::info_v2!("caller.started", dependency.name = "test-caller");
            builder.monitor::<T>("test-service", shutdown).await;
        }
        .with_subscriber(subscriber),
    )
    .await
    .expect("monitor should stop after reporting a connection");

    assert_eq!(
        *events.lock().unwrap(),
        [("miden::test::caller", Level::INFO), ("miden::rpc::client", Level::INFO)]
    );
}

#[tokio::test]
async fn generic_client_diagnostics_use_the_target_at_their_definition() {
    let (url, shutdown, task) = super::message_size::server(0).await;
    connection_target::<RemoteProverProxyStatusClient>(url.clone()).await;
    connection_target::<ValidatorClient>(url).await;
    shutdown.cancel();
    task.await.unwrap();
}
