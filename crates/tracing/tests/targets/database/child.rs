#[miden_node_tracing::instrument]
pub fn inherited() -> &'static str {
    tracing::Span::current().metadata().unwrap().target()
}

pub struct Database;

impl Database {
    #[miden_node_tracing::instrument]
    pub fn load<T>(&self, value: T) -> T {
        assert_eq!(tracing::Span::current().metadata().unwrap().target(), "miden::storage::sqlite");
        value
    }

    #[miden_node_tracing::instrument]
    pub async fn load_async<T>(&self, value: T) -> T {
        tokio::task::yield_now().await;
        assert_eq!(tracing::Span::current().metadata().unwrap().target(), "miden::storage::sqlite");
        value
    }
}

pub trait Backend {
    fn target(&self) -> &'static str;
}

impl Backend for Database {
    #[miden_node_tracing::instrument]
    fn target(&self) -> &'static str {
        tracing::Span::current().metadata().unwrap().target()
    }
}

#[miden_node_tracing::instrument]
pub fn returned_future() -> impl Future<Output = &'static str> {
    async {
        tokio::task::yield_now().await;
        tracing::Span::current().metadata().unwrap().target()
    }
}

pub fn events() {
    use miden_node_tracing::{debug, error, info, trace, warn};

    let error = std::io::Error::other("database unavailable");
    trace!("trace.event", block.number = 1_u32);
    debug!(&error, "debug.event", block.number = 2_u32);
    info!("info.event", block.number = 3_u32, custom.attribute = "custom" #[nonstandard]);
    warn!(&error, "warn.event", block.number = 4_u32);
    error!(&error, "error.event", block.number = 5_u32);
}

pub fn debug_enabled() -> bool {
    miden_node_tracing::enabled!(tracing::Level::DEBUG)
}

pub fn override_enabled() -> bool {
    miden_node_tracing::enabled!(target: "miden::rpc::server", tracing::Level::DEBUG)
}

pub fn fields_enabled() -> bool {
    miden_node_tracing::enabled!(tracing::Level::DEBUG, block.number)
}

#[miden_node_tracing::instrument(target = "miden::rpc::server")]
pub fn parented_events(parent: &tracing::Span) {
    miden_node_tracing::info!("contextual.event");
    miden_node_tracing::info!(parent: parent, "parented.event");
    miden_node_tracing::info!(parent: None, "root.event");
    miden_node_tracing::warn!(
        std::io::Error::other("database unavailable"),
        target: "miden::storage::override",
        parent: parent,
        "override.event",
        block.number = 6_u32
    );
}

#[expect(non_snake_case)]
#[miden_node_tracing::instrument]
pub fn helper_name_collision(__MIDEN_TRACING_TARGET: u32) -> u32 {
    __MIDEN_TRACING_TARGET
}
