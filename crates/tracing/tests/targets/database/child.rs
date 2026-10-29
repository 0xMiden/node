#[miden_node_tracing::instrument_v2]
pub fn inherited() -> &'static str {
    tracing::Span::current().metadata().unwrap().target()
}

pub struct Database;

impl Database {
    #[miden_node_tracing::instrument_v2]
    pub fn load<T>(&self, value: T) -> T {
        assert_eq!(tracing::Span::current().metadata().unwrap().target(), "miden::storage::sqlite");
        value
    }

    #[miden_node_tracing::instrument_v2]
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
    #[miden_node_tracing::instrument_v2]
    fn target(&self) -> &'static str {
        tracing::Span::current().metadata().unwrap().target()
    }
}

#[miden_node_tracing::instrument_v2]
pub fn returned_future() -> impl Future<Output = &'static str> {
    async {
        tokio::task::yield_now().await;
        tracing::Span::current().metadata().unwrap().target()
    }
}

pub fn events() {
    use miden_node_tracing::{debug_v2, error_v2, info_v2, trace_v2, warn_v2};

    let error = std::io::Error::other("database unavailable");
    trace_v2!("trace.event", block.number = 1_u32);
    debug_v2!(&error, "debug.event", block.number = 2_u32);
    info_v2!("info.event", block.number = 3_u32, custom.attribute = "custom" #[nonstandard]);
    warn_v2!(&error, "warn.event", block.number = 4_u32);
    error_v2!(&error, "error.event", block.number = 5_u32);
}

#[miden_node_tracing::instrument_v2(target = "miden::rpc::server")]
pub fn parented_events(parent: &tracing::Span) {
    miden_node_tracing::info_v2!("contextual.event");
    miden_node_tracing::info_v2!(parent: parent, "parented.event");
    miden_node_tracing::info_v2!(parent: None, "root.event");
    miden_node_tracing::warn_v2!(
        std::io::Error::other("database unavailable"),
        target: "miden::storage::override",
        parent: parent,
        "override.event",
        block.number = 6_u32
    );
}
