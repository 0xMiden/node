pub mod database;

pub mod rocksdb {
    #[miden_node_tracing::instrument]
    pub fn target() -> &'static str {
        tracing::Span::current().metadata().unwrap().target()
    }

    pub fn event() {
        miden_node_tracing::info!("rocksdb.event");
    }

    pub fn debug_enabled() -> bool {
        miden_node_tracing::enabled!(tracing::Level::DEBUG)
    }
}

pub mod files {
    #[miden_node_tracing::instrument]
    pub fn target() -> &'static str {
        tracing::Span::current().metadata().unwrap().target()
    }

    pub fn event() {
        miden_node_tracing::info!("files.event");
    }
}

pub mod maintenance;
