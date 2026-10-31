miden_node_tracing::target_scope! {
    "miden::storage";

    pub mod database;

    pub mod rocksdb {
        miden_node_tracing::target_scope! {
            "miden::storage::rocksdb";

            #[miden_node_tracing::instrument_v2]
            pub fn target() -> &'static str {
                tracing::Span::current().metadata().unwrap().target()
            }
        }
    }

    pub mod files {
        miden_node_tracing::target_scope! {
            "miden::storage::files";

            #[miden_node_tracing::instrument_v2]
            pub fn target() -> &'static str {
                tracing::Span::current().metadata().unwrap().target()
            }
        }
    }

    pub mod maintenance;
}
