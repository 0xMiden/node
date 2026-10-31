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

            pub fn event() {
                miden_node_tracing::info_v2!("rocksdb.event");
            }

            pub fn debug_enabled() -> bool {
                miden_node_tracing::enabled_v2!(tracing::Level::DEBUG)
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

            pub fn event() {
                miden_node_tracing::info_v2!("files.event");
            }
        }
    }

    pub mod maintenance;
}
