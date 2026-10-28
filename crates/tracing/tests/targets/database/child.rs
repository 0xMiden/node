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
