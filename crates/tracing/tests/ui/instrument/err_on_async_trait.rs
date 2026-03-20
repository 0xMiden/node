use async_trait::async_trait;
use miden_node_tracing::instrument;

#[async_trait]
trait Service {
    async fn call(&self) -> Result<(), String>;
}

struct Impl;

#[async_trait]
impl Service for Impl {
    #[instrument(rpc: err)]
    async fn call(&self) -> Result<(), String> {
        Ok(())
    }
}

fn main() {}
