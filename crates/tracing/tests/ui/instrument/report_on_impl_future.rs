use miden_node_tracing::instrument;

#[instrument(rpc: report)]
fn foo() -> impl std::future::Future<Output = Result<(), String>> {
    async { Ok(()) }
}

fn main() {}
