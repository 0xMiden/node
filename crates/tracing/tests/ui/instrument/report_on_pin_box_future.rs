use miden_node_tracing::instrument;

#[instrument(rpc: report)]
fn foo() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>>>> {
    Box::pin(async { Ok(()) })
}

fn main() {}
