use miden_node_tracing::instrument;

#[instrument(rpc: report, err)]
fn foo() -> Result<(), String> {
    Ok(())
}

fn main() {}
