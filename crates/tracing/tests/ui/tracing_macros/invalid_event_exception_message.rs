miden_node_tracing::declare_targets! { default: "miden::test", }

use miden_node_tracing::info;

fn main() {
    info!("test.info", exception.message = "manual report");
    info!("test.info", exception.stacktrace = "manual sources");
}
