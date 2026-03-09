# Miden Node Tracing Macro

Internal procedural macro crate for `miden-node-tracing`.

**Do not use this crate directly.** Use `miden-node-tracing` instead, which re-exports this macro along with all required dependencies.

## Usage

```rust
use miden_node_tracing::instrument_with_err_report;

#[instrument_with_err_report(target = COMPONENT, skip_all, err)]
pub async fn apply_block(&self, block: ProvenBlock) -> Result<(), ApplyBlockError> {
    // Function body...
}
```
