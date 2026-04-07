# Miden Node Tracing

Tracing utilities for Miden node with enhanced error reporting.

## Overview

This crate provides an `#[instrument]` attribute macro that wraps `tracing::instrument` with a
custom syntax that enforces OpenTelemetry field naming conventions and adds optional full
error-chain reporting. It is **not** a drop-in replacement for `tracing::instrument`.

All function arguments are skipped automatically. The component name becomes the tracing `target`;
for string-literal components it also prefixes the span name (`"component.fn_name"`).

## Usage

```rust
use miden_node_tracing::instrument;

// COMPONENT is a `&str` const defined in the calling crate, e.g.:
// pub const COMPONENT: &str = "miden-store";

#[instrument(COMPONENT: report)]
pub async fn apply_block(&self, block: ProvenBlock) -> Result<(), ApplyBlockError> {
    // Function body...
}
```

The component prefix can also be a string literal:

```rust
#[instrument("miden-store": err)]
pub fn get_account(&self, id: AccountId) -> Result<Account, Error> { ... }
```

## Supported Syntax

```
#[instrument]
#[instrument(COMPONENT)]
#[instrument(COMPONENT:)]
#[instrument(COMPONENT: element, element, ...)]
```

`COMPONENT` is either an identifier (referencing a `&str` const in scope, resolved as
`crate::IDENT`) or a string literal.

### Elements

| Element | Description |
|---------|-------------|
| `report` | On `Err`: walk the full error chain via `ErrorReport`, log it, and set the OpenTelemetry span status. Mutually exclusive with `err`. Requires `Result` return. |
| `err` | On `Err`: emit a tracing event with the top-level error message. Mutually exclusive with `report`. Requires `Result` return. |
| `ret` | Record the function's return value inside the span. |
| `root` | Force the span to be a root span (`parent = None`). |
| `level: LEVEL` | Set the span level. `LEVEL` must be one of `INFO`, `DEBUG`, `TRACE`, `WARN`, `ERROR`. Defaults to `INFO`. |
| `dotted.name = [%\|?] expr` | Add an OTel span field. The name must be present in `allowlist.txt`. `%` uses Display; `?` or no modifier uses Debug. |

`skip_all` is always injected automatically. There is no way to record individual arguments;
use explicit field entries instead.

## Enhanced Error Reporting

When `report` is used and an error occurs, the full error chain is recorded:

```text
ERROR apply_block: error = "failed to apply block
caused by: database error
caused by: SQLite error: table 'blocks' has 10 columns but 9 values were supplied"
```

## Requirements

- `report` / `err` require the function to return `Result<T, E>`.
- `report` additionally requires `E: std::error::Error` (via the `ErrorReport` blanket impl from `miden-node-utils`).
- `async fn` returning `Result` is fully supported. `impl Future` and `Pin<Box<dyn Future>>` return types are not.
