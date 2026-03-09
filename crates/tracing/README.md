# Miden Node Tracing

Tracing utilities for Miden node with enhanced error reporting.

## Overview

This crate provides an `#[instrument_with_err_report]` attribute macro that enhances the standard `tracing::instrument` with full error chain reporting. When a function returns an error, instead of just logging the top-level error message, it captures and logs the entire error chain.

## Usage

```rust
use miden_node_tracing::instrument_with_err_report;

#[instrument_with_err_report(target = "my_component", skip_all, err)]
pub async fn apply_block(&self, block: ProvenBlock) -> Result<(), ApplyBlockError> {
    // Function body...
}
```

## Enhanced Error Reporting

When an error occurs, the full error chain is recorded:

```text
ERROR apply_block: error.report = "failed to apply block
caused by: database error
caused by: SQLite error: table 'blocks' has 10 columns but 9 values were supplied"
```

This is much more useful for debugging than just seeing "failed to apply block".

## Supported Arguments

All arguments from `tracing::instrument` are supported:

| Argument | Example | Description |
|----------|---------|-------------|
| `target` | `target = "my_component"` | Sets the tracing target |
| `level` | `level = "debug"` | Sets the tracing level |
| `name` | `name = "custom.span.name"` | Sets a custom span name |
| `err` | `err` | Record errors with full error chain |
| `ret` | `ret` or `ret(level = "debug")` | Record return values |
| `skip` | `skip(arg1, arg2)` | Skip specific arguments |
| `skip_all` | `skip_all` | Skip all arguments |
| `fields` | `fields(key = value)` | Add custom fields |
| `parent` | `parent = None` | Create a root span |

## Requirements

The enhanced error reporting requires the error type to implement `std::error::Error`. For error types that don't (like `tonic::Status` or `anyhow::Error`), use the standard `tracing::instrument` instead.
