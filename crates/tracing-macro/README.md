# miden-node-tracing-macro

Internal procedural macro crate for `miden-node-tracing`.

**Do not use this crate directly.** Import from `miden-node-tracing` instead,
which re-exports every macro here together with all required runtime dependencies
(`ErrorReport`, `OpenTelemetrySpanExt`, …).

---

## `#[instrument]`

Instruments a function with a [`tracing`] span.  Extends `tracing::instrument`
with a component-target shorthand, an OpenTelemetry field allowlist, and a `report`
keyword for full error-chain capture.

### Syntax

```text
#[instrument]
#[instrument( [COMPONENT:] [element, …] )]

COMPONENT   ::= ident | "string literal"
element     ::= field-entry | "ret" | "err" | "report"
field-entry ::= dotted-name "=" ["%"] expr
dotted-name ::= ident ["." ident]*   -- must appear in allowlist.txt
```

### Keywords

| Keyword | Requires `Result`? | Description |
|---|---|---|
| `ret` | no | Records the return value inside the span |
| `err` | yes | Emits a tracing event with the top-level error message (delegates to `tracing::instrument`'s built-in `err`) |
| `report` | yes | Emits an `error!` event with the **full error chain** via `ErrorReport::as_report()` and sets the OpenTelemetry span status to `Error`.  Mutually exclusive with `err`. |

### Field entries

```rust
#[instrument(rpc: account.id = account_id)]    // Debug  → {:?}
#[instrument(rpc: account.id = %account_id)]   // Display → {}
```

Field names must appear in [`allowlist.txt`](allowlist.txt).  An undeclared name
is a compile error; the macro suggests the closest allowlisted names.

### Full argument reference

| Attribute | fn returns `Result`? | Valid? | Behaviour |
|---|---|---|---|
| *(empty)* | any | ✓ | Thin `#[tracing::instrument]` wrapper |
| `rpc:` | any | ✓ | Span with `target = "rpc"`, no field/ret tracking |
| `rpc: ret` | any | ✓ | `tracing::instrument` `ret` |
| `rpc: err` | yes | ✓ | `tracing::instrument` `err` (top-level message) |
| `rpc: err` | no | ✗ | `err` requires `Result` return |
| `rpc: report` | yes | ✓ | Full error chain + OpenTelemetry status |
| `rpc: report` | no | ✗ | `report` requires `Result` return |
| `rpc: err, report` | any | ✗ | Mutually exclusive |
| `rpc: report, err` | any | ✗ | Mutually exclusive (order irrelevant) |
| `rpc: ret, err` | yes | ✓ | Return value + top-level error |
| `rpc: ret, report` | yes | ✓ | Return value + full error chain |
| `rpc: ret, report` | no | ✗ | `report` requires `Result` return |
| `rpc: account.id = id` | any | ✓ | Allowlisted field, Debug |
| `rpc: account.id = %id` | any | ✓ | Allowlisted field, Display |
| `rpc: foo = id` | any | ✗ | `foo` not in allowlist |
| `rpc: foo.bar.baz = %id` | any | ✗ | `foo.bar.baz` not in allowlist |
| `rpc: account.id = %id, err` | yes | ✓ | Field + standard error |
| `rpc: account.id = %id, report` | yes | ✓ | Field + full error chain |
| `rpc: account.id = %id, ret, report` | yes | ✓ | Field + return value + full error chain |
| `rpc: account.id = %id, report, err` | yes | ✗ | Mutually exclusive |

### `err` vs `report`

| | `err` | `report` |
|---|---|---|
| Mechanism | `tracing::instrument` built-in | Custom body wrapper |
| Error detail | Top-level `Display`/`Debug` | Full chain via `ErrorReport::as_report()` |
| OpenTelemetry span status | Not set | Set to `Error` |
| Event level | `ERROR` | `ERROR` |

Use `err` for lightweight internal helpers.  Use `report` on RPC handlers and
any boundary where the full error chain must appear in telemetry.

### Examples

```rust
use miden_node_tracing::instrument;

// Minimal – default target, no tracking.
#[instrument]
fn simple() {}

// Component only.
#[instrument(rpc:)]
fn with_target() {}

// Return value.
#[instrument(rpc: ret)]
fn compute() -> u32 { 42 }

// Standard error (top-level message).
#[instrument(store: err)]
async fn load() -> Result<Data, LoadError> { todo!() }

// Full error chain + OpenTelemetry span status.
#[instrument(rpc: report)]
async fn apply_block(block: Block) -> Result<(), ApplyBlockError> { todo!() }

// Return value + full error chain.
#[instrument(rpc: ret, report)]
async fn fetch_count() -> Result<u32, FetchError> { todo!() }

// Allowlisted field (Display) + full error chain.
#[instrument(rpc: account.id = %account_id, report)]
async fn get_account(account_id: AccountId) -> Result<Account, RpcError> { todo!() }

// Multiple allowlisted fields.
#[instrument(store: account.id = %account_id, block.number = block_num, err)]
async fn get_account_at(
    account_id: AccountId,
    block_num: BlockNumber,
) -> Result<Account, StoreError> { todo!() }
```

---

## `warn!` / `error!` / `info!` / `debug!` / `trace!`

These macros enforce the same rules as `#[instrument]` and then expand to the
underlying `tracing::<level>!` macro.

### Syntax

```text
warn!( [COMPONENT:] [field = ["%"|"?"] expr ,]* [format_string [, args…]] )

COMPONENT   ::= ident | string-literal
field-entry ::= dotted-name "=" ["%" | "?"] expr
dotted-name ::= ident ["." ident]*   -- must appear in allowlist.txt
```

The optional `COMPONENT:` prefix sets the tracing target (e.g. `rpc:` →
`target: "rpc"`).  Field names are validated against the OpenTelemetry allowlist;
an unlisted name is a compile error with fuzzy-matched suggestions.

### Full argument reference for `warn!`

| Form | Example | Valid? |
|---|---|---|
| Empty | `warn!()` | ✓ |
| Plain message | `warn!("something looks off")` | ✓ |
| Format string | `warn!("retrying after {}ms", delay_ms)` | ✓ |
| Component + message | `warn!(rpc: "request failed")` | ✓ |
| Component + format | `warn!(store: "migrated {} rows", n)` | ✓ |
| Component only | `warn!(rpc:)` | ✓ |
| Allowlisted field, Debug | `warn!(account.id = id, "context")` | ✓ |
| Allowlisted field, Display | `warn!(account.id = %id, "context")` | ✓ |
| Allowlisted field, Debug explicit | `warn!(account.id = ?id, "context")` | ✓ |
| Unlisted field | `warn!(foo = %x, "context")` | ✗ |
| Unlisted dotted field | `warn!(foo.bar = %x, "context")` | ✗ |
| Multiple allowlisted fields + message | `warn!(account.id = %id, block.number = n, "msg")` | ✓ |
| Fields only, no message | `warn!(account.id = %id, block.number = n)` | ✓ |
| Component + fields + message (full form) | `warn!(rpc: account.id = %id, "rejected")` | ✓ |
| Component + unlisted field | `warn!(rpc: foo = %x, "msg")` | ✗ |

The same table applies to `error!`, `info!`, `debug!`, and `trace!` – only the
severity level differs.
