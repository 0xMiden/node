---
title: "Monitoring"
sidebar_position: 5
---

# Monitoring & telemetry

We provide logging to `stdout` and an optional [OpenTelemetry](https://opentelemetry.io/) exporter for our traces.

OpenTelemetry exporting can be enabled by specifying `--enable-otel` via the command-line or the
`MIDEN_NODE_ENABLE_OTEL` environment variable when operating the node.

We do _not_ export OpenTelemetry logs or metrics. Our end goal is to derive these based off of our tracing information.
This approach is known as [wide-events](https://isburmistrov.substack.com/p/all-you-need-is-wide-events-not-metrics),
[structured logs](https://newrelic.com/blog/how-to-relic/structured-logging), and
[Observibility 2.0](https://www.honeycomb.io/blog/time-to-version-observability-signs-point-to-yes).

What we're exporting are `traces` which consist of `spans` (covering a period of time), and `events` (something happened
at a specific instance in time). These are extremely useful to debug distributed systems - even though `miden` is still
centralized, the `node` components are distributed.

OpenTelemetry provides a
[Span Metrics Converter](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/spanmetricsconnector)
which can be used to convert our traces into more conventional metrics.

## What gets traced

We assign a unique trace (aka root span) to each RPC request, batch build, and block build process.

<div class="warning">

Span and attribute naming is unstable and should not be relied upon. This also means changes here will not be considered
breaking, however we will do our best to document them.

</div>

### RPC request/response

Not yet implemented.

### Block building

This trace covers the building, proving and submission of a block.

<details>
  <summary>Span tree</summary>

```sh
block_builder.build_block
┝━ block_builder.select_block
│  ┝━ mempool.lock
│  ┕━ mempool.select_block
┝━ block_builder.get_block_inputs
│  ┝━ block_builder.summarize_batches
│  ┕━ store.client.get_block_inputs
│     ┕━ store.rpc/GetBlockInputs
│        ┕━ store.server.get_block_inputs
│           ┝━ validate_nullifiers
│           ┝━ read_account_ids
│           ┝━ validate_note_commitments
│           ┝━ select_block_header_by_block_num
│           ┝━ select_note_inclusion_proofs
│           ┕━ select_block_headers
┝━ block_builder.prove_block
│  ┝━ execute_program
│  ┕━ block_builder.simulate_proving
┝━ block_builder.inject_failure
┕━ block_builder.commit_block
   ┝━ store.client.apply_block
   │ ┕━ store.rpc/ApplyBlock
   │    ┕━ store.server.apply_block
   │       ┕━ apply_block
   │          ┝━ select_block_header_by_block_num
   │          ┕━ update_in_memory_structs
   ┝━ mempool.lock
   ┕━ mempool.commit_block
      ┕━ mempool.revert_expired_transactions
         ┕━ mempool.revert_transactions
```

</details>

### Batch building

This trace covers the building and proving of a batch.

<details>
  <summary>Span tree</summary>

```sh
batch_builder.build_batch
┝━ batch_builder.wait_for_available_worker
┝━ batch_builder.select_batch
│  ┝━ mempool.lock
│  ┕━ mempool.select_batch
┝━ batch_builder.get_batch_inputs
│  ┕━ store.client.get_batch_inputs
┝━ batch_builder.propose_batch
┝━ batch_builder.prove_batch
┝━ batch_builder.inject_failure
┕━ batch_builder.commit_batch
   ┝━ mempool.lock
   ┕━ mempool.commit_batch
```

</details>

## Verbosity

We log important spans and events at `info` level or higher, which is also the default log level.

Changing this level should rarely be required - let us know if you're missing information that should be at `info`.

The available log levels are `trace`, `debug`, `info` (default), `warn`, `error` which can be configured using the
`RUST_LOG` environment variable e.g.

```sh
export RUST_LOG=debug
```

The verbosity can also be specified by component (when running them as a single process):

```sh
export RUST_LOG=warn,block-producer=debug,rpc=error
```

The above would set the general level to `warn`, and the `block-producer` and `rpc` components would be overridden to
`debug` and `error` respectively. Though as mentioned, it should be unusual to do this.

## Configuration

The OpenTelemetry trace exporter is enabled by adding the `--enable-otel` flag to the node's start command:

```sh
miden-node bundled start --enable-otel
```

The exporter can be configured using environment variables as specified in the official
[documents](https://opentelemetry.io/docs/specs/otel/protocol/exporter/).

<div class="warning">
Not all options are fully supported. We are limited to what the Rust OpenTelemetry implementation supports. If you have any problems please open an issue and we'll do our best to resolve it.

Note: we only support gRPC as the export protocol.

</div>

#### Example: Honeycomb configuration

This is based off Honeycomb's OpenTelemetry
[setup guide](https://docs.honeycomb.io/send-data/opentelemetry/#using-the-honeycomb-opentelemetry-endpoint).

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io:443 \
OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-team=your-api-key" \
miden-node bundled start --enable-otel
```

### Honeycomb queries, triggers and board examples

#### Example Queries

Here are some useful Honeycomb queries to help monitor your Miden node:

**Block building performance**:

```honeycomb
VISUALIZE
HEATMAP(duration_ms) AVG(duration_ms)
WHERE
name = "block_builder.build_block"
GROUP BY block.number
ORDER BY block.number DESC
LIMIT 100
```

**Batch processing latency**:

```honeycomb
VISUALIZE
HEATMAP(duration_ms) AVG(duration_ms) P95(duration_ms)
WHERE
name = "batch_builder.build_batch"
GROUP BY batch.id
LIMIT 100
```

**Block proving failures**:

```honeycomb
VISUALIZE
COUNT
WHERE
name = "block_builder.build_block"
AND status = "error"
CALCULATE RATE
```

**Transaction volume by block**:

```honeycomb
VISUALIZE
MAX(transactions.count)
WHERE
name = "block_builder.build_block"
GROUP BY block.number
ORDER BY block.number DESC
LIMIT 100
```

**RPC request rate by endpoint**:

```honeycomb
VISUALIZE
COUNT
WHERE
name contains "rpc"
GROUP BY name
```

**RPC latency by endpoint**:

```honeycomb
VISUALIZE
AVG(duration_ms) P95(duration_ms)
WHERE
name contains "rpc"
GROUP BY name
```

**RPC errors by status code**:

```honeycomb
VISUALIZE
COUNT
WHERE
name contains "rpc"
GROUP BY status_code
```

#### Example Triggers

Create triggers in Honeycomb to alert you when important thresholds are crossed:

**Slow block building**:

- Query:

```honeycomb
VISUALIZE
AVG(duration_ms)
WHERE
name = "block_builder.build_block"
```

- Trigger condition: `AVG(duration_ms) > 30000` (adjust based on your expected block time)
- Description: Alert when blocks take too long to build (more than 30 seconds on average)

**High failure rate**:

- Query:

```honeycomb
VISUALIZE
COUNT
WHERE
name = "block_builder.build_block" AND error = true
```

- Trigger condition: `COUNT > 100 WHERE error = true`
- Description: Alert when more than 100 block builds are failing

#### Advanced investigation with BubbleUp

To identify the root cause of performance issues or errors, use Honeycomb's BubbleUp feature:

1. Create a query for a specific issue (e.g., high latency for block building)
2. Click on a specific high-latency point in the visualization
3. Use BubbleUp to see which attributes differ significantly between normal and slow operations
4. Inspect the related spans in the trace to pinpoint the exact step causing problems

This approach helps identify patterns like:

- Which types of transactions are causing slow blocks
- Which specific operations within block/batch processing take the most time
- Correlations between resource usage and performance
- Common patterns in error cases
