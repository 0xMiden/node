# Docker throughput benchmark

This benchmark compares one Docker cache slot with two isolated cache slots. It replays six pinned source revisions from
the fee-collection PR stack. The workload and configuration commits are in `workload.json`.

Use an idle WarpBuild profile with the same machine size as normal Docker CI. The benchmark uses the same selected
builder for both configurations. Other builds on that worker invalidate a controlled comparison. The default profile is
the normal CI builder, so choose a quiet period or supply a separate profile.

## Run from the PR branch

The benchmark is a mode of the existing Docker workflow. It can run from the branch before the changes merge:

```sh
BENCHMARK_REF=your-benchmark-branch
gh workflow run docker.yml --repo 0xMiden/node \
  --ref "$BENCHMARK_REF" \
  -f mode=benchmark \
  -f ref="$BENCHMARK_REF" \
  -f benchmark_platform=linux/amd64 \
  -f benchmark_rounds=1
```

Add `-f benchmark_profile=PROFILE_NAME` to select a different builder. Start with one paired AMD64 round. Use two or
three rounds to check repeatability, then repeat for ARM64.

One round performs three warm-up builds and twelve measured builds. Warm-up is outside the throughput measurement, but
its duration remains in the results.

To use an already configured local or remote BuildKit builder:

```sh
python3 scripts/docker-throughput/benchmark.py \
  --fetch --platform linux/amd64 --rounds 1 --output /tmp/docker-throughput-results
```

The output directory must not exist. The script uses only the Python standard library, Git, and Docker Buildx. It does
not publish images.

## Method

Each configuration receives fresh cache mount IDs. The script builds the same common ancestor into each slot, then
submits all six source revisions together. Baseline builds share one cache and use the baseline CPU and memory budget.
Candidate builds select one of two caches by PR-number parity and use the candidate budget. The script changes only the
cache ID prefixes and adds a shell no-op with a unique trial identifier to each cache-mounted command.

The script checks that all source revisions descend from the warm-up commit and have distinct Docker build inputs. The
unique shell no-op changes the BuildKit operation without changing the compiler environment. This forces each measured
revision through Cargo and prevents a completed Docker layer from replacing the workload. Both configurations use Bake
directly, without the action's build-history export.

Rounds alternate baseline/candidate and candidate/baseline order. Each configuration warms fresh caches again. Cleanup
filters both the cache type and this trial's unique cache ID prefix. It does not request a global builder prune.
Interrupted jobs can leave benchmark caches for normal BuildKit garbage collection.

Cache IDs isolate contents, not disk capacity or I/O. Benchmark builds can still cause normal BuildKit garbage
collection on the selected worker. A separate, equally sized builder provides the cleanest comparison.

## Results

The Actions summary reports batch time and successful builds per hour. The `docker-throughput-*` artifact contains:

- `results.json` and `summary.md`: warm-up and measured batch results, plus the paired throughput ratio.
- Per-build `timing.json`, `build.log`, `metadata.json`, and the Kache report.
- The scoped Dockerfile, Bake configuration, workload commits, builder configuration, disk snapshots, and cleanup logs.

The throughput ratio is baseline batch time divided by candidate batch time. A ratio above 1 means that the candidate
completed the batch faster. Failed or incomplete pairs have no ratio. Compare individual build latency and cache hits as
well as the batch result.

Disk snapshots are not peak measurements. The runner does not have access to the remote worker's CPU and memory
counters; use WarpBuild telemetry to check saturation or memory pressure. A single faster pair is preliminary evidence.
Repeat the comparison before changing normal CI.

## Harness checks

```sh
python3 -m unittest discover -s scripts/docker-throughput -p 'test_*.py'
```

The Docker integration test uses a tiny workload with deliberate two-second build steps. It checks A/B and B/A order,
warm cache reuse, forced execution, and cleanup isolation. Its timing is not a node throughput result.

```sh
DOCKER_THROUGHPUT_INTEGRATION=1 \
  python3 -m unittest discover -s scripts/docker-throughput -p 'test_*.py'
```
