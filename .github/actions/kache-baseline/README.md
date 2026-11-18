# Compiler-cache baselines

Each CI build configuration restores one compressed kache local-store snapshot before starting its daemon. This keeps
warmup to a metadata request and an archive download. Missing artifacts use normal exact-key downloads through
CloudFront; speculative prefetch is disabled. Uploads use S3.

Baselines are independent for `next` and every `release/v*` branch, with separate metadata for each repository, job,
platform, and pinned kache version. Pull requests and merge queues read their target branch's baseline. Version tags
such as `v0.18.3` read `release/v0.18`. Other refs read `next`.

## Refreshing a baseline

Only successful protected push jobs on `next` or `release/v*` can publish their own branch's baseline. Pull requests may
upload individual artifacts when authorized, but cannot replace a baseline. Register this action before the kache setup
action so its post hook runs after kache stops and finishes its uploads. Docker builds must also stop the daemon and
return cache-directory ownership to the runner before the post hook.

A baseline refreshes when at least 5% of the current job's artifact keys are missing, it is at least seven days old, or
it is missing or cannot be restored. A current baseline causes no archive or metadata upload. Refresh takes a consistent
SQLite backup and archives the complete persistent local store; runtime state and pending upload queues are excluded.
Existing local cache size limits still apply.

Publication uploads the immutable archive before replacing its metadata conditionally. A concurrent metadata update
causes publication to stop rather than overwrite that update. Older runs of the same workflow cannot replace a newer
baseline. Readers already using an older archive can finish normally. Existing bucket lifecycle rules retire old
archives; this action does not delete shared artifacts or packs.

## Troubleshooting and checks

Restore and publication failures produce warnings and leave compilation available through the normal artifact cache. A
failed restore uses an empty local store. Check the `Restore branch baseline` and `Post Restore branch baseline` logs
for coverage, refresh reasons, checksum failures, or conditional-upload conflicts.

The CloudFront distribution must cache `protected-branch/baselines/v1/archives/*` as immutable content and leave
baseline metadata uncached. Every download, including metadata, goes through the configured CloudFront endpoint. There
is no direct S3 download fallback.

Run the helper tests with Python 3.12 or later and `zstd` installed:

```sh
python3 -m unittest discover -s .github/actions/kache-baseline -p test_baseline.py -v
```

Set `KACHE_TEST_BINARY` to a local kache executable to include a real Cargo build, snapshot restore, and source-change
check. Those builds run offline with a temporary local-only cache.
