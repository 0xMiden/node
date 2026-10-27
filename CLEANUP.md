# Deferred cleanup

## Patched kache prefetch trial

Status: waiting for an official kache release containing the prefetch cancellation fix.

[Setup kache](.github/actions/setup-kache/action.yml) installs a checksum-pinned
Linux x64 build from [the trial fork](https://github.com/Mirko-von-Leipzig/kache/tree/miden-prefetch-v1.2.2).
The patch prevents cancellation while a plan is loading and reassesses earlier
requests when its candidates arrive.

Once an official release contains both fixes:

1. Verify the release includes the regression tests for pending requests and
   replacement plans, or equivalent coverage.
2. Remove the patched-binary installation step and select the official version
   in the setup action.
3. Run CI and rerun the same commit with a warm S3 cache. Check the uploaded daemon
   diagnostics for early cancellation, compare build times and downloaded bytes,
   and confirm the setup and post-job hooks succeed.
4. Remove this entry after the official release passes those checks.
