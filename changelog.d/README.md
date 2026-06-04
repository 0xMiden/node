# Changelog Entries

Usually add one TOML file per pull request under the next release version:

```text
changelog.d/v0.15.0/2149.toml
changelog.d/v0.15.0/2149-bootstrap-command.toml
```

The filename must start with the pull request number. A short slug is optional.

Use one `[[entries]]` table for each release-note item:

```toml
[[entries]]
component = "ntx-builder"
category = "added"
summary = "Added `miden-ntx-builder bootstrap` to initialize the builder database before `start`."
```

If a pull request affects multiple public surfaces, add multiple entries to the same file:

```toml
[[entries]]
component = "ntx-builder"
category = "added"
summary = "Added `miden-ntx-builder bootstrap` to initialize the builder database before `start`."

[[entries]]
component = "docs"
category = "changed"
summary = "Updated network transaction builder bootstrap instructions."
```

For stacked pull requests that refine the same release-note item, update the existing entry and add the stacked PRs to
`related_prs`:

```toml
[[entries]]
component = "ntx-builder"
category = "added"
summary = "Added `miden-ntx-builder bootstrap` to initialize the builder database before `start`."
related_prs = [2150, 2151]
```

The filename PR is always linked first, followed by `related_prs`.

Allowed components:

```text
rpc-api
node
validator
ntx-builder
remote-prover
network-monitor
packaging
docs
internal
```

Crate-only implementation changes should use `internal`. If a crate change affects a public boundary, use the affected
public component instead. Not all PRs require an entry; be minimal - every entry adds noise. Be frugal especially with
`internal` changes - only those that have a meaningful impact on your colleagues.

Allowed categories:

```text
added
changed
deprecated
removed
fixed
security
performance
```

Set `breaking = true` when existing users must change clients, configs, CLI invocations, protobuf consumers, databases,
or deployments. It defaults to `false`; internal entries cannot be breaking.

Useful commands:

```sh
cargo xtask changelog check
cargo xtask changelog ci-check --base origin/main --pr 2149 --report target/changelog-check.md
cargo xtask changelog render --version v0.15.0
cargo xtask changelog release --version v0.15.0 --date 2026-06-03
```

`release` overwrites `CHANGELOG.md` with a freshly rendered section for the requested version. Historical changelog
entries from before structured automation live in `CHANGELOG.archived.md`.

The CI check uses simple heuristics to decide whether a changelog entry is likely required. When it triggers, any
`changelog.d/**` change satisfies the gate, including updates to an existing entry for stacked pull requests. Use the
`no changelog` label for changes that are intentionally not release-notable.
