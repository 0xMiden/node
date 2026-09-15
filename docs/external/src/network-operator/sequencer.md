---
title: "Sequencer"
sidebar_position: 4
---

# Sequencer

The sequencer is centralized network infrastructure operated by the network operator. It runs `miden-node sequencer`,
produces blocks, serves public RPC, and connects to the validator and network transaction builder.

## Start

```bash
miden-node sequencer \
  --rpc.listen 0.0.0.0:57291 \
  --data-directory node-data \
  --validator.url http://validator-1:50101 \
  --validator.url http://validator-2:50101 \
  --validator.url http://validator-3:50101 \
  --ntx-builder.url http://ntx-builder:50301 \
  --rpc.network-tx-auth-header-value <network-tx-auth-secret>
```

Only the public RPC listener should be externally reachable. The validator, NTX builder, and prover URLs are trusted
internal services.

The network transaction auth value is a shared secret used to authorize network transaction submissions. It must match
the NTX builder's `--rpc.auth-header-value`; otherwise, the sequencer rejects network transactions from the builder.

## RPC Source

The sequencer implements the full RPC API and can act as an RPC source. This is useful for networks without full nodes,
for routing excess RPC load to the sequencer when it has spare capacity, or as a fallback if the available full node
capacity fails.

For larger deployments, prefer serving public RPC through full nodes so the sequencer can focus on block production.

## Allowlist Administration

The sequencer can serve a private JSON administration API. The listener is disabled by default. Configure its address to
enable it:

```bash
--admin.listen 127.0.0.1:50100
```

The corresponding environment variable is `MIDEN_NODE_ADMIN_LISTEN`. The API does not authenticate requests. Enforce
authentication and authorization externally, and prevent direct access to this listener. Keep it on an isolated operator
network behind an authenticated proxy or gateway. The listener serves HTTP; terminate TLS at the proxy for remote
access. Do not expose it through the public RPC ingress.

| Method | Path                                               | Request body                                | Result                                                                                                        |
| ------ | -------------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `PUT`  | `/admin/allowlist/invitations/{invitation_digest}` | `{}` or `{"account_id":"<hex-account-id>"}` | `201` for a new invitation, `204` for an existing invitation. The optional account ID binds it to an account. |
| `GET`  | `/admin/allowlist/invitations/{invitation_digest}` | None                                        | Registration status, optional `account_id`, and optional `allowlisted_at`.                                    |
| `PUT`  | `/admin/allowlist/accounts/{account_id}`           | None                                        | `201` for a new registration, `204` if already registered. Adds the account without consuming an invitation.  |
| `GET`  | `/admin/allowlist/accounts/{account_id}`           | None                                        | `account_id` and `allowlisted_at`, or `404` if not registered.                                                |

Compute `invitation_digest` as SHA-256 of the exact invitation code bytes. For text codes, use UTF-8 without a trailing
newline or other normalization. Encode the digest as 64 hexadecimal characters without a `0x` prefix. The API stores
this digest directly and does not hash it again. Generate nonempty random codes with enough entropy to resist guessing.
Give the original code to the recipient. The administration API never receives or returns the original code.

Invitation status is `unknown`, `unused`, or `registered`. The response has `account_id` and `allowlisted_at` fields. An
unknown invitation has `null` in both fields. Both status responses use `allowlisted_at` to record when the entry was
added to the allowlist in UTC Unix seconds. Registration and retries do not change this timestamp. It does not record
on-chain account creation.

Invalid digests or account IDs return `400`, invalid JSON shapes return `422`, and registration conflicts return `409`.
Each request changes one entry. To import multiple entries, send one request per entry. Identical retries succeed
without replacing registrations. An invitation `PUT` without an account preserves its current registration.

The registry is stored in `miden-allowlist.sqlite3`, separately from the block database. Chain bootstrap does not create
it. Starting the sequencer administration API creates an empty registry if none exists, including when promoting an
existing full node. Existing registries are loaded without replacing their entries. Startup does not apply migrations.
`miden-node migrate --data-directory node-data` applies allowlist migrations only if the registry exists.

Back up the registry separately. It is not replicated with blocks. Restore it before starting a replacement sequencer to
preserve invitations and registrations. Without a restored registry, the replacement starts with an empty allowlist.

## Failover

Full nodes replicate the committed sequencer state from their upstream block source. Because of this, a full node can be
promoted to sequencer if the active sequencer needs to be replaced.

The promotion target must be in sync with the current sequencer state. A full node that is behind the sequencer is not a
valid replacement until it has caught up to the committed chain tip.

There is always some risk of data loss during failover because full nodes follow the sequencer asynchronously. Blocks
committed by the sequencer but not yet replicated to the promoted full node may be missing from that node's local state.
The validator also retains a copy of the blocks it validated and signed, and can be used to recover missing committed
block data when this occurs. See [Recovery](/network-operator/recovery) for the procedure.

## Common Configuration

| Option                               | Purpose                                                |
| ------------------------------------ | ------------------------------------------------------ |
| `--rpc.listen`                       | Public RPC socket exposed by the sequencer.            |
| `--rpc.network-tx-auth-header-value` | Shared secret for authorized network transaction flow. |
| `--validator.url`                    | Internal validator service URLs (one per validator).   |
| `--ntx-builder.url`                  | Internal network transaction builder service URL.      |
| `--batch.interval`                   | Maximum interval between batch scheduler checks.       |
| `--block.interval`                   | Block production interval.                             |

Use `miden-node sequencer --help` for the complete current option list.
