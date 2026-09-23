---
title: "Sequencer"
sidebar_position: 4
---

# Sequencer

The sequencer is centralized network infrastructure operated by the network operator. It runs `miden-node sequencer`,
produces blocks, serves public RPC, and connects to the validator and network transaction builder.

## Fee Collection

The sequencer uses a dedicated immutable fee collector account to send transaction fees to the batch builder's wallet
account. The fee collector transforms the fees into a single P2ID note targeting the wallet account.

This process will need to change when we support fees paid in non-native tokens. For now, it provides a simple way to
collect fees while avoiding race conditions on the receiving wallet account.

The fee collector account must be created and deployed before the sequencer can start. Use
`miden-node fee-collector create` to create the account and `miden-node fee-collector deploy` to deploy it. Deployment
creates a dedicated block and therefore the validators must be running to sign this block.

The collector account is fairly low-risk. It only needs to exist and is immutable once deployed. Keep the generated
signing key to authorize transactions. A new collector can be trivially created and redeployed so backup isn't a strong
requirement.

## Start

```bash
miden-node sequencer \
  --rpc.listen 0.0.0.0:57291 \
  --data-directory node-data \
  --validator.url http://validator-1:50101 \
  --validator.url http://validator-2:50101 \
  --validator.url http://validator-3:50101 \
  --ntx-builder.url http://ntx-builder:50301 \
  --batch.builder.wallet-account-id <wallet-account-id> \
  --rpc.network-tx-auth-header-value <network-tx-auth-secret>
```

Only the public RPC listener should be externally reachable. The validator, NTX builder, and prover URLs are trusted
internal services.

The wallet account receives batch-building fees. The sequencer needs only its ID, not its signing key. The sequencer
loads its deployed collection account from the account file. The wallet's P2ID notes remain unspent until a separate
service collects them.

The network transaction auth value is a shared secret used to authorize network transaction submissions. It must match
the NTX builder's `--rpc.auth-header-value`; otherwise, the sequencer rejects network transactions from the builder.

## RPC Source

The sequencer implements the full RPC API and can act as an RPC source. This is useful for networks without full nodes,
for routing excess RPC load to the sequencer when it has spare capacity, or as a fallback if the available full node
capacity fails.

For larger deployments, prefer serving public RPC through full nodes so the sequencer can focus on block production.

## Allowlist Administration

The sequencer checks new, non-network accounts against the allowlist on both public and internal submission APIs.
Existing-account transactions and network-account creation do not require registration.

For development networks, use `--disable-account-allowlist` or set `MIDEN_NODE_DISABLE_ACCOUNT_ALLOWLIST=true` to allow
unrestricted account creation. Enforcement is enabled by default. When enforcement is disabled, `RegisterAccount`
accepts any invitation code, including an empty code. It adds the account directly to the registry without storing or
consuming the code. New registrations still request funding if configured. The administration API remains available.

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

Compute `invitation_digest` as SHA-256 of the invitation code's exact UTF-8 representation. Do not trim the code, add a
newline, or normalize the text. Encode the digest as 64 hexadecimal characters without a `0x` prefix. The API stores
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
it. Starting the sequencer creates an empty registry if none exists, including when promoting an existing full node.
Existing registries are loaded without replacing their entries. Startup does not apply migrations.
`miden-node migrate --data-directory node-data` applies allowlist migrations only if the registry exists.

The public `RegisterAccount` RPC uses this registry even when the administration listener is disabled. When allowlist
enforcement is enabled, it binds an unused invitation to an account. See
[Account Registration](../rpc/public-api.md#account-registration) for the request and retry behavior.

Back up the registry separately. It is not replicated with blocks. Restore it before starting a replacement sequencer to
preserve invitations and registrations. Without a restored registry, the replacement starts with an empty allowlist.

### Admin CLI

Use `miden-node admin` to call the private administration API. Set its base URL with `--url` or `MIDEN_NODE_ADMIN_URL`.
The CLI does not need the sequencer's data directory.

Create 100 invitation codes and save them to a new CSV file:

```bash
miden-node admin --url http://127.0.0.1:50100 create-invites \
  --count 100 --output invitations.csv
```

Each code contains 12 random ASCII alphanumeric characters (`A-Z`, `a-z`, and `0-9`). Codes are unique within the
generated batch. The CSV has one column, `invitation_code`, with the original codes to give to users. Only SHA-256
digests are sent to the admin API. Treat the CSV as a secret. The CLI creates it with owner-only permissions on Unix and
refuses to replace an existing file.

The CLI saves the complete CSV before the first upload. If an upload fails, the command exits with an error and reports
the failed row. The CSV remains available, but some codes may not be registered. Earlier successful uploads remain in
the registry. Verify invitation status before distributing codes from a failed upload.

Allowlist an account without an invitation code:

```bash
miden-node admin --url http://127.0.0.1:50100 allowlist-account <hex-account-id>
```

The command uses the account `PUT` endpoint and inherits its funding behavior when funding is configured.

## Registration Funding

Configure both options to request funding for each new account registration:

```bash
--funding-service.url http://funding-service:50401 \
--funding-service.amount 1000000
```

The amount is a positive number of native-asset base units. The corresponding environment variables are
`MIDEN_NODE_FUNDING_SERVICE_URL` and `MIDEN_NODE_FUNDING_SERVICE_AMOUNT`. Funding is disabled when both options are
absent. Keep the funding service on the operator network. It does not authenticate requests.

The sequencer sends `POST /request-funds` to the service for each new registration through `RegisterAccount` or the
administration API. This includes an admin binding an existing invitation to an account. The sequencer commits the
registration before it requests funding, then waits for the funding response. Repeated registration requests do not
request more funds. Existing registrations are not funded at startup. Disabling allowlist enforcement does not disable
funding for accounts that register.

The service creates a public P2ID note. The account owner can retrieve it through the account's note tag after the note
commits. The registration response does not include the note.

Funding failures return gRPC `UNAVAILABLE` or HTTP `503`. They do not undo registration. Requests are not retried or
persisted. Repeating registration after a funding failure does not make another funding request. Operators can use the
funding service directly to fund an account after a failed or interrupted request.

## Failover

Full nodes replicate the committed sequencer state from their upstream block source. Because of this, a full node can be
promoted to sequencer if the active sequencer needs to be replaced.

The promotion target must be in sync with the current sequencer state. A full node that is behind the sequencer is not a
valid replacement until it has caught up to the committed chain tip.

There is always some risk of data loss during failover because full nodes follow the sequencer asynchronously. Blocks
committed by the sequencer but not yet replicated to the promoted full node may be missing from that node's local state.
The validator also retains a copy of the blocks it validated and signed, and can be used to recover missing committed
block data when this occurs. See [Recovery](/network-operator/recovery) for the procedure.

### Fee Collector Account

Copy the existing `fee-collector.mac` file to the replacement node's data directory before starting it as a sequencer.
This file contains the collector's signing key and is not replicated with chain state. The account is already deployed
and does not need to be deployed again.

If the file is lost, complete chain recovery, then create and deploy a new collector with the same
[Fee Collection](#fee-collection) procedure. Keep the replacement node stopped until deployment completes.

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
