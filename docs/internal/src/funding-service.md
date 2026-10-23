# Funding Service Component

The [operator documentation](https://github.com/0xMiden/node/blob/next/docs/external/src/network-operator/funding-service.md) covers configuration and the API. This page covers request persistence, transaction recovery, and wallet synchronization.

## The funding account

The service owns one public wallet account provisioned at genesis. Bootstrap records its account ID, the genesis commitment, and the native asset in SQLite. Startup checks the database's network identity against the connected node and verifies that the supplied signing key matches the account.

The account is public, so the node serves its full state. A long-lived funding wallet holds the account state, signing key, unspent deposits, and synchronization progress in memory. The worker synchronizes it to the transaction's reference block before preparing a transaction.

Startup loads the account state from the node and reads the signing key from its standalone serialized file. The initial balance, block, and fee are published before the HTTP server starts. Synchronization progress and deposits are not persisted; after resolving any unfinished transaction, the worker scans from genesis to recover unspent deposits before preparing another transaction.

## Durable request acceptance

The HTTP handler validates the target and amount against its configured limits and the last published balance and fee. It draws a serial number and passes the target, amount, and serial number to the database. The database builds a public pay-to-ID note and commits the request before the handler returns HTTP 200 with the serialized note. Acceptance requires no call to the node.

Each request stores its note ID, target, amount, serial number, acceptance sequence, and acceptance time. The sender and asset are shared by every request and come from the database identity. Creation and reads use the same note constructor, with the standard P2ID script, zero salt, and no attachments. The database accepts these request fields rather than arbitrary notes, so it cannot accept a salt or attachment that would be lost on reconstruction.

Writes use the local database crate's single SQLite writer; readers can run concurrently through WAL. Retrying the same target, amount, and serial number returns the original request, preserving its acceptance order, time, and delivery record. HTTP retries draw a new serial number and therefore create another request. A timed-out handler can still finish its database write, so a timeout does not establish whether the request was accepted.

The returned note is created on chain asynchronously. Accepted requests survive restarts and remain pending until delivery is recorded, providing at-least-once delivery while the account has sufficient funds and the node is available. Confirmed requests remain in the database for auditing, with the transaction ID, commitment block, and local confirmation time, and are excluded from later batches. Acceptance and confirmation times use microseconds since the Unix epoch in SQLite and `SystemTime` in Rust.

The backlog has no configured capacity limit. Requests wait for their database writes and are subject to the HTTP timeout. A requester that needs the note on chain can wait for it at the node or consume it as an unauthenticated input note, which the node authenticates when it builds the block.

## One worker, one transaction in flight

A single worker owns the account and submits one transaction at a time. It loads at most `--max-notes-per-tx` pending requests in acceptance order. Other requests stay in SQLite, and handlers can continue accepting requests while a transaction is in progress.

The worker checks for work immediately on startup and waits `--poll-interval` between attempts. If an unfinished transaction is recorded, it resolves that attempt before the next check. Otherwise, it follows these steps:

1. Load the oldest pending requests. Read the chain state and sync the wallet, including deposit discovery and spent-note checks, then publish the synchronized balance and fee.
2. Select at most one deposit and an affordable prefix of requests, then execute and prove the transaction.
3. Record the transaction attempt and link its requests in one database transaction before submitting it to the node.
4. Resolve the outcome. On commitment, record delivery and remove the attempt atomically. On rejection or expiration, remove the attempt and leave its requests pending for retry.

### Recovering an unfinished transaction

The database holds at most one transaction attempt. It records the transaction ID, reference and expiration blocks, the selected deposit's nullifier if any, and links to its funding requests. Requests linked to an attempt are excluded from pending batches until that attempt is resolved.

The transaction payload is not retained. After a restart or an uncertain submission result, the worker polls `SyncTransactions` for the recorded ID. Each poll checks every page from the block after the reference block through the earlier of the current tip and expiration block. It reports expiration only after checking that range for commitment. RPC failures delay resolution; they do not release requests for retry.

A known commitment is kept in memory while its delivery write is retried. The worker does not start another transaction until that write succeeds. Recording delivery and removing the attempt share a database transaction, so a restart cannot leave a partially recorded batch.

A crash after recording an attempt but before submission can delay its requests until expiration, because recovery cannot rebroadcast the transaction. Errors known to occur before submission, such as failure to fetch the encryption key or seal the inputs, release the attempt immediately. A definite node rejection also releases it. A state-conflict rejection with error byte `2` discards the selected deposit and retains all payouts. A failed RPC submission clears the cached encryption key for the next submission.

Preparation failures, rejections, and expiration preserve each request's note ID across retries. Once an attempt is resolved, the worker synchronizes the wallet before preparing the next transaction.

### Deposits and payouts in one transaction

The worker selects at most one deposit and pending funding notes together. It uses the account balance plus that deposit to admit payouts. A transaction can consume a deposit, create funding notes, or do both.

Input assets enter the vault before the transaction creates funding notes and the kernel withdraws the fee. Deposits can therefore fund payouts and the fee in the same transaction when the account balance is zero. The combined transaction pays one fee.

### The fee faucet is a foreign account

The native asset is callback-enabled: the kernel loads the issuing faucet in a foreign context whenever the asset enters or leaves a vault. Every funding transaction moves the asset, so the faucet must be in the transaction's data store together with its account-tree witness at the reference block. This holds even on a chain which does not charge fees, because the callback belongs to the asset and not to the fee.

## Admission

The worker adds the selected deposit to the account balance and holds back the worst-case fee of one transaction. It then admits queued notes in order and stops at the first note which does not fit, which keeps the queue first-come-first-served and stops a stream of small notes from starving a large one.

A note which does not fit remains pending in SQLite. The next attempt reloads pending requests in acceptance order and refreshes the balance and deposits before selecting payouts. Requests that arrive during an attempt are considered on a later attempt.

The handler checks the amount against the balance the service last read, and refuses a request the account plainly cannot serve. That check is best effort: the balance is the one of an earlier block and does not account for the notes already queued.

## Deposits

A deposit is found by synchronizing notes by the funding account's tag. A filter keeps only the notes the account can consume: public, pay-to-ID, targeting the funding account, and holding the native asset and nothing else.

The worker indexes deposits by nullifier. Duplicate deposits in the pool occupy one entry. At startup, it collects all deposits through a fixed chain tip, then checks the recovered pool against the nullifier history. The nullifier lookup follows every response page and filters prefix matches by the exact nullifier. Spent deposits are discarded before the worker processes funding requests.

Each sync discovers deposits and checks spent notes from the block after the last successfully applied update through its reference block. The pagination cursor and discovered notes remain local until synchronization succeeds. The worker then applies the account state, unspent deposits, and reference block together. Failure or cancellation leaves the wallet unchanged; the next attempt repeats the range. Each restart scans from genesis to recover unspent deposits, including those created while the service was stopped.

Subsequent syncs check nullifiers only in the new block range. A note ID can appear on chain again after the note was spent in an earlier block. The worker expects the node to reject this transaction with `INVALID_ARGUMENT` and error byte `2`. The transaction has at most one deposit, so the worker discards that deposit and retains the payouts. This relies on one writer for the funding account and outputs constructed by the service. P2ID deposits have no reclaim path.

One transaction consumes at most one deposit. The worker selects the largest available deposit.

A transaction which only consumes deposits is submitted only when the deposits are worth more than the fee. Anyone can send a note which holds a single base unit, and consuming it on its own would cost the account more than it brings in.
