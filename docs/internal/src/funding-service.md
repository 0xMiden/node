# Funding Service Component

The operator documentation covers the configuration and the API. This page covers the design.

## The funding account

The service owns one wallet account. The account is created at genesis from a named `[[wallet]]` entry, which prefunds it and writes its account file to a fixed path.

The account is public, and the service stores no account state of its own. It reads the account from the node before every transaction and holds only the account ID, the signing key, and the code commitment from the account file. The node stores the full state of a public account, which makes that read possible.

This removes a class of failure which a service holding its own copy of the account would have. If a service crashes between submitting a transaction and seeing it commit, its copy of the account is behind the chain, and every later transaction it builds is rejected for a stale nonce until it re-synchronizes. Reading the account each time means there is no local copy to fall behind.

## The request handler builds the note

The HTTP handler builds the public pay-to-ID note itself. A note needs only the sender, the target, the asset and a serial number, none of which depend on the chain, so the handler needs no call to the node. It answers with the note and puts it on the worker's queue.

The answer is therefore optimistic: it names a note which no transaction has created yet. A requester which needs the note on chain either waits for it at the node or consumes it as an unauthenticated input note, which the node authenticates when it builds the block.

The service keeps accepted requests and pending transactions in memory. A restart can lose an accepted request before its transaction reaches the node. Accepted requests do not have a durable delivery guarantee.

## One worker, one transaction in flight

A single worker owns the account. It keeps at most one batch of requests outside the bounded request channel. The batch contains at most `--max-notes-per-tx` notes. Requests stay in the channel while the batch is full or a transaction remains pending. A full channel causes the HTTP handler to return 429.

The worker waits for a request, a deposit scan deadline, or a transaction poll deadline. It processes work in this order:

1. If a transaction is pending, read the account and resolve that transaction. Do not prepare another transaction while its outcome is unknown.
2. Otherwise, scan for deposits when the scan interval is due and fill the active batch from the request channel.
3. Read the chain state and remove spent deposits. Select deposits and affordable payouts, then execute and prove one transaction.
4. Record its ID, account nonce, expiration block, and selected notes before submitting it to the node.
5. Wait for commitment or expiration, regardless of the submission response.

A submission error can occur after the node accepts a transaction. The worker treats every submission error as an unknown outcome and keeps the transaction pending until the chain resolves it. The account has one writer, so a higher nonce means the transaction committed. If the nonce has not changed at the expiration block, the worker can retry its notes in a new transaction. The notes keep their IDs across retries. A failed RPC submission also clears the cached encryption key so the next submission fetches a fresh key.

### Deposits and payouts in one transaction

The worker selects deposits and queued funding notes together. It uses the account balance plus the selected deposits to admit payouts. A transaction can consume deposits, create funding notes, or do both. The worker also takes queued requests when a scan finds deposits, up to the batch limit.

Input assets enter the vault before the transaction creates funding notes and the kernel withdraws the fee. Deposits can therefore fund payouts and the fee in the same transaction when the account balance is zero. The combined transaction pays one fee.

### The fee faucet is a foreign account

The native asset is callback-enabled: the kernel loads the issuing faucet in a foreign context whenever the asset enters or leaves a vault. Every funding transaction moves the asset, so the faucet must be in the transaction's data store together with its account-tree witness at the reference block. This holds even on a chain which does not charge fees, because the callback belongs to the asset and not to the fee.

## Admission

The worker adds the selected deposits to the account balance and holds back the worst-case fee of one transaction. It then admits queued notes in order and stops at the first note which does not fit, which keeps the queue first-come-first-served and stops a stream of small notes from starving a large one.

A note which does not fit stays in the active batch. The worker polls the balance while that batch waits for funds. It can fill unused space in the batch from the request channel while no transaction is pending. Deposit scans continue on their own interval.

The handler checks the amount against the balance the service last read, and refuses a request the account plainly cannot serve. That check is best effort: the balance is the one of an earlier block and does not account for the notes already queued.

## Deposits

A deposit is found by synchronizing notes by the funding account's tag. A filter keeps only the notes the account can consume: public, pay-to-ID, targeting the funding account, and holding the native asset and nothing else.

The worker indexes deposits by nullifier. Multiple records for the same deposit enter the pool only once. The nullifier scan starts at genesis because a repeated note can have a nullifier spent before the current scan range. The worker checks the pool for spent deposits again before collection.

The scan cursor advances only after note retrieval and nullifier checks succeed. A failed scan retries the same range. Successful scans add deposits to the pool even if no collection is ready. A restart scans from genesis to find unspent deposits again.

One transaction consumes at most a fixed number of deposits, and takes the largest ones first. The protocol allows far more input notes than that; the bound is proving time, because every input note runs its own script and lengthens the transaction the service has to prove before it can serve the next one.

A transaction which only consumes deposits is submitted only when the deposits are worth more than the fee. Anyone can send a note which holds a single base unit, and consuming it on its own would cost the account more than it brings in.
