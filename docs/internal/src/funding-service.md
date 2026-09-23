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

The worker records the committed chain tip at startup. It scans every note page from genesis through that fixed tip before it processes requests. Failed pages are retried without advancing the cursor. The worker then repeats these steps in order:

1. Wait for the poll interval. Scan for new deposits if the scan interval has elapsed.
2. Fill the active batch from the request channel.
3. Read the chain state. Select at most one deposit and affordable payouts, then execute and prove one transaction.
4. Submit the transaction. Handle node rejections immediately. For accepted transactions or uncertain transport failures, poll `SyncTransactions` until commitment or expiration.
5. On commitment, remove the selected deposit and the queued payout prefix. On expiration, retain the notes for retry.

A node rejection means that the transaction was not submitted. A rejection with state-conflict error byte `2` discards the selected deposit and retains all payouts. Other rejections retain all notes for retry. A transport failure can leave the outcome unknown, so the worker waits for commitment or expiration before it prepares another transaction. Failed transaction polls are retried within that wait. Each poll checks every page in the block range before it reports expiration. The worker reads the full account state only when it prepares a transaction.

Selected notes stay in the deposit pool and request batch while the outcome is unknown. Preparation failures and expiration leave those notes available for retry. The output notes keep their IDs across retries. A failed RPC submission clears the cached encryption key so the next submission fetches a fresh key.

### Deposits and payouts in one transaction

The worker selects at most one deposit and queued funding notes together. It uses the account balance plus that deposit to admit payouts. A transaction can consume a deposit, create funding notes, or do both. The worker also takes queued requests when a scan finds deposits, up to the batch limit.

Input assets enter the vault before the transaction creates funding notes and the kernel withdraws the fee. Deposits can therefore fund payouts and the fee in the same transaction when the account balance is zero. The combined transaction pays one fee.

### The fee faucet is a foreign account

The native asset is callback-enabled: the kernel loads the issuing faucet in a foreign context whenever the asset enters or leaves a vault. Every funding transaction moves the asset, so the faucet must be in the transaction's data store together with its account-tree witness at the reference block. This holds even on a chain which does not charge fees, because the callback belongs to the asset and not to the fee.

## Admission

The worker adds the selected deposit to the account balance and holds back the worst-case fee of one transaction. It then admits queued notes in order and stops at the first note which does not fit, which keeps the queue first-come-first-served and stops a stream of small notes from starving a large one.

A note which does not fit stays in the active batch. The worker polls the balance while that batch waits for funds. It can fill unused space in the batch from the request channel while no transaction is pending. Deposit scans continue on their own interval.

The handler checks the amount against the balance the service last read, and refuses a request the account plainly cannot serve. That check is best effort: the balance is the one of an earlier block and does not account for the notes already queued.

## Deposits

A deposit is found by synchronizing notes by the funding account's tag. A filter keeps only the notes the account can consume: public, pay-to-ID, targeting the funding account, and holding the native asset and nothing else.

The worker indexes deposits by nullifier. Duplicate deposits in the pool occupy one entry. At startup, it collects all deposits through a fixed chain tip, then checks the recovered pool against the nullifier history. The nullifier lookup follows every response page and filters prefix matches by the exact nullifier. Spent deposits are discarded before the worker processes funding requests.

The scan cursor advances after note retrieval succeeds. A failed note page retries the same range. A failed startup nullifier check retries against the recovered pool without scanning the notes again. Periodic scans capture a new target tip and resume from the saved cursor. Each restart scans from genesis to recover unspent deposits, including those created while the service was stopped.

Periodic scans do not check nullifiers. A note ID can appear on chain again after the note was spent. The worker expects the node to reject this transaction with `INVALID_ARGUMENT` and error byte `2`. The transaction has at most one deposit, so the worker discards that deposit and retains the payouts. This relies on one writer for the funding account and outputs constructed by the service. P2ID deposits have no reclaim path.

One transaction consumes at most one deposit. The worker selects the largest available deposit.

A transaction which only consumes deposits is submitted only when the deposits are worth more than the fee. Anyone can send a note which holds a single base unit, and consuming it on its own would cost the account more than it brings in.
