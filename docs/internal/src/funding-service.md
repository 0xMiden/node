# Funding Service Component

The operator documentation covers the configuration and the API. This page covers the design.

## The funding account

The service owns one wallet account. The account is created at genesis from a named `[[wallet]]` entry, which prefunds it and writes its account file to a fixed path.

The account is public, and the service stores no account state of its own. It reads the account from the node before every transaction and holds only the account ID, the signing key, and the code commitment from the account file. The node stores the full state of a public account, which makes that read possible.

This removes a class of failure which a service holding its own copy of the account would have. If a service crashes between submitting a transaction and seeing it commit, its copy of the account is behind the chain, and every later transaction it builds is rejected for a stale nonce until it re-synchronizes. Reading the account each time means there is no local copy to fall behind.

## The request handler builds the note

The HTTP handler builds the public pay-to-ID note itself. A note needs only the sender, the target, the asset and a serial number, none of which depend on the chain, so the handler needs no call to the node. It answers with the note and puts it on the worker's queue.

The answer is therefore optimistic: it names a note which no transaction has created yet. A requester which needs the note on chain either waits for it at the node or consumes it as an unauthenticated input note, which the node authenticates when it builds the block.

The alternative, waiting until the note commits, costs at least one block interval per request and gives a requester no way to be told about a retry. The service now funds user accounts at registration, where that cost is not acceptable.

## One worker, one transaction in flight

A single task owns the account. It is the only writer of that account, which is what serializes its transactions.

The worker wakes when a note is queued and on its own interval. One cycle runs the following steps.

1. Do nothing when there is no transaction in flight, nothing queued, no deposit pooled, and no scan due. An idle service therefore makes no call to the node beyond the status refresher's own.
2. Read the chain tip and a partial blockchain which proves it, then the funding account and the fee faucet at that block. Every value of the cycle comes from this one reference block.
3. Resolve the transaction in flight. The account has one writer, so a nonce higher than the one the transaction was built on means it committed. A reference block at or past the expiration block means it did not, and its deposits and notes return to the queues.
4. Scan for deposits when the scan interval has passed.
5. Select the deposits and the notes of the next transaction.
6. Execute, prove and submit one transaction which consumes the deposits and creates the notes. Anything which fails returns the deposits and the notes to the queues, and the next cycle tries again from a fresh reference block.

A note keeps its serial number across a retry, so it keeps its ID. The note a requester holds is the note which is eventually created.

### One transaction carries both directions

The deposits and the funding notes share one transaction. Two tasks submitting from the same account would race for the nonce, and the loser's transaction would be rejected.

The assets of an input note land in the vault before the kernel withdraws the fee. A deposit therefore pays for the notes of the same transaction, and a transaction which only consumes deposits works at a zero balance, which is the state a deposit exists to recover from.

### The fee faucet is a foreign account

The native asset is callback-enabled: the kernel loads the issuing faucet in a foreign context whenever the asset enters or leaves a vault. Every funding transaction moves the asset, so the faucet must be in the transaction's data store together with its account-tree witness at the reference block. This holds even on a chain which does not charge fees, because the callback belongs to the asset and not to the fee.

## Admission

The transaction pays its own fee from the same vault the notes are paid from, so the worker holds back the worst-case fee of one transaction before it spends the balance. It then admits queued notes in order and stops at the first note which does not fit, which keeps the queue first-come-first-served and stops a stream of small notes from starving a large one.

A note which does not fit stays in the queue. The service already answered a requester with it, so it is created once a deposit raises the balance rather than being dropped. The worker logs a warning and waits out the deposit scan interval before it reads the chain state again, because only a deposit changes the answer.

The handler checks the amount against the balance the service last read, and refuses a request the account plainly cannot serve. That check is best effort: the balance is the one of an earlier block and does not account for the notes already queued.

## Deposits

A deposit is found by synchronizing notes by the funding account's tag. A filter keeps only the notes the account can consume: public, pay-to-ID, targeting the funding account, and holding the native asset and nothing else.

The scan ends at the reference block of the cycle, which is also the reference block of the next transaction. Every deposit the scan returns therefore exists and is unspent at the block the transaction is built against. The node answers a range in pages, and the scan reads every page up to that block, so a restart catches up in one scan.

A deposit which the chain already records as spent is dropped, because a transaction which consumes a spent note is rejected. The nullifier scan covers the same range as the note scan, since a note cannot be spent before it exists.

The scan cursor advances only after every request of the scan succeeds, so a failed scan covers the same range again. A successful scan advances the cursor whether or not the worker consumes what it found. A deposit stays in the pool until it is spent, and a transaction which does not commit returns its deposits there, so no range has to be scanned twice. The pool is in memory, so a restart scans the chain again from genesis and finds whatever is still unspent.

One transaction consumes at most a fixed number of deposits, and takes the largest ones first. The protocol allows far more input notes than that; the bound is proving time, because every input note runs its own script and lengthens the transaction the service has to prove before it can serve the next one.

A transaction which only consumes deposits is submitted only when the deposits are worth more than the fee. Anyone can send a note which holds a single base unit, and consuming it on its own would cost the account more than it brings in.
