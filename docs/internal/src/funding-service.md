# Funding Service Component

The operator documentation covers the configuration and the API. This page covers the design.

## The funding account

The service owns one wallet account. The account is created at genesis from a named `[[wallet]]` entry, which prefunds it and writes its account file to a fixed path.

The account is public, and the service stores no account state of its own. It reads the account from the node before every transaction and holds only the account ID, the signing key, and the code commitment from the account file. The node stores the full state of a public account, which makes that read possible.

This removes a class of failure which a service holding its own copy of the account would have. If a service crashes between submitting a transaction and seeing it commit, its copy of the account is behind the chain, and every later transaction it builds is rejected for a stale nonce until it re-synchronizes. Reading the account each time means there is no local copy to fall behind.

## One worker, one transaction in flight

A single task owns the account and the requests. The gRPC handler validates the amount, puts the request on a queue, and waits for the worker's answer.

The worker therefore keeps one transaction in flight and collects every request which arrives in the meantime into the next transaction. A client which tops up several accounts at once pays for one transaction rather than one per account, which is what makes the service usable from a test suite.

Each batch runs the following steps.

1. Read the chain tip and a partial blockchain which proves it. This is the transaction's reference block.
2. Read the funding account and the fee faucet at that block.
3. Decide which queued requests the balance covers.
4. Build one private pay-to-ID note per admitted request.
5. Execute, prove, and submit one transaction which creates all of them.
6. Poll the node until every note is committed, then answer each requester with its note.

### The fee faucet is a foreign account

The native asset is callback-enabled: the kernel loads the issuing faucet in a foreign context whenever the asset enters or leaves a vault. Every funding transaction moves the asset, so the faucet must be in the transaction's data store together with its account-tree witness at the reference block. This holds even on a chain which does not charge fees, because the callback belongs to the asset and not to the fee.

## Admission

The transaction pays its own fee from the same vault the notes are paid from, so the worker holds back the worst-case fee of one transaction before it spends the balance. It then admits queued requests in order and stops at the first request which does not fit, which keeps the queue first-come-first-served and stops a stream of small requests from starving a large one. A request which does not fit is refused at once, and the requester is told that the account needs funds rather than being made to wait.

## Private notes

The notes are private, so their details never reach the node. The response therefore carries the note in full, and it is the only copy: a client which loses the response cannot recover the funds. This is also why the worker skips a request whose requester has gone away. Creating the note anyway would move funds into a note nobody holds the details of, and those funds could not be recovered.
