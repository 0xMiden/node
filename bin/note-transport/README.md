# Miden note transport

The note transport service stores private note envelopes for recipients that poll by note tag. It is part of the Miden
node workspace and uses the workspace license.

## API

The public `note_transport.Api` service is defined in the workspace protobuf crate. It supports `SendNote`,
`SendNoteWithProof`, and `FetchNotes` over gRPC and gRPC-Web. Standard gRPC health and reflection are available on the
same listener. There are no note subscriptions or statistics RPCs.

### Sending notes

`SendNote` accepts a `SendNoteRequest` whose `note` field contains a `TransportNote` with the shared protocol note
header and note details. It returns an empty `SendNoteResponse`. The service checks that the details commitment matches
the header. The optional `SendNoteRequest.after_block_num` gives recipients a lower bound for their chain scan. The
service stores this hint without chain lookup; an absent hint differs from block zero.

`SendNoteWithProof` requires a `TransportNote` and a `NoteInclusionProof`. It checks the note ID, the proof path, and
the referenced block's note root before storage. This request has no block hint. The service stores the exact inclusion
block but does not store the proof. This method also returns an empty `SendNoteResponse`.

The service caches up to 1,024 note root commitments from the trusted node, keyed by block number. The cache evicts the
least recently used entry when full. Failed lookups and invalid headers are not cached. Each submission still verifies
its inclusion proof against the note root, including cache hits.

Uncached header lookups make up to three attempts for `UNAVAILABLE`, `DEADLINE_EXCEEDED`, or `RESOURCE_EXHAUSTED`
responses. Attempts use short exponential backoff and individual timeouts. All attempts and delays share half of the
configured gRPC timeout: 5 seconds with the default 10-second timeout. Missing blocks and invalid headers are not
retried.

A retry with the same note ID succeeds and keeps the first envelope, timestamp, and cursor. This also applies when the
`SendNote` retry supplies a different block hint or storage is full. `SendNoteWithProof` validates the proof on every
request, including duplicates. A valid retry through either method keeps the first envelope. In particular, a verified
retry does not replace a hint previously stored by `SendNote`.

### Fetching notes

`FetchNotes` returns `FetchedNote` records with the header, details, and two optional block fields. `after_block_num`
contains the unverified lower bound from `SendNote`. `included_in_block` contains the exact block verified through
`SendNoteWithProof`. At most one field is present. An absent block differs from block zero.

`FetchNotes` accepts at most 128 tags and an exclusive cursor with a `fixed64` database nonce and a `fixed64` sequence.
Omit the cursor to start from the first retained note. Store the complete response cursor and use it for the next
request with the same set of tags. Results follow insertion order across all requested tags. Duplicate tags do not
duplicate results. Every successful response includes a cursor. An initial empty page returns the current nonce and
sequence zero. Later empty pages retain the request cursor. The response `has_more` field indicates that another page is
available. Nonce zero is valid and has no special meaning.

A cursor belongs to the requested set of tags. Clear the cursor when you add or remove tags. Reordering tags or changing
duplicate tags does not change the set. Restarting a fetch from the beginning can return notes that you fetched before.
Use note IDs to remove duplicate results.

For example, after you fetch tag A through cursor 100, clear the cursor when you add tag B. If you reuse cursor 100, you
skip retained notes for tag B with cursors at or below 100.

A page contains at most 500 notes and 3 MiB of canonically serialized header and detail bytes. The encoded response also
fits the default 4 MiB gRPC client limit. The default per-note limit is 512,000 bytes. `--max-note-size` can change it
up to the page limit. The required `--max-storage-bytes` limits retained header and detail bytes. It does not include
SQLite indexes, database metadata, or WAL disk usage. Cursor sequences use the positive signed 64-bit range supported by
SQLite. Sequence zero starts a fetch. Nonces use the complete unsigned 64-bit range. Recipients must poll before notes
expire.

The service generates a random nonce when it creates the database. Schema migration initializes the nonce for existing
databases. Ordinary service restarts, repeated migrations, and retention cleanup preserve the nonce. A cursor from a
different database generation returns `FAILED_PRECONDITION`. Clear the cursor and fetch again after this error.
Deduplicate results by note ID. The nonce detects a generation change; it does not recover lost notes or authenticate
cursors.

The structured cursor is incompatible with the scalar cursor API. Coordinate client and server upgrades. Discard
persisted scalar cursors when upgrading clients. Run the database migration before starting the updated service.
Restoring an older backup also restores its nonce. That recovery procedure must rotate the nonce before the service
starts. This service does not provide a nonce rotation command.

### Errors

Malformed requests return `INVALID_ARGUMENT`. Note size and storage capacity limits return `RESOURCE_EXHAUSTED`. Storage
failures return `INTERNAL` and are logged by the service. Invalid proofs and conflicting block hints return
`INVALID_ARGUMENT`. An unknown proof block returns `FAILED_PRECONDITION`. Node lookup failures and invalid node
responses return `UNAVAILABLE`. Lookup timeouts return `DEADLINE_EXCEEDED`. These failures do not store a note.
