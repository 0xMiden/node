# Miden note transport

The note transport service stores private note envelopes for recipients that poll by note tag. It is part of the Miden
node workspace and uses the workspace license.

## API

The public `miden.note_transport.v1.NoteTransportService` service is defined in the workspace protobuf crate. It
supports `SendNoteWithProof` and `FetchNotes` over gRPC and gRPC-Web. Standard gRPC health and reflection are available
on the same listener. There are no note subscriptions or statistics RPCs.

### Sending notes

`SendNoteWithProof` requires a `TransportNote` and a `NoteInclusionProof`. The transport note contains the shared
protocol note header and note details. The service accepts only private notes. It rejects non-private notes with
`INVALID_ARGUMENT` before storage or trusted-node lookup. It checks that the details commitment matches the header.

The service checks the note ID, the proof path, and the referenced block's note root before storage. It stores the exact
inclusion block but does not store the proof. The method returns an empty `SendNoteWithProofResponse`. Senders must wait
for note inclusion and obtain a proof before submission.

The service caches up to 1,024 note root commitments from the trusted node, keyed by block number. The cache evicts the
least recently used entry when full. Failed lookups and invalid headers are not cached. Each submission still verifies
its inclusion proof against the note root, including cache hits.

Uncached header lookups make up to three attempts for `UNAVAILABLE`, `DEADLINE_EXCEEDED`, or `RESOURCE_EXHAUSTED`
responses. Attempts use short exponential backoff and individual timeouts. All attempts and delays share half of the
configured gRPC timeout: 5 seconds with the default 10-second timeout. Missing blocks and invalid headers are not
retried.

A retry with the same note ID succeeds and keeps the first envelope, inclusion block, timestamp, and cursor, including
when storage is full. The service validates the proof on every request, including duplicates.

### Fetching notes

`FetchNotes` returns `FetchedNote` records with the header, details, and `committed_in_block`. Every record contains the
exact inclusion block verified through `SendNoteWithProof`. Block zero is valid.

`FetchNotes` accepts at most 128 tags, an optional exclusive `cursor`, and an optional inclusive `sync_to` bound. Both
bounds contain the database nonce and sequence. Omit `cursor` to start from the first retained note. Omit `sync_to` to
use the current database head. Results follow insertion order within `(cursor, sync_to]` across the requested tags.
Duplicate tags do not duplicate results.

Every successful response includes both bounds. The response `cursor` identifies the last delivered note; an empty page
retains the request cursor, or sequence zero when the request omitted it. The response `sync_to` identifies the upper
bound used for the request. `has_more` reports remaining matching notes within that range. When it is false, those tags
are complete through `sync_to`, including when the page is empty.

To synchronize more than 128 tags with one stored cursor:

1. Freeze the round's tag set and retain its stored cursor `C`.
2. Fetch the first chunk from `C`, omitting `sync_to`, and capture the returned target `H`.
3. Continue that chunk with the response cursor and `sync_to = H` until `has_more` is false.
4. Start each remaining chunk from `C` and finish its pages with the same `H`.
5. Store `H` only after every chunk's notes have been durably processed.

Reuse one temporary page cursor for the chunks. Do not start a chunk from another chunk's page cursor. If a round fails,
retain `C` and retry, deduplicating by note ID. Notes inserted above `H` are fetched in a later round. Chunk boundaries
may change between rounds. A client using this procedure must require the response `sync_to`; older servers may ignore
the request bound and omit that response field.

Removing tags between rounds requires no reset. If retained history is required for newly added tags, fetch only those
tags from the beginning through `C` before including them in subsequent rounds. An insertion cutoff does not keep
expired notes alive. Recipients must finish fetching before retention removes the notes they need.

Sequences above `i64::MAX`, reversed ranges, and either bound ahead of the current database head return
`INVALID_ARGUMENT`. Equal bounds return an empty completed range. Nonce zero is valid. A nonce from another database
generation in either bound returns `FAILED_PRECONDITION`, even with no requested tags or no lower cursor. Clear both
bounds after that error and restart, deduplicating by note ID.

A page contains at most 500 notes and 3 MiB of canonically serialized header and detail bytes. The encoded response also
fits the default 4 MiB gRPC client limit. The default per-note limit is 512,000 bytes. `--max-note-size` can change it
up to the page limit. The required `--max-storage-bytes` limits retained header and detail bytes. It does not include
SQLite indexes, database metadata, or WAL disk usage. Cursor sequences use the positive signed 64-bit range supported by
SQLite. Sequence zero starts a fetch. Nonces use the complete unsigned 64-bit range. Recipients must poll before notes
expire.

The service generates a random nonce when it creates the database. Ordinary service restarts, repeated migrations, and
retention cleanup preserve the nonce. The nonce detects a generation change; it does not recover lost notes or
authenticate cursors.

Restoring a backup also restores its nonce. Rotate the nonce before the service starts after a backup restore. This
service does not provide a nonce rotation command.

### Errors

Malformed requests return `INVALID_ARGUMENT`. Note size and storage capacity limits return `RESOURCE_EXHAUSTED`. Storage
failures return `INTERNAL` and are logged by the service. Invalid proofs return `INVALID_ARGUMENT`. An unknown proof
block returns `FAILED_PRECONDITION`. Node lookup failures and invalid node responses return `UNAVAILABLE`. Lookup
timeouts return `DEADLINE_EXCEEDED`. These failures do not store a note.
