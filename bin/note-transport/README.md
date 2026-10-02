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

The service generates a random nonce when it creates the database. Ordinary service restarts, repeated migrations, and
retention cleanup preserve the nonce. A cursor from a different database generation returns `FAILED_PRECONDITION`. Clear
the cursor and fetch again after this error. Deduplicate results by note ID. The nonce detects a generation change; it
does not recover lost notes or authenticate cursors.

Restoring a backup also restores its nonce. Rotate the nonce before the service starts after a backup restore. This
service does not provide a nonce rotation command.

### Errors

Malformed requests return `INVALID_ARGUMENT`. Note size and storage capacity limits return `RESOURCE_EXHAUSTED`. Storage
failures return `INTERNAL` and are logged by the service. Invalid proofs return `INVALID_ARGUMENT`. An unknown proof
block returns `FAILED_PRECONDITION`. Node lookup failures and invalid node responses return `UNAVAILABLE`. Lookup
timeouts return `DEADLINE_EXCEEDED`. These failures do not store a note.
