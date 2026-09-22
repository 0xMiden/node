# Miden note transport

The note transport service stores private note envelopes for recipients that poll by note tag. It is part of the Miden
node workspace and uses the workspace license.

## API

The public `note_transport.Api` service is defined in the workspace protobuf crate. It supports `SendNote` and
`FetchNotes` over gRPC and gRPC-Web. Standard gRPC health and reflection are available on the same listener. There are
no note subscriptions or statistics RPCs.

`SendNote` accepts a `SendNoteRequest` whose `note` field contains a `TransportNote` with the shared protocol note
header and note details. It returns an empty `SendNoteResponse`. The service checks that the details commitment matches
the header. An optional block hint gives recipients a lower bound for their chain scan. The service stores this hint
without chain lookup; an absent hint differs from block zero.

A retry with the same note ID succeeds and keeps the first envelope, timestamp, and cursor. This also applies when the
retry supplies a different block hint or storage is full.

`FetchNotes` accepts at most 128 tags and an exclusive cursor. Start with cursor zero. Use each response cursor for the
next request with the same set of tags. Results follow insertion order across all requested tags. Duplicate tags do not
duplicate results. Empty pages retain the request cursor. The response `has_more` field indicates that another page is
available.

A cursor belongs to the requested set of tags. Reset the cursor to zero when you add or remove tags. Reordering tags or
changing duplicate tags does not change the set. A restart can return notes that you fetched before. Use note IDs to
remove duplicate results.

For example, after you fetch tag A through cursor 100, reset the cursor to zero when you add tag B. If you reuse cursor
100, you skip retained notes for tag B with cursors at or below 100.

A page contains at most 500 notes and 3 MiB of canonically serialized header and detail bytes. The encoded response also
fits the default 4 MiB gRPC client limit. The default per-note limit is 512,000 bytes. `--max-note-size` can change it
up to the page limit. The required `--max-storage-bytes` limits retained header and detail bytes. It does not include
SQLite indexes, database metadata, or WAL disk usage. Cursors use the positive signed 64-bit range supported by SQLite.
Recipients must poll before notes expire.

Malformed requests return `INVALID_ARGUMENT`. Note size and storage capacity limits return `RESOURCE_EXHAUSTED`. Storage
failures return `INTERNAL` and are logged by the service.

## Development

```sh
cargo test -p miden-note-transport
make format
```

The database uses `miden-node-db` transaction and migration helpers. It supports SQLite only.
