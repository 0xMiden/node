# Transaction stream message bound

`GetTransactionsById` sends one complete `TransactionRecord` per message. The transport does not
limit the aggregate stream to 4 MiB. Each record remains below the default 4 MiB receiver cap.

The bound uses the `miden-protocol` and `miden-objects` 0.17.0 versions pinned by `Cargo.lock`:

- A valid proven transaction has at most 1024 inputs and 1024 outputs.
- A note metadata header has at most four attachment schemes. It sends their commitment, not
  attachment bodies or note details.
- An output note inclusion path has at most 16 siblings, from `BLOCK_NOTE_TREE_DEPTH`.
- Output proof and consumed-reference counts cannot exceed output and input counts, respectively.

For a conservative protobuf bound, allow six bytes for each nested message's tag and length
prefix (one tag byte and up to five length bytes). This covers the endpoint wrapper too. A Word
is 34 bytes: its 32-byte payload, one tag, and one length. Account IDs fit within 40 bytes,
including their version wrapper and two fixed64 field elements. A metadata message fits within
128 bytes, including version/type, sender, tag, four packed fixed32 schemes and the attachment
commitment. A note header therefore fits within 174 bytes.

An input commitment, including its optional note header and a consumed-note reference, fits in
320 bytes after enclosing-field overhead. An output header plus its inclusion proof fits in
1024 bytes after overhead. The proof includes the note ID, block number, leaf index, the fixed64
sparse mask, and 16 nested Words. Allow 512 bytes for all fixed record/header fields and six bytes
for the endpoint wrapper:

```text
512 + (1024 × 320) + (1024 × 1024) + 6 = 1,376,774 bytes < 4 MiB
```

This deliberately overestimates the record: header-bearing input commitments and consumed
references do not normally occur together. Maximum-shape tests cover both authenticated inputs
with references and unauthenticated inputs with note headers, maximum outputs/proofs, attachment
counts, sibling counts and scalar widths, measuring the encoded endpoint wrapper.

Compile-time assertions flag changes to the proof depth, attachment count, or aggregate bound.
The streaming encoder checks protocol counts and proof depth, then enforces the actual encoded
message cap. Corrupt or out-of-contract stored records terminate the stream with a non-OK status;
clients must discard the incomplete result. Valid transactions are not rejected to accommodate
transport sizing, and the receiver limit is not increased.
