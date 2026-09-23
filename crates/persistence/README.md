# Miden node persistence

Shared protobuf codecs for structured SQLite values and node-owned binary files. Raw database keys, execution proofs,
and cryptographic encodings retain their formats.

Native serialization remains at these boundaries:

- SQLite keys and indexed words use fixed-width bytes for joins and cursor ordering.
- The `proven_tip` file stores one four-byte little-endian block number.
- Execution-proof files and proof fields retain the proof library encoding.
- Sealed transaction-input submissions use the existing RPC plaintext encoding.
- Keys, signatures, encrypted record keys, associated data and DKG files use their cryptographic library encodings.
- Upstream `AccountFile` handles account files. Its format is already protobuf.
