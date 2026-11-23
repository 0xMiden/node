-- Marks a note as consumed by setting `committed_at` to the block number whose committed body
-- contained its nullifier. Rows for nullifiers we never inserted are silently skipped (no match).
-- Rows are kept (not deleted) so the `GetNetworkNoteStatus` endpoint can report a consumed note
-- until it is pruned.
UPDATE notes
SET committed_at = ?2
WHERE nullifier = ?1 AND committed_at IS NULL
