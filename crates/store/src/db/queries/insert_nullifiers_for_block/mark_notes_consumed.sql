-- Marks the notes spent by a block's nullifiers as consumed at that block.
--
-- Nullifiers are bound as a single array parameter so the statement text stays constant regardless
-- of how many the block created; see `miden_node_db::sqlite::InList`. Nullifiers whose note is not
-- stored here (a private note, or one committed before this node's history) match nothing.
UPDATE notes
SET consumed_at = ?1
WHERE nullifier IN (SELECT value FROM rarray(?2))
