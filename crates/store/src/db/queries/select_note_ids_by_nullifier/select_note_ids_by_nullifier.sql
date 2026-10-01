-- Maps the given nullifiers to the ids of their notes.
--
-- Only public notes store a nullifier, so private notes never match.
--
-- Nullifiers are bound as a single array parameter so the statement text stays constant regardless
-- of how many are requested; see `miden_node_db::sqlite::InList`.
SELECT nullifier, note_id
FROM notes
WHERE nullifier IN (SELECT value FROM rarray(?1))
