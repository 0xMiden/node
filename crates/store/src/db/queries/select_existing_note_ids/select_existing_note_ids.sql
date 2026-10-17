-- Returns the given note ids that are stored at or before the block.
--
-- Note ids are bound as a single array parameter so the statement text stays constant regardless
-- of how many are requested; see `miden_node_db::sqlite::InList`.
SELECT note_id
FROM notes
WHERE note_id IN (SELECT value FROM rarray(?1))
  AND committed_at <= ?2
