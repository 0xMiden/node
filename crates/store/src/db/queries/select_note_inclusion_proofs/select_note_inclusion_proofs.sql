-- Returns the inclusion proof data of the given notes that are committed at or before the block.
--
-- Note commitments are bound as a single array parameter so the statement text stays constant
-- regardless of how many are requested; see `miden_node_db::sqlite::InList`.
SELECT committed_at, note_id, batch_index, note_index, inclusion_path
FROM notes
WHERE note_id IN (SELECT value FROM rarray(?1))
  AND committed_at <= ?2
ORDER BY committed_at ASC
