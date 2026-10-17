-- Returns the sync records of the given notes, oldest block first.
--
-- Note ids are bound as a single array parameter so the statement text stays constant regardless
-- of how many are requested; see `miden_node_db::sqlite::InList`.
SELECT committed_at, batch_index, note_index, note_id, note_type, sender, tag, attachment,
       inclusion_path
FROM notes
WHERE note_id IN (SELECT value FROM rarray(?1))
ORDER BY committed_at ASC
