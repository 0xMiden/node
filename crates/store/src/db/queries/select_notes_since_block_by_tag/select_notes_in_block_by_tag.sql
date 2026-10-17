-- Returns every note in the given block that has one of the tags, in block note order.
SELECT committed_at, batch_index, note_index, note_id, note_type, sender, tag, attachment,
       inclusion_path
FROM notes
WHERE committed_at = ?2
  AND tag IN (SELECT value FROM rarray(?1))
ORDER BY committed_at ASC, batch_index ASC, note_index ASC
