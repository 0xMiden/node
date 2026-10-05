SELECT committed_at, batch_index, note_index, note_id, note_type, sender, tag, attachment,
       inclusion_path
FROM notes
WHERE tag IN (SELECT value FROM rarray(?1))
  AND committed_at >= ?2 AND committed_at <= ?3
  AND (committed_at, batch_index, note_index) > (?4, ?5, ?6)
ORDER BY committed_at, batch_index, note_index
LIMIT ?7
