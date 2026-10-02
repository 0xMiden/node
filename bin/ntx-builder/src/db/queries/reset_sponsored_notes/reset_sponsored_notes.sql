-- Sets `next_eligible_block` for every unconsumed note in the given note id list.

UPDATE notes
SET next_eligible_block = ?2
WHERE committed_at IS NULL
  AND note_id IN (SELECT value FROM rarray(?1))
