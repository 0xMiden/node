-- Makes the pending feature notes that just gained a `FEE_SPONSORSHIP` note eligible again.

UPDATE notes
SET next_eligible_block = ?2
WHERE committed_at IS NULL
  AND note_id IN (SELECT value FROM rarray(?1))
