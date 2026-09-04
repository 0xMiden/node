-- Corrects the stored eligibility block of one note.

UPDATE notes
SET next_eligible_block = ?2
WHERE nullifier = ?1 AND committed_at IS NULL
