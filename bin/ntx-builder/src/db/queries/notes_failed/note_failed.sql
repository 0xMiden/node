-- Marks a note as failed by incrementing `attempt_count`, setting `last_attempt`, storing the
-- latest error message, and moving `next_eligible_block` to the end of the new backoff window.
UPDATE notes
SET attempt_count = attempt_count + 1,
    last_attempt = ?2,
    last_error = ?3,
    next_eligible_block = ?4
WHERE nullifier = ?1
