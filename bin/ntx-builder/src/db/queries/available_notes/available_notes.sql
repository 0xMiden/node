-- Selects unconsumed notes for the account (a row exists only while a note is unconsumed) whose
-- `attempt_count` is below the cap and whose stored eligibility block has passed.
SELECT note_data, attempt_count, last_attempt FROM notes
WHERE account_id = ?1
  AND committed_at IS NULL
  AND attempt_count < ?2
  AND next_eligible_block <= ?3
