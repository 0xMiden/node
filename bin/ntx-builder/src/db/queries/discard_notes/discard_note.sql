-- Marks a note as permanently unconsumable by pinning `attempt_count` to `max_attempts`, recording
-- the block at which it was discarded in `last_attempt`, and storing the reason in `last_error`.
--
-- `next_eligible_block` is pinned to the maximum block number as well, so the note is excluded by
-- the eligibility filter even if the attempt cap is later raised.
UPDATE notes
SET attempt_count = ?2, last_attempt = ?3, last_error = ?4, next_eligible_block = ?5
WHERE nullifier = ?1
