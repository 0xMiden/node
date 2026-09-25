-- Records the latest failure of a FEE_SPONSORSHIP note by setting `last_attempt` and `last_error`.
-- The attempt count and the backoff stay on the feature note.
UPDATE sponsorship_notes
SET last_attempt = ?2, last_error = ?3
WHERE nullifier = ?1
