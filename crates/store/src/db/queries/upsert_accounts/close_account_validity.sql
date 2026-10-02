-- Closes an account's current row at the block that supersedes it.
--
-- Only the open-ended row (`valid_until` at the sentinel) can be the previous version, so matching
-- on it both selects that row and makes the update idempotent.
UPDATE accounts
SET valid_until = ?1
WHERE account_id = ?2
  AND valid_until = ?3
