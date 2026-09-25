-- Closes the previous version of a vault asset at the block that supersedes it.
--
-- Only the open-ended row (`valid_until` at the sentinel) can be the previous version, so matching
-- on it both selects that row and makes the update idempotent.
UPDATE account_vault_assets
SET valid_until = ?1
WHERE account_id = ?2
  AND vault_key = ?3
  AND valid_until = ?4
