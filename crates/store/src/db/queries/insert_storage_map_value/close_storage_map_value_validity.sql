-- Closes the previous version of a storage-map entry and returns whether its value was nonzero.
--
-- Only the open-ended row (`valid_until` at the sentinel) can be the previous version, so matching
-- on it both selects that row and makes the update idempotent.
UPDATE account_storage_map_values
SET valid_until = ?1
WHERE account_id = ?2
  AND slot_name = ?3
  AND key = ?4
  AND valid_until = ?5
RETURNING value != zeroblob(32)
