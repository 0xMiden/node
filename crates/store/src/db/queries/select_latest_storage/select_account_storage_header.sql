-- Returns the storage header of the given account's latest committed state.
SELECT storage_header
FROM accounts
WHERE account_id = ?1
  AND valid_until = ?2;
