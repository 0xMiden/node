-- Returns the storage map updates of the given account within a block range, oldest first.
SELECT block_num, slot_name, key, value
FROM account_storage_map_values
WHERE account_id = ?1
  AND block_num >= ?2
  AND block_num <= ?3
ORDER BY block_num ASC
LIMIT ?4
