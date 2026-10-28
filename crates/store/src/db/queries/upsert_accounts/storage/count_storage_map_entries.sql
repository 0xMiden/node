SELECT COUNT(*)
FROM account_storage_map_values
WHERE account_id = ?1 AND slot_name = ?2 AND valid_until = ?3
  AND value != zeroblob(32)
