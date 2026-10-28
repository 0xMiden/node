SELECT slot_name, key, value
FROM account_storage_map_values
WHERE account_id = ?1 AND block_num <= ?2
  AND valid_until > ?2 AND value != zeroblob(32)
