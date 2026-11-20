UPDATE account_storage_map_values
SET valid_until = ?1
WHERE account_id = ?2 AND slot_name = ?3 AND valid_until = ?4
