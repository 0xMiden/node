-- Returns every current storage map entry of the given account.
SELECT slot_name, key, value
FROM account_storage_map_values
WHERE account_id = ?1
  AND valid_until = ?2;
