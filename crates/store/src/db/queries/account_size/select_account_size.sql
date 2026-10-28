SELECT storage_slots, storage_map_entries, vault_assets
FROM accounts
WHERE account_id = ?1 AND block_num <= ?2 AND storage_header IS NOT NULL
ORDER BY block_num DESC
LIMIT 1
