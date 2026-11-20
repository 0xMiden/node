UPDATE accounts
SET storage_slots = ?3, storage_map_entries = ?4, vault_assets = ?5
WHERE account_id = ?1 AND block_num = ?2
