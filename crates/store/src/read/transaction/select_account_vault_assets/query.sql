-- Returns the vault updates of the given account within a block range, oldest first.
SELECT block_num, vault_key, asset
FROM account_vault_assets
WHERE account_id = ?1
  AND block_num >= ?2
  AND block_num <= ?3
ORDER BY block_num ASC
LIMIT ?4
