-- Returns the assets in the given account's vault as of a block.
--
-- Selects, per vault key, the row whose validity interval covers the block; a NULL asset marks a
-- removal and is skipped by the caller.
SELECT asset
FROM account_vault_assets
WHERE account_id = ?1
  AND block_num <= ?2
  AND valid_until > ?2
LIMIT ?3;
