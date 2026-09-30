-- Returns the assets in the given account's vault as of a block.
--
-- Selects, per vault key, the row whose validity interval covers the block. A NULL asset marks a
-- removal.
SELECT asset
FROM account_vault_assets
WHERE account_id = ?1
  AND block_num <= ?2
  AND valid_until > ?2
  AND asset IS NOT NULL
LIMIT ?3;
