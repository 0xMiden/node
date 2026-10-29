SELECT asset
FROM account_vault_assets
WHERE account_id = ?1 AND block_num <= ?2 AND valid_until > ?2
  AND asset IS NOT NULL
