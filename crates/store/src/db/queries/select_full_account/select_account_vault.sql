-- Returns the assets currently held in the given account's vault.
--
-- A NULL asset marks a removal, and is skipped by the caller.
SELECT asset
FROM account_vault_assets
WHERE account_id = ?1
  AND valid_until = ?2;
