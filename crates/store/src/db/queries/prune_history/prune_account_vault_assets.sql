-- Deletes vault-asset rows whose validity interval ends at or below the retention cutoff.
--
-- The literal sentinel term (rather than a bound parameter) lets SQLite prove the predicate implies
-- `idx_vault_cleanup`'s partial-index condition. It is kept in sync with `VALID_FOREVER` by a
-- compile-time assertion in this module.
DELETE FROM account_vault_assets
WHERE valid_until != 9223372036854775807
  AND valid_until <= ?1
