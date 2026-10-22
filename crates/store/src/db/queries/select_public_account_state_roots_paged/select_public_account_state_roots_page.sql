-- Returns the page of public account vault roots and storage headers that starts at the cursor,
-- ordered by account id.
--
-- The first page binds an empty blob, which sorts before every account id.
-- The partial index serves pages in account-id order without scanning and sorting all public
-- accounts. Its validity predicate must be literal so SQLite can prove the index applies.
SELECT account_id, vault_root, storage_header
FROM accounts INDEXED BY idx_accounts_latest_public_by_account
WHERE valid_until = 9223372036854775807
  AND code_commitment IS NOT NULL
  AND account_id >= ?2
ORDER BY account_id ASC
LIMIT ?1
