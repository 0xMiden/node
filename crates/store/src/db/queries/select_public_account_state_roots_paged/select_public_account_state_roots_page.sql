-- Returns the page of public account vault roots and storage headers that starts at the cursor,
-- ordered by account id.
--
-- The first page binds an empty blob, which sorts before every account id.
SELECT account_id, vault_root, storage_header
FROM accounts
WHERE valid_until = ?2
  AND code_commitment IS NOT NULL
  AND account_id >= ?3
ORDER BY account_id ASC
LIMIT ?1
