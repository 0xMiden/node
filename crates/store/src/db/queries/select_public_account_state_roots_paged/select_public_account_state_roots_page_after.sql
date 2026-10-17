-- Returns the page of public account vault roots and storage headers after the cursor, ordered by
-- account id.
SELECT account_id, vault_root, storage_header
FROM accounts
WHERE valid_until = ?2
  AND code_commitment IS NOT NULL
  AND account_id > ?3
ORDER BY account_id ASC
LIMIT ?1
