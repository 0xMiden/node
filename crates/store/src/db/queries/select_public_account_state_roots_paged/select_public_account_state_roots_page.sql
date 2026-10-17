-- Returns the first page of public account vault roots and storage headers, ordered by account id.
SELECT account_id, vault_root, storage_header
FROM accounts
WHERE valid_until = ?2
  AND code_commitment IS NOT NULL
ORDER BY account_id ASC
LIMIT ?1
