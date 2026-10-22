-- Returns the page of latest account commitments that starts at the cursor, ordered by account id.
--
-- The cursor is a plain `>=` comparison and not a nullable parameter, so the range scan can use the
-- index on `account_id`. The first page binds an empty blob, which sorts before every account id.
SELECT account_id, account_commitment
FROM accounts
WHERE valid_until = ?2
  AND account_id >= ?3
ORDER BY account_id ASC
LIMIT ?1
