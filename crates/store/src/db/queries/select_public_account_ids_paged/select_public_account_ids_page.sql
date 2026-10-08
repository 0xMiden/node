-- Returns the page of public account ids that starts at the cursor, ordered by account id.
--
-- Public accounts store a code commitment. Private accounts store only their account commitment.
-- The first page binds an empty blob, which sorts before every account id.
SELECT account_id
FROM accounts
WHERE valid_until = ?2
  AND code_commitment IS NOT NULL
  AND account_id >= ?3
ORDER BY account_id ASC
LIMIT ?1
