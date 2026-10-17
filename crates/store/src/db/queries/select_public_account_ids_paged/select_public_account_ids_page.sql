-- Returns the first page of public account ids, ordered by account id.
--
-- Public accounts store a code commitment. Private accounts store only their account commitment.
SELECT account_id
FROM accounts
WHERE valid_until = ?2
  AND code_commitment IS NOT NULL
ORDER BY account_id ASC
LIMIT ?1
