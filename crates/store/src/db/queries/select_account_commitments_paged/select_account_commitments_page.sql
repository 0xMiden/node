-- Returns the first page of latest account commitments, ordered by account id.
SELECT account_id, account_commitment
FROM accounts
WHERE valid_until = ?2
ORDER BY account_id ASC
LIMIT ?1
