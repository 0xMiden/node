-- Returns the latest committed summary of the given account.
SELECT account_id, account_commitment, block_num
FROM accounts
WHERE account_id = ?1
  AND valid_until = ?2
