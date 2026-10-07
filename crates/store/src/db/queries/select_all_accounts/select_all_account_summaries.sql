-- Returns the latest committed summary of every account, ordered by the block of the last update.
SELECT account_id, account_commitment, block_num
FROM accounts
WHERE valid_until = ?1
ORDER BY block_num ASC
