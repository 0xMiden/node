SELECT account_id, block_num
FROM accounts
WHERE account_id IN (SELECT value FROM rarray(?1))
  AND block_num >= ?2 AND block_num <= ?3
  AND valid_until > ?3
ORDER BY account_id
LIMIT ?4
