SELECT nullifier, block_num
FROM nullifiers
WHERE nullifier_prefix IN (SELECT value FROM rarray(?1))
  AND block_num >= ?2 AND block_num <= ?3
ORDER BY block_num, nullifier
LIMIT ?4
