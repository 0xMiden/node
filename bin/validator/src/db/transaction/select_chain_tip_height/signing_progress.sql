SELECT block_num, block_num - COALESCE((SELECT missed_heights FROM recovery_confirmation), 0)
FROM blocks
ORDER BY block_num DESC
LIMIT 1
