SELECT block_header
FROM blocks
WHERE block_num >= COALESCE((SELECT block_num FROM recovery_confirmation), 0)
ORDER BY block_num DESC
LIMIT 2;
