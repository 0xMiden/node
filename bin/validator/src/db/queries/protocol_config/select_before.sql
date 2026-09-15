SELECT commitment
FROM protocol_configs
WHERE block_number < ?1
ORDER BY block_number DESC
LIMIT 1;
