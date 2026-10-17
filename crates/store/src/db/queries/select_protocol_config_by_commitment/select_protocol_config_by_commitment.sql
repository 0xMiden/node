-- Returns the earliest stored protocol configuration with the given commitment.
SELECT protocol_config
FROM protocol_configs
WHERE commitment = ?1
ORDER BY block_number ASC
LIMIT 1
