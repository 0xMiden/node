-- Returns the commitment of the latest protocol configuration activated at or before the given
-- block number.
SELECT commitment
FROM protocol_configs
WHERE block_number <= ?1
ORDER BY block_number DESC
LIMIT 1
