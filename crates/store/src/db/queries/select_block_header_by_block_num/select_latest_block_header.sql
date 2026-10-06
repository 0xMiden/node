-- Returns the block header of the chain tip.
SELECT block_header, commitment
FROM block_headers
ORDER BY block_num DESC
LIMIT 1
