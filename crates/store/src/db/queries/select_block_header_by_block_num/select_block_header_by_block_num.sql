-- Returns the block header stored at the given block number.
SELECT block_header, commitment
FROM block_headers
WHERE block_num = ?1
