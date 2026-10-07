-- Returns the block header stored at the given block number and its validator signatures.
SELECT block_header, signature
FROM block_headers
WHERE block_num = ?1
