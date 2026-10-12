-- Returns the block header stored at the given block number.
SELECT block_header
FROM blocks
WHERE block_num = ?1;
