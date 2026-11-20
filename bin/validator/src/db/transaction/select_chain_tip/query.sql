-- Returns the block header with the highest block number, i.e. the chain tip.
SELECT block_header
FROM blocks
ORDER BY block_num DESC
LIMIT 1;
