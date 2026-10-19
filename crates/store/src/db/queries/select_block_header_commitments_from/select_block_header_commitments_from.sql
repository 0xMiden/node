-- Returns the block header commitments starting at the given block number, ordered by block number.
SELECT commitment
FROM block_headers
WHERE block_num >= ?1
ORDER BY block_num ASC
