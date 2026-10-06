-- Returns every stored block header commitment, ordered by block number.
SELECT commitment
FROM block_headers
ORDER BY block_num ASC
