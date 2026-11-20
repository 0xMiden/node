-- Returns the block headers stored at the given block numbers, ordered by block number.
--
-- Block numbers are bound as a single array parameter so the statement text stays constant
-- regardless of how many are requested; see `miden_node_db::sqlite::InList`.
SELECT block_header, commitment
FROM block_headers
WHERE block_num IN (SELECT value FROM rarray(?1))
ORDER BY block_num ASC
