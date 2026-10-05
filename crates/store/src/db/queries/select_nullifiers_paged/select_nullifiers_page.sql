-- Returns the first page of nullifiers, ordered by nullifier for stable pagination.
SELECT nullifier, block_num
FROM nullifiers
ORDER BY nullifier ASC
LIMIT ?1
