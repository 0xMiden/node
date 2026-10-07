-- Returns the page of nullifiers after the cursor, ordered by nullifier for stable pagination.
--
-- The cursor is a plain `>` comparison and not a nullable parameter, so the range scan can use the
-- primary key index.
SELECT nullifier, block_num
FROM nullifiers
WHERE nullifier > ?2
ORDER BY nullifier ASC
LIMIT ?1
