-- Returns the page of nullifiers that starts at the cursor, ordered by nullifier for stable
-- pagination.
--
-- The cursor is a plain `>=` comparison and not a nullable parameter, so the range scan can use the
-- primary key index. The first page binds an empty blob, which sorts before every nullifier.
SELECT nullifier, block_num
FROM nullifiers
WHERE nullifier >= ?2
ORDER BY nullifier ASC
LIMIT ?1
