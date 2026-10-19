-- Returns every stored nullifier with the block at which it was created.
SELECT nullifier, block_num
FROM nullifiers
ORDER BY nullifier ASC
