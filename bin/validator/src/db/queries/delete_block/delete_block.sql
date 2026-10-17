-- Deletes the block header at the given height. The block's rows in `block_transactions` are
-- deleted with it via `ON DELETE CASCADE`, so its transactions revert to being unlinked.
DELETE FROM blocks
WHERE block_num = ?1;
