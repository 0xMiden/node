-- Returns one page of committed validated transactions in committed order, i.e. ordered by
-- (block_num, block_tx_index).
--
-- The row-value comparison seeks the primary key of `block_transactions` straight to the start of
-- the page, so a page costs O(log n). A caller pages by passing the position one past the last
-- row of the previous page as the new start.
SELECT
    bt.transaction_id,
    vt.key_epoch,
    vt.setup_context_id,
    bt.block_num,
    bt.block_tx_index
FROM block_transactions AS bt
JOIN validated_transactions AS vt ON vt.id = bt.transaction_id
WHERE (bt.block_num, bt.block_tx_index) >= (?1, ?2)
  AND bt.block_num <= ?3
ORDER BY bt.block_num, bt.block_tx_index
LIMIT ?4;
