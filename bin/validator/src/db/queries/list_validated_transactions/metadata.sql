-- Returns one metadata page of committed validated transactions in committed order.
--
-- The subquery finds where the page ends (a block number: the highest block among the range's
-- first ?3 rows); the outer query fetches what's in it (every row up to and including that
-- block). Bounding the page by block rather than by row count is what keeps blocks whole: ?3 is a
-- row-count target, not a hard page size, and the block that crosses it is returned in full. An
-- empty range yields a NULL bound and therefore no rows.
--
-- Paging advances ?1 past the last block a page returned, so that the index on
-- (block_num, block_tx_index) can seek straight to the start of the next page. Keep the range as
-- the only constraint on `block_num` when doing so: passing the resume point as a second
-- predicate alongside a wider range, rather than folding it into ?1, measured two orders of
-- magnitude slower over a 200k-row table and degraded as the sweep advanced. Both forms plan
-- identically under EXPLAIN QUERY PLAN, so this is not visible without timing it.
SELECT
    id,
    key_epoch,
    setup_context_id,
    block_num,
    block_tx_index
FROM validated_transactions
WHERE block_num IS NOT NULL
  AND block_num BETWEEN ?1 AND (
      SELECT MAX(block_num)
      FROM (
          SELECT block_num
          FROM validated_transactions
          WHERE block_num IS NOT NULL
            AND block_num BETWEEN ?1 AND ?2
          ORDER BY block_num, block_tx_index
          LIMIT ?3
      )
  )
ORDER BY block_num, block_tx_index;
