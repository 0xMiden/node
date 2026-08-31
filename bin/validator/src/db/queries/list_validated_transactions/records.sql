-- Returns one full-record page of committed validated transactions in committed order. Paging is
-- identical to `metadata.sql`; only the column list differs, with the first nine columns matching
-- the shared private-record column list.
SELECT
    chain_id,
    key_epoch,
    id,
    validator_id,
    setup_context_id,
    format_version,
    cipher_nonce,
    encrypted_record,
    encrypted_record_key,
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
