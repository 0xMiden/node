-- Returns the fields of an account's current row that preparing its next update depends on:
--
--   * `created_at_block` and `network_account_type` are carried forward by every update
--   * `nonce` is preserved when a partial patch omits its final nonce
--   * `code_commitment` is unchanged by partial patches
--   * `storage_header` is the header the storage patch is applied to
SELECT created_at_block, network_account_type, nonce, code_commitment, storage_header
FROM accounts
WHERE account_id = ?1
  AND valid_until = ?2
