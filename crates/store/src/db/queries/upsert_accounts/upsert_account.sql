-- Writes an account's state at `block_num` as its current, open-ended version.
--
-- Re-applying the same block overwrites that block's row rather than failing, so an interrupted
-- block application can be replayed. The key columns are excluded from the update: they are what
-- the conflict matched on.
INSERT INTO accounts (
    account_id,
    network_account_type,
    block_num,
    account_commitment,
    code_commitment,
    nonce,
    storage_header,
    vault_root,
    created_at_block,
    valid_until
)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
ON CONFLICT(account_id, block_num) DO UPDATE SET
    network_account_type = excluded.network_account_type,
    account_commitment   = excluded.account_commitment,
    code_commitment      = excluded.code_commitment,
    nonce                = excluded.nonce,
    storage_header       = excluded.storage_header,
    vault_root           = excluded.vault_root,
    created_at_block     = excluded.created_at_block,
    valid_until          = excluded.valid_until
