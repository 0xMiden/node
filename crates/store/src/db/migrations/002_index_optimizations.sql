-- Generic latest-account lookups and account-tree pagination.
DROP INDEX IF EXISTS idx_accounts_latest;
CREATE INDEX idx_accounts_latest_by_account
    ON accounts(account_id)
    WHERE is_latest = 1;
-- Public-account pagination and public-account state-root pagination.
CREATE INDEX idx_accounts_latest_public_by_account
    ON accounts(account_id)
    WHERE is_latest = 1 AND code_commitment IS NOT NULL;
-- Network-account subset filtering.
DROP INDEX IF EXISTS idx_accounts_network_type;
CREATE INDEX idx_accounts_latest_network_by_account
    ON accounts(account_id)
    WHERE is_latest = 1 AND network_account_type = 1;
-- Latest storage map lookups and update-old-latest paths.
DROP INDEX IF EXISTS idx_account_storage_latest;
DROP INDEX IF EXISTS idx_account_storage_map_latest_by_account_slot_key;
CREATE INDEX idx_account_storage_map_latest_by_account_slot_key
    ON account_storage_map_values(account_id, slot_name, key)
    WHERE is_latest = 1;
-- Latest vault lookups and update-old-latest paths.
DROP INDEX IF EXISTS idx_vault_assets_latest;
DROP INDEX IF EXISTS idx_account_vault_assets_latest_by_account_key;
CREATE INDEX idx_account_vault_assets_latest_by_account_key
    ON account_vault_assets(account_id, vault_key)
    WHERE is_latest = 1;

-- The current nullifier prefix sync query filters by `nullifier_prefix IN (...)`,
-- filters a block range, orders by `block_num`, and returns `nullifier, block_num`.
-- The existing `idx_nullifiers_prefix(nullifier_prefix)` cannot constrain the block
-- range inside each prefix, so we replace it with a composite index.
DROP INDEX IF EXISTS idx_nullifiers_prefix;
CREATE INDEX idx_nullifiers_prefix_block_num
    ON nullifiers(nullifier_prefix, block_num);
DROP INDEX IF EXISTS idx_nullifiers_block_num;

-- `insert_nullifiers_for_block` first updates notes by `nullifier IN (...)`, then
-- inserts into `nullifiers`.  Since private notes have `nullifier IS NULL`, the
-- current full `idx_notes_nullifier` should be partial instead.
DROP INDEX IF EXISTS idx_notes_nullifier;
CREATE INDEX idx_notes_public_nullifier
    ON notes(nullifier)
    WHERE nullifier IS NOT NULL;

-- Unused indexes
DROP INDEX IF EXISTS idx_accounts_created_at_block;
DROP INDEX IF EXISTS idx_accounts_block_num;
-- `idx_accounts_code_commitment` is not needed for `select_full_account`, because
-- that query starts from `accounts` filtered by `account_id` and `is_latest`, then
-- joins to `account_codes` by the `account_codes` primary key.
DROP INDEX IF EXISTS idx_accounts_code_commitment;

DROP INDEX IF EXISTS idx_notes_sender;
DROP INDEX IF EXISTS idx_notes_target_account;
-- The left join to `note_scripts` is reached from notes filtered by `note_id`,
-- then probes `note_scripts` by its primary key.
DROP INDEX IF EXISTS idx_notes_script_root;
DROP INDEX IF EXISTS idx_notes_consumed_at;
