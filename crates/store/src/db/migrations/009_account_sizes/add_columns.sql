ALTER TABLE accounts ADD COLUMN storage_slots BIGINT CHECK (storage_slots >= 0);
ALTER TABLE accounts ADD COLUMN storage_map_entries BIGINT CHECK (storage_map_entries >= 0);
ALTER TABLE accounts ADD COLUMN vault_assets BIGINT CHECK (vault_assets >= 0);

CREATE INDEX idx_storage_map_live_values
    ON account_storage_map_values(account_id, slot_name, valid_until, block_num)
    WHERE value != zeroblob(32);
CREATE INDEX idx_vault_live_assets
    ON account_vault_assets(account_id, valid_until, block_num)
    WHERE asset IS NOT NULL;
