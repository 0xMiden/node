-- Store-sync checkpoint: the highest block whose state has been fully ingested into the local
-- DB by the startup catch-up sync.
--
-- NULL means "never sync'd": treated as a full GENESIS-onward sync on first boot after upgrade.
ALTER TABLE chain_state ADD COLUMN store_sync_checkpoint INTEGER
    CHECK (store_sync_checkpoint IS NULL
           OR store_sync_checkpoint BETWEEN 0 AND 0xFFFFFFFF);
