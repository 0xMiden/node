-- The next chain block whose state the ntx-builder should ingest from the store on its next
-- startup catch-up. Defaults to GENESIS (0) so an upgraded DB triggers a full sync; once
-- catch-up successfully reaches block N the column is bumped to N + 1.
ALTER TABLE chain_state ADD COLUMN next_block_to_sync INTEGER NOT NULL DEFAULT 0
    CHECK (next_block_to_sync BETWEEN 0 AND 0xFFFFFFFF);
