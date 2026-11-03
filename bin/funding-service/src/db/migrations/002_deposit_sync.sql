-- Where deposit discovery resumes. Block 0 scans from genesis, which every start did before this
-- table existed.
CREATE TABLE deposit_sync (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_sync_block INTEGER NOT NULL CHECK (next_sync_block BETWEEN 0 AND 4294967295)
) STRICT;

INSERT INTO deposit_sync (singleton, next_sync_block) VALUES (1, 0);

-- Deposits found before `next_sync_block`, not seen spent before it, and not yet consumed or
-- discarded by the service.
CREATE TABLE deposits (
    nullifier BLOB PRIMARY KEY CHECK (length(nullifier) = 32),
    note BLOB NOT NULL
) STRICT;
