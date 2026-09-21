CREATE TABLE notes (
    seq INTEGER PRIMARY KEY AUTOINCREMENT CHECK (seq > 0),
    id BLOB NOT NULL UNIQUE,
    tag INTEGER NOT NULL CHECK (tag BETWEEN 0 AND 4294967295),
    header BLOB NOT NULL,
    details BLOB NOT NULL,
    -- created_at stores microseconds since the Unix epoch, assigned by the service at insertion.
    created_at INTEGER NOT NULL,
    -- after_block_num is the sender's unverified lower bound for the inclusion block.
    -- A NULL block hint differs from block zero.
    after_block_num INTEGER CHECK (after_block_num BETWEEN 0 AND 4294967295)
) STRICT;

CREATE INDEX idx_notes_tag_seq ON notes(tag, seq);
CREATE INDEX idx_notes_created_at ON notes(created_at);

CREATE TABLE storage_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    retained_bytes INTEGER NOT NULL CHECK (retained_bytes >= 0)
) STRICT;

INSERT INTO storage_metadata (singleton, retained_bytes) VALUES (1, 0);
