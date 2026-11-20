CREATE TABLE pending_validator_config (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    config BLOB NOT NULL
) STRICT;
