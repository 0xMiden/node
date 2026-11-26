CREATE TABLE pending_validator_quorum (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    quorum INTEGER NOT NULL CHECK (quorum BETWEEN 1 AND 65535)
) STRICT;
