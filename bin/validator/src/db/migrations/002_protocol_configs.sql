CREATE TABLE protocol_configs (
    commitment BLOB NOT NULL CHECK (length(commitment) = 32),
    block_number BIGINT NOT NULL CHECK (block_number BETWEEN 0 AND 0xFFFFFFFF),
    protocol_config BLOB NOT NULL,
    PRIMARY KEY (commitment, block_number)
) WITHOUT ROWID;

CREATE UNIQUE INDEX protocol_configs_block_number ON protocol_configs (block_number);
