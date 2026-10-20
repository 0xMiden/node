INSERT INTO protocol_configs (commitment, block_number, protocol_config)
VALUES (?1, ?2, ?3)
ON CONFLICT (block_number) DO UPDATE SET
    commitment = excluded.commitment,
    protocol_config = excluded.protocol_config;
