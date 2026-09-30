-- Records a protocol configuration at the block that activates it.
INSERT INTO protocol_configs (commitment, block_number, protocol_config)
VALUES (?1, ?2, ?3)
