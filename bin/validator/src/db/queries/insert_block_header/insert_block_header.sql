-- Inserts a block header at a height that must not already hold one.
INSERT INTO block_headers (block_num, block_header)
VALUES (?1, ?2);
