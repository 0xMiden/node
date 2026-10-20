-- Inserts a block header together with the signatures that committed it.
INSERT INTO block_headers (block_num, block_header, signature, commitment)
VALUES (?1, ?2, ?3, ?4)
