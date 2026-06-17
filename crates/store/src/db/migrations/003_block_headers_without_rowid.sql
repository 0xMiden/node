-- Make `block_headers` a WITHOUT ROWID table. Due to SQLite not handling our BIGINT primary
-- key as a row id `block_headers` was using a `rowid` under the hood. Declaring it explicitly
-- as `WITHOUT ROWID` avoids that issue.
CREATE TABLE block_headers_new (
    block_num    BIGINT NOT NULL,
    block_header BLOB   NOT NULL,
    signature    BLOB   NOT NULL,
    commitment   BLOB   NOT NULL,

    PRIMARY KEY (block_num),
    CONSTRAINT block_header_block_num_is_u32 CHECK (block_num BETWEEN 0 AND 0xFFFFFFFF)
) WITHOUT ROWID;

INSERT INTO block_headers_new (
    block_num,
    block_header,
    signature,
    commitment
)
SELECT
    block_num,
    block_header,
    signature,
    commitment
FROM block_headers
ORDER BY block_num;

DROP TABLE block_headers;

ALTER TABLE block_headers_new RENAME TO block_headers;
