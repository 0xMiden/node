-- Previous versions stored the tag as a signed 32-bit value, so a tag at or above 2^31 is
-- negative. This statement converts each negative tag to its unsigned value.
UPDATE notes SET tag = tag + 4294967296 WHERE tag < 0;
