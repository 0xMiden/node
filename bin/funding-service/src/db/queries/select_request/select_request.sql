SELECT sequence, note, accepted_at, transaction_id, committed_in_block, confirmed_at
FROM requests
WHERE note_id = ?1;
