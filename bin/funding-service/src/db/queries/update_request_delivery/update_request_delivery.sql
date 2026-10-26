UPDATE requests
SET transaction_id = ?1, committed_in_block = ?2, confirmed_at = ?3
WHERE note_id = ?4;
