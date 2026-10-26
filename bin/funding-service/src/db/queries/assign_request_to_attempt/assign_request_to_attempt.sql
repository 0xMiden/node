UPDATE requests SET attempt_id = ?1
WHERE note_id = ?2 AND transaction_id IS NULL AND attempt_id IS NULL;
