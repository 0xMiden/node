UPDATE deposits SET attempt_id = ?1 WHERE nullifier = ?2 AND attempt_id IS NULL;
