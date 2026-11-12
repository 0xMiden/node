SELECT nullifier FROM deposits WHERE attempt_id = ?1 ORDER BY amount DESC, nullifier;
