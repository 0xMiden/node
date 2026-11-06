SELECT note FROM deposits WHERE attempt_id IS NULL ORDER BY amount DESC, nullifier LIMIT ?1;
