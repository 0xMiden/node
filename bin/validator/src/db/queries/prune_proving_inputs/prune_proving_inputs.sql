UPDATE blocks SET proving_inputs = NULL
WHERE block_num <= ?1 AND proving_inputs IS NOT NULL;
