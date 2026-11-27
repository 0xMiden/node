-- Heights imported before this validator signed a block at that height.
ALTER TABLE recovery_confirmation
ADD COLUMN missed_heights INTEGER NOT NULL DEFAULT 0 CHECK (missed_heights >= 0);
