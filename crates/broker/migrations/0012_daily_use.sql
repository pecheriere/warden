-- A grant's uses of the day: calls through the proxy now, relay sessions later. A
-- grant has one kind, so one set of columns serves them all. Days are Unix days
-- (seconds / 86400); a NULL use_day means the grant was never used.
ALTER TABLE grants ADD COLUMN use_day INTEGER;
ALTER TABLE grants ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE grants ADD COLUMN use_limit_noticed_day INTEGER;
