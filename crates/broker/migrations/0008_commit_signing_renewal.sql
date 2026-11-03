-- When the owner was last tried, and when they were told, that a commit signing
-- grant is about to end. Null for every other grant.
ALTER TABLE grants ADD COLUMN renewal_notice_tried_at INTEGER;
ALTER TABLE grants ADD COLUMN renewal_noticed_at INTEGER;

-- The UTC day a commit signing grant last signed on, its signatures that day, and the
-- day the owner was last told it reached its limit. Null for every other grant.
ALTER TABLE grants ADD COLUMN signing_day INTEGER;
ALTER TABLE grants ADD COLUMN signing_count INTEGER;
ALTER TABLE grants ADD COLUMN signing_limit_noticed_day INTEGER;
