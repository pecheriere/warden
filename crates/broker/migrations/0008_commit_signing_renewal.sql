-- When the owner was last tried, and when they were told, that a commit signing
-- grant is about to end. Null for every other grant.
ALTER TABLE grants ADD COLUMN renewal_notice_tried_at INTEGER;
ALTER TABLE grants ADD COLUMN renewal_noticed_at INTEGER;
