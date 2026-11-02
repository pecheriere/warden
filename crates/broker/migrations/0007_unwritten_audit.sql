-- Audit entries of changes that end access (a revocation, a denial, an expiry),
-- stored in the transaction that makes the change and removed once they are in the
-- audit log, so that the log can neither stop the change nor lose its entry. A
-- writer claims a row first, so two processes do not both write it; a claim left
-- behind by a crash can be taken over later.
CREATE TABLE unwritten_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL,
  took_effect_at INTEGER NOT NULL, claim TEXT, claimed_at INTEGER);
