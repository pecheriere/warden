-- Audit entries of revocations, stored in the transaction that revokes and
-- removed once they are in the audit log, so that a log that fails or stalls
-- can neither stop a revocation nor lose its entry.
CREATE TABLE unwritten_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT NOT NULL, revoked_at INTEGER NOT NULL);
