-- An agent can cancel its own pending request, so `requests.status` gains
-- 'cancelled'. SQLite cannot alter a CHECK constraint, so `requests` is
-- rebuilt (create, copy, drop, rename) and its indexes recreated. `grants`
-- references `requests`, and migrations run in one transaction, where
-- `PRAGMA foreign_keys = OFF` has no effect and a parent cannot be dropped
-- while children point at it; `grants` is therefore set aside in a plain
-- table (no foreign key), recreated against the new `requests` and refilled,
-- so every foreign key is checked against rows that exist at each step.
CREATE TABLE requests_new (id TEXT PRIMARY KEY, agent TEXT NOT NULL REFERENCES agents(name), fingerprint TEXT NOT NULL,
  dedupe_key TEXT NOT NULL, body TEXT NOT NULL, approval_token_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','expired','revoked','error','cancelled')),
  error TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, decided_at INTEGER);
INSERT INTO requests_new (rowid, id, agent, fingerprint, dedupe_key, body, approval_token_hash, status, error,
  created_at, expires_at, decided_at)
  SELECT rowid, id, agent, fingerprint, dedupe_key, body, approval_token_hash, status, error,
  created_at, expires_at, decided_at FROM requests;

CREATE TABLE grants_stash AS SELECT rowid AS rid, * FROM grants;

DROP TABLE grants;
DROP TABLE requests;
ALTER TABLE requests_new RENAME TO requests;

CREATE TABLE grants (id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE REFERENCES requests(id), agent TEXT NOT NULL,
  window_secs INTEGER NOT NULL, not_before INTEGER NOT NULL, not_after INTEGER NOT NULL, revoked_at INTEGER, view TEXT NOT NULL);
INSERT INTO grants (rowid, id, request_id, agent, window_secs, not_before, not_after, revoked_at, view)
  SELECT rid, id, request_id, agent, window_secs, not_before, not_after, revoked_at, view FROM grants_stash;
DROP TABLE grants_stash;

CREATE UNIQUE INDEX one_pending ON requests(dedupe_key) WHERE status = 'pending';
CREATE INDEX requests_created_at ON requests(created_at);
CREATE INDEX grants_not_after ON grants(not_after);
