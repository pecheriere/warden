CREATE TABLE agents (name TEXT PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE requests (id TEXT PRIMARY KEY, agent TEXT NOT NULL REFERENCES agents(name), fingerprint TEXT NOT NULL,
  dedupe_key TEXT NOT NULL, body TEXT NOT NULL, approval_token_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','expired','revoked','error')),
  error TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, decided_at INTEGER);
CREATE UNIQUE INDEX one_pending ON requests(dedupe_key) WHERE status = 'pending';
CREATE TABLE grants (id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE REFERENCES requests(id), agent TEXT NOT NULL,
  window_secs INTEGER NOT NULL, not_before INTEGER NOT NULL, not_after INTEGER NOT NULL, revoked_at INTEGER, view TEXT NOT NULL);
CREATE TABLE passkeys (id TEXT PRIMARY KEY, label TEXT NOT NULL, credential TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE enrollment_codes (code_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, used_at INTEGER);
