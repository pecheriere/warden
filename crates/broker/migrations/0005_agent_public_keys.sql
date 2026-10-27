-- Agents can authenticate by signing requests with an SSH key instead of a
-- bearer key: `agents` gains `auth_kind` ('bearer' or 'ssh-key'), the key's
-- normalised OpenSSH line (`public_key`) and its fingerprint, and `key_hash`
-- becomes nullable (a key-signed agent has no bearer key). SQLite cannot
-- relax NOT NULL or add such CHECKs in place, so `agents` is rebuilt. Both
-- `requests` and `grants` sit below it in the foreign-key chain, and
-- migrations run in one transaction, where `PRAGMA foreign_keys = OFF` has no
-- effect and a parent cannot be dropped while children point at it; as in
-- migration 0003 they are set aside in plain tables (no foreign keys),
-- dropped, recreated against the new `agents` and refilled, with their
-- rowids, so every foreign key is checked against rows that exist at each
-- step.
CREATE TABLE agents_stash AS SELECT rowid AS rid, * FROM agents;
CREATE TABLE requests_stash AS SELECT rowid AS rid, * FROM requests;
CREATE TABLE grants_stash AS SELECT rowid AS rid, * FROM grants;

DROP TABLE grants;
DROP TABLE requests;
DROP TABLE agents;

CREATE TABLE agents (name TEXT PRIMARY KEY, key_hash TEXT UNIQUE, created_at INTEGER NOT NULL, revoked_at INTEGER,
  auth_kind TEXT NOT NULL DEFAULT 'bearer' CHECK (auth_kind IN ('bearer','ssh-key')),
  public_key TEXT, key_fingerprint TEXT,
  CHECK (CASE auth_kind
    WHEN 'bearer' THEN key_hash IS NOT NULL AND public_key IS NULL AND key_fingerprint IS NULL
    ELSE key_hash IS NULL AND public_key IS NOT NULL AND key_fingerprint IS NOT NULL END));
INSERT INTO agents (rowid, name, key_hash, created_at, revoked_at)
  SELECT rid, name, key_hash, created_at, revoked_at FROM agents_stash;
DROP TABLE agents_stash;
-- One key enrols one agent: a shared key would let either agent's name sign.
CREATE UNIQUE INDEX agents_key_fingerprint ON agents(key_fingerprint) WHERE key_fingerprint IS NOT NULL;

CREATE TABLE requests (id TEXT PRIMARY KEY, agent TEXT NOT NULL REFERENCES agents(name), fingerprint TEXT NOT NULL,
  dedupe_key TEXT NOT NULL, body TEXT NOT NULL, approval_token_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','expired','revoked','error','cancelled')),
  error TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, decided_at INTEGER);
INSERT INTO requests (rowid, id, agent, fingerprint, dedupe_key, body, approval_token_hash, status, error,
  created_at, expires_at, decided_at)
  SELECT rid, id, agent, fingerprint, dedupe_key, body, approval_token_hash, status, error,
  created_at, expires_at, decided_at FROM requests_stash;
DROP TABLE requests_stash;

CREATE TABLE grants (id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE REFERENCES requests(id), agent TEXT NOT NULL,
  window_secs INTEGER NOT NULL, not_before INTEGER NOT NULL, not_after INTEGER NOT NULL, revoked_at INTEGER, view TEXT NOT NULL);
INSERT INTO grants (rowid, id, request_id, agent, window_secs, not_before, not_after, revoked_at, view)
  SELECT rid, id, request_id, agent, window_secs, not_before, not_after, revoked_at, view FROM grants_stash;
DROP TABLE grants_stash;

CREATE UNIQUE INDEX one_pending ON requests(dedupe_key) WHERE status = 'pending';
CREATE INDEX requests_created_at ON requests(created_at);
CREATE INDEX grants_not_after ON grants(not_after);

-- Nonces of accepted signed requests, kept until the request could no longer
-- be replayed inside the clock-skew window; `(agent, nonce)` is unique.
CREATE TABLE agent_nonces (agent TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL,
  PRIMARY KEY (agent, nonce));
CREATE INDEX agent_nonces_expires_at ON agent_nonces(expires_at);
