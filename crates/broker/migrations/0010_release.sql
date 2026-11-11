-- What the broker read from GitHub when a release request was made, as JSON: the
-- facts the owner approved, kept so that a step can be checked against them.
CREATE TABLE release_facts (
    request_id TEXT PRIMARY KEY REFERENCES requests(id),
    facts TEXT NOT NULL
);

-- The steps of a release grant that were claimed, and when. A step is claimed
-- once, before it is done, so that a repeat or a retry never does it twice.
-- Null means not claimed yet.
CREATE TABLE release_steps (
    grant_id TEXT PRIMARY KEY REFERENCES grants(id),
    tag_claimed_at INTEGER,
    manifest_claimed_at INTEGER,
    manifest_sha256 TEXT,
    signature_sha256 TEXT,
    publish_claimed_at INTEGER
);
