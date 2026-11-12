-- GitHub tokens are limited per agent per hour, counted here: the hour (Unix
-- seconds / 3600) an agent last minted in, and its tokens that hour.
-- The `mint_hour` and `mint_count` columns that 0009 added to `grants` are no
-- longer read or written; a later migration may drop them.
CREATE TABLE github_token_mints (
  agent TEXT PRIMARY KEY,
  mint_hour INTEGER NOT NULL,
  mint_count INTEGER NOT NULL
);

-- What the repository names of a GitHub token request resolved to when it was
-- made: the repositories the owner is shown and approves.
CREATE TABLE github_repositories (
  request_id TEXT PRIMARY KEY REFERENCES requests(id),
  resolution TEXT NOT NULL
);
