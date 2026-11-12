-- GitHub tokens are limited per agent per hour, counted here: the hour (Unix
-- seconds / 3600) an agent last minted in, and its tokens that hour.
-- The `mint_hour` and `mint_count` columns that 0009 added to `grants` are no
-- longer read or written; a later migration may drop them.
CREATE TABLE github_token_mints (
  agent TEXT PRIMARY KEY,
  mint_hour INTEGER NOT NULL,
  mint_count INTEGER NOT NULL
);

-- What the repository names of a GitHub token request resolved to: the repositories
-- the owner is shown and approves. The row is written when the owner first opens the
-- approval page, or, for a renewal, when the renewal is created.
CREATE TABLE github_repositories (
  request_id TEXT PRIMARY KEY REFERENCES requests(id),
  resolution TEXT NOT NULL
);
