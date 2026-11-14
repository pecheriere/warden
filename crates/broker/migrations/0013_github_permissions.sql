-- The permission set of each GitHub token request, fixed when it is created: the
-- owner's default at that time plus the extras it asked for. A request with no row
-- here was stored before 0.15 and means the legacy set
-- (contents:write,issues:write,metadata:read,pull_requests:write), never the
-- default configured now.
--
-- `permissions` is the full set in its written form (sorted by name, `name:level`
-- joined with `,`). `beyond_default` is the extras the default did not cover, in the
-- same form without `metadata:read`, or the empty string when there are none: it
-- keeps the approval page's marking stable when the owner later changes the default.
CREATE TABLE github_permissions (
    request_id     TEXT PRIMARY KEY REFERENCES requests(id),
    permissions    TEXT NOT NULL,
    beyond_default TEXT NOT NULL
);
