-- Lookups of live access (key binding on create, the relay's login check)
-- read only recent requests and unexpired grants; these keep them from
-- scanning the whole history.
CREATE INDEX requests_created_at ON requests(created_at);
CREATE INDEX grants_not_after ON grants(not_after);
