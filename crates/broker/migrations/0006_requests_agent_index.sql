-- The per-agent request limits read an agent's recent requests on every
-- create; this keeps them from reading its whole history, or anyone else's.
CREATE INDEX requests_agent_created_at ON requests(agent, created_at);
