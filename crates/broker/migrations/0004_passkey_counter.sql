-- The signature counter of each passkey gets its own column so it can be
-- raised atomically (`UPDATE ... WHERE counter < ?`) and never lowered by a
-- late, concurrent approval. It is backfilled from the counter inside the
-- stored credential JSON (`Passkey` serialises as {"cred":{"counter":N,...}});
-- a credential without one starts at 0.
ALTER TABLE passkeys ADD COLUMN counter INTEGER NOT NULL DEFAULT 0;
UPDATE passkeys SET counter = COALESCE(json_extract(credential, '$.cred.counter'), 0);
