-- Primary source for Session Encryption Keys (SEK), per requirement PDF
-- pp.12-14. The spec calls for a SQL Server memory-optimized, physically
-- partitioned table with per-partition TRUNCATE for cleanup; Postgres has
-- no equivalent, so this is a plain table with a btree index on
-- expiration_bucket and a DELETE-based cleanup job instead (see
-- auth-service/src/pds/cleanupJob.ts). Documented deviation, not an
-- oversight — see docs/encryption-workflow.md.

CREATE TABLE IF NOT EXISTS session_encryption_key (
  session_id              CHAR(32)    PRIMARY KEY,
  wrapped_encryption_key  BYTEA       NOT NULL CHECK (octet_length(wrapped_encryption_key) = 40),
  device_public_key       BYTEA       NOT NULL CHECK (octet_length(device_public_key) = 91),
  expiration_bucket       SMALLINT    NOT NULL CHECK (expiration_bucket BETWEEN 0 AND 23),
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sek_expiration_bucket ON session_encryption_key (expiration_bucket);
