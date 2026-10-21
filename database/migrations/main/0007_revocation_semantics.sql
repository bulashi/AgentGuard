BEGIN;

ALTER TABLE credential_revocations
    RENAME COLUMN reason TO revocation_reason;

CREATE INDEX idx_credential_revocations_time
    ON credential_revocations (revoked_at, credential_id);

COMMIT;
