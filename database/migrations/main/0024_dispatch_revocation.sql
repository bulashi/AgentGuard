BEGIN;

ALTER TABLE audit_events DROP CONSTRAINT audit_event_version_type;
ALTER TABLE audit_events ADD CONSTRAINT audit_event_version_type CHECK (
    (schema_version = '1.0' AND event_type NOT IN (
        'COAUTH_ROOT_AUTHORIZED', 'COAUTH_REVOCATION_APPLIED', 'CREDENTIAL_REVOKED'
    ))
    OR (schema_version = '2.0' AND event_type = 'COAUTH_ROOT_AUTHORIZED' AND execution_id IS NULL)
    OR (schema_version = '3.0' AND event_type = 'COAUTH_REVOCATION_APPLIED' AND execution_id IS NULL)
    OR (schema_version = '4.0' AND event_type = 'CREDENTIAL_REVOKED' AND execution_id IS NULL)
);

CREATE TABLE dispatch_cancellations (
    cancellation_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL UNIQUE REFERENCES execution_records (execution_id),
    denial_execution_id TEXT NOT NULL UNIQUE REFERENCES execution_records (execution_id),
    request_id TEXT NOT NULL,
    request_hash TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    credential_chain_hash TEXT NOT NULL CHECK (credential_chain_hash ~ '^[0-9a-f]{64}$'),
    reason_code TEXT NOT NULL,
    evidence JSONB NOT NULL,
    cancelled_at BIGINT NOT NULL CHECK (cancelled_at BETWEEN 0 AND 9007199254740991),
    CHECK (execution_id <> denial_execution_id)
);

CREATE FUNCTION protect_dispatch_cancellation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'dispatch cancellation evidence is immutable' USING ERRCODE = '22023';
END;
$$;

CREATE TRIGGER dispatch_cancellation_immutable
    BEFORE UPDATE OR DELETE ON dispatch_cancellations
    FOR EACH ROW EXECUTE FUNCTION protect_dispatch_cancellation();

COMMIT;
