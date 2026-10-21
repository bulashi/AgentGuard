BEGIN;

ALTER TABLE audit_events ADD COLUMN schema_version TEXT NOT NULL DEFAULT '1.0';
ALTER TABLE audit_events ADD CONSTRAINT audit_event_version_type CHECK (
    (schema_version = '1.0' AND event_type <> 'COAUTH_ROOT_AUTHORIZED')
    OR (schema_version = '2.0' AND event_type = 'COAUTH_ROOT_AUTHORIZED'
        AND execution_id IS NULL)
);

COMMIT;
