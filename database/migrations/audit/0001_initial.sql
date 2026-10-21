BEGIN;

CREATE TABLE audit_checkpoints (
    checkpoint_sequence BIGINT PRIMARY KEY CHECK (checkpoint_sequence > 0),
    latest_event_sequence BIGINT NOT NULL CHECK (latest_event_sequence > 0),
    latest_event_hash TEXT NOT NULL CHECK (latest_event_hash ~ '^[0-9a-f]{64}$'),
    checkpoint_timestamp BIGINT NOT NULL CHECK (checkpoint_timestamp >= 0),
    signer_key_id TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL CHECK (signature_algorithm = 'SM2'),
    signature_encoding TEXT NOT NULL CHECK (signature_encoding = 'SM2_RS_HEX_128_LOWERCASE'),
    signature_value TEXT NOT NULL CHECK (signature_value ~ '^[0-9a-f]{128}$'),
    signed_checkpoint JSONB NOT NULL,
    received_at BIGINT NOT NULL CHECK (received_at >= checkpoint_timestamp),
    UNIQUE (latest_event_sequence),
    UNIQUE (latest_event_hash)
);

COMMIT;
