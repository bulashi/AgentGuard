BEGIN;

-- A replayed request already owns an execution_requests row.  Keep the
-- original execution immutable and persist each replay denial separately so
-- it can receive its own signed DENY receipt and audit evidence.
CREATE TABLE replay_denial_attempts (
    attempt_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    request_hash TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    original_execution_id TEXT NOT NULL REFERENCES execution_records (execution_id),
    denial_execution_id TEXT NOT NULL UNIQUE REFERENCES execution_records (execution_id),
    reason_code TEXT NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at >= 0)
);

CREATE INDEX idx_replay_denial_attempts_request
    ON replay_denial_attempts (request_id, created_at);

CREATE INDEX idx_replay_denial_attempts_original_execution
    ON replay_denial_attempts (original_execution_id);

COMMIT;
