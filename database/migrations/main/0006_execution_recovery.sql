BEGIN;

CREATE TABLE execution_recovery_records (
    execution_id TEXT PRIMARY KEY REFERENCES execution_records (execution_id),
    recovery_attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (recovery_attempt_count >= 0),
    max_recovery_attempts BIGINT NOT NULL CHECK (max_recovery_attempts BETWEEN 1 AND 100),
    recovery_deadline BIGINT NOT NULL CHECK (recovery_deadline >= 0),
    final_failure_reason TEXT,
    manual_review_required BOOLEAN NOT NULL DEFAULT FALSE,
    last_error TEXT,
    last_attempt_at BIGINT,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at)
);

CREATE INDEX idx_execution_recovery_open
    ON execution_recovery_records (recovery_deadline, recovery_attempt_count)
    WHERE manual_review_required = FALSE;

COMMIT;
