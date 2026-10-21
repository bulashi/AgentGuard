BEGIN;

CREATE TABLE execution_budget_reservations (
    execution_id TEXT NOT NULL REFERENCES execution_records (execution_id),
    credential_id TEXT NOT NULL REFERENCES credentials (credential_id),
    quota_type TEXT NOT NULL CHECK (quota_type IN ('refund_total_fen', 'max_tool_calls')),
    amount BIGINT NOT NULL CHECK (amount > 0 AND amount <= 9007199254740991),
    status TEXT NOT NULL CHECK (status IN ('RESERVED', 'COMMITTED', 'RELEASED')),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (execution_id, credential_id, quota_type)
);

CREATE INDEX idx_budget_reservations_credential
    ON execution_budget_reservations (credential_id, quota_type, status);

COMMIT;
