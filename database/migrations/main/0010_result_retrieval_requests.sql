BEGIN;

-- Retrieval requests have their own replay namespace.  They never create an
-- execution record, budget reservation, tool attempt, or business effect.
CREATE TABLE result_retrieval_requests (
    request_id TEXT PRIMARY KEY,
    request_hash TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    task_id TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('EXECUTION', 'RECEIPT')),
    target_id TEXT NOT NULL,
    execution_id TEXT REFERENCES execution_records (execution_id),
    receipt_id TEXT REFERENCES execution_receipts (receipt_id),
    outcome TEXT NOT NULL CHECK (outcome IN ('ALLOWED', 'DENIED')),
    reason_code TEXT NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at >= 0)
);

CREATE INDEX idx_result_retrieval_target
    ON result_retrieval_requests (target_type, target_id);

CREATE INDEX idx_result_retrieval_execution
    ON result_retrieval_requests (execution_id);

COMMIT;
