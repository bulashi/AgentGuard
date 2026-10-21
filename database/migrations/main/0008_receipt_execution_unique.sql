BEGIN;

CREATE UNIQUE INDEX IF NOT EXISTS uq_execution_receipts_execution_id
    ON execution_receipts (execution_id);

COMMIT;
