BEGIN;

-- A durable signed receipt is the authoritative finalization evidence for its execution.
-- Repair retryable execution rows left by an interrupted receipt-recovery attempt.
UPDATE execution_records e
SET receipt_status = 'SIGNED',
    updated_at = GREATEST(e.updated_at, r.updated_at)
FROM execution_receipts r
WHERE r.execution_id = e.execution_id
  AND r.receipt_status = 'SIGNED'
  AND e.receipt_status <> 'SIGNED';

COMMIT;
