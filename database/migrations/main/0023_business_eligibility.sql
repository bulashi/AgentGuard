-- Business state extension only. Existing signed V1 objects and effects are unchanged.
ALTER TABLE tickets ADD COLUMN cloud_shareable BOOLEAN NOT NULL DEFAULT FALSE;
-- Only the three explicitly provisioned fixture identities may retain cloud access.
UPDATE tickets SET cloud_shareable = TRUE
WHERE (ticket_id = 'T10086' AND tenant_id = 'tenant-A' AND customer_id = 'C9527')
   OR (ticket_id = 'T10088' AND tenant_id = '演示企业' AND customer_id = '张三')
   OR (ticket_id = 'T10089' AND tenant_id = 'tenant-A' AND customer_id = 'C9528');

CREATE UNIQUE INDEX tickets_refund_identity
ON tickets (ticket_id, tenant_id, customer_id);

CREATE TABLE business_payment_verifications (
    tenant_id TEXT NOT NULL,
    original_transaction_id TEXT NOT NULL CHECK (length(original_transaction_id) BETWEEN 1 AND 128),
    customer_id TEXT NOT NULL,
    verification_status TEXT NOT NULL CHECK (verification_status IN ('VERIFIED', 'PENDING', 'REJECTED')),
    refundable_amount_fen BIGINT NOT NULL CHECK (refundable_amount_fen BETWEEN 0 AND 9007199254740991),
    evidence_reference TEXT NOT NULL CHECK (length(evidence_reference) BETWEEN 1 AND 512),
    verified_at BIGINT CHECK (verified_at BETWEEN 0 AND 9007199254740991),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (tenant_id, original_transaction_id),
    UNIQUE (tenant_id, original_transaction_id, customer_id),
    CHECK (verification_status <> 'VERIFIED' OR (refundable_amount_fen > 0 AND verified_at IS NOT NULL))
);

CREATE TABLE refund_eligibility (
    ticket_id TEXT NOT NULL,
    trusted_action_slot TEXT NOT NULL CHECK (trusted_action_slot IN ('primary-refund', 'approved-second-refund')),
    tenant_id TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    verification_status TEXT NOT NULL CHECK (verification_status IN ('VERIFIED', 'PENDING', 'REJECTED')),
    original_transaction_id TEXT,
    refund_reason_code TEXT NOT NULL CHECK (length(refund_reason_code) BETWEEN 1 AND 128),
    refundable_amount_fen BIGINT NOT NULL CHECK (refundable_amount_fen BETWEEN 0 AND 9007199254740991),
    evidence_reference TEXT NOT NULL CHECK (length(evidence_reference) BETWEEN 1 AND 512),
    verified_at BIGINT CHECK (verified_at BETWEEN 0 AND 9007199254740991),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (ticket_id, trusted_action_slot),
    UNIQUE (tenant_id, original_transaction_id, refund_reason_code, trusted_action_slot),
    FOREIGN KEY (ticket_id, tenant_id, customer_id) REFERENCES tickets (ticket_id, tenant_id, customer_id),
    FOREIGN KEY (tenant_id, original_transaction_id, customer_id)
        REFERENCES business_payment_verifications (tenant_id, original_transaction_id, customer_id),
    CHECK (verification_status <> 'VERIFIED' OR (
        original_transaction_id IS NOT NULL AND refundable_amount_fen > 0 AND verified_at IS NOT NULL
    ))
);

-- NULL groups identify legacy effects; they are retained, not assigned invented facts.
ALTER TABLE refunds ADD COLUMN original_transaction_id TEXT;
ALTER TABLE refunds ADD COLUMN refund_reason_code TEXT;
ALTER TABLE refunds ADD COLUMN trusted_action_slot TEXT;
ALTER TABLE refunds ADD COLUMN refund_business_key TEXT;
ALTER TABLE refunds ADD CONSTRAINT refunds_business_extension_complete CHECK (
    (original_transaction_id IS NULL AND refund_reason_code IS NULL
        AND trusted_action_slot IS NULL AND refund_business_key IS NULL)
    OR (original_transaction_id IS NOT NULL AND refund_reason_code IS NOT NULL
        AND trusted_action_slot IS NOT NULL
        AND trusted_action_slot IN ('primary-refund', 'approved-second-refund')
        AND refund_business_key IS NOT NULL AND refund_business_key ~ '^[0-9a-f]{64}$')
);
ALTER TABLE refunds ADD CONSTRAINT refunds_original_payment_binding
FOREIGN KEY (tenant_id, original_transaction_id, customer_id)
REFERENCES business_payment_verifications (tenant_id, original_transaction_id, customer_id);
CREATE UNIQUE INDEX refunds_business_once ON refunds (refund_business_key)
WHERE refund_business_key IS NOT NULL;
CREATE UNIQUE INDEX refunds_original_business_once
ON refunds (tenant_id, original_transaction_id, refund_reason_code, trusted_action_slot)
WHERE original_transaction_id IS NOT NULL;
CREATE INDEX refunds_original_payment ON refunds (tenant_id, original_transaction_id);
