-- New cases store facts only. Qualification is derived after the task starts.
CREATE TABLE business_case_facts (
    ticket_id TEXT PRIMARY KEY REFERENCES tickets (ticket_id),
    tenant_id TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    order_id TEXT NOT NULL CHECK (length(order_id) BETWEEN 1 AND 128),
    facts JSONB NOT NULL CHECK (jsonb_typeof(facts) = 'object'),
    facts_hash TEXT NOT NULL CHECK (facts_hash ~ '^[0-9a-f]{64}$'),
    created_at BIGINT NOT NULL CHECK (created_at BETWEEN 0 AND 9007199254740991),
    UNIQUE (tenant_id, order_id),
    UNIQUE (ticket_id, tenant_id, customer_id),
    FOREIGN KEY (ticket_id, tenant_id, customer_id)
        REFERENCES tickets (ticket_id, tenant_id, customer_id)
);

-- A payment cannot be relabelled as a different ticket or order to repeat a refund.
CREATE TABLE business_case_payment_ids (
    tenant_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL CHECK (length(transaction_id) BETWEEN 1 AND 128),
    ticket_id TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, transaction_id),
    FOREIGN KEY (ticket_id, tenant_id, customer_id)
        REFERENCES business_case_facts (ticket_id, tenant_id, customer_id)
);

CREATE TABLE business_fact_evaluations (
    task_id TEXT PRIMARY KEY REFERENCES tasks (task_id),
    ticket_id TEXT NOT NULL REFERENCES business_case_facts (ticket_id),
    facts_hash TEXT NOT NULL CHECK (facts_hash ~ '^[0-9a-f]{64}$'),
    result JSONB NOT NULL CHECK (jsonb_typeof(result) = 'object'),
    created_at BIGINT NOT NULL CHECK (created_at BETWEEN 0 AND 9007199254740991)
);
CREATE INDEX business_fact_evaluations_ticket ON business_fact_evaluations (ticket_id);

CREATE FUNCTION reject_business_fact_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'business facts and first evaluation snapshots are immutable'
        USING ERRCODE = '55000';
END;
$$;
CREATE TRIGGER business_case_facts_immutable BEFORE UPDATE OR DELETE ON business_case_facts
FOR EACH ROW EXECUTE FUNCTION reject_business_fact_mutation();
CREATE TRIGGER business_case_payment_ids_immutable BEFORE UPDATE OR DELETE
ON business_case_payment_ids FOR EACH ROW EXECUTE FUNCTION reject_business_fact_mutation();
CREATE TRIGGER business_fact_evaluations_immutable BEFORE UPDATE OR DELETE
ON business_fact_evaluations FOR EACH ROW EXECUTE FUNCTION reject_business_fact_mutation();
