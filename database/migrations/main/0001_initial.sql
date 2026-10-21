BEGIN;

CREATE TYPE key_state AS ENUM ('ACTIVE', 'RETIRED', 'REVOKED', 'COMPROMISED');
CREATE TYPE key_material_state AS ENUM ('PRESENT', 'DESTROYED');
CREATE TYPE key_purpose AS ENUM (
    'AUTHORIZATION_ROOT_SIGNING',
    'AGENT_HOLDER_SIGNING',
    'GATEWAY_EXECUTION_SIGNING',
    'EXECUTION_RECEIPT_SIGNING',
    'AUDIT_CHECKPOINT_SIGNING'
);
CREATE TYPE credential_type AS ENUM ('ROOT', 'DELEGATION');
CREATE TYPE task_status AS ENUM ('PENDING_AUTHORIZATION', 'AUTHORIZED', 'CLOSED');
CREATE TYPE business_action_status AS ENUM ('ACTIVE', 'COMMITTED', 'RELEASED', 'CONFLICT');
CREATE TYPE execution_state AS ENUM (
    'RECEIVED',
    'DENIED',
    'ADMITTED',
    'DISPATCHED',
    'UNKNOWN',
    'RECONCILING',
    'COMMITTED',
    'RELEASED',
    'RECOVERY_FAILED_FINAL'
);
CREATE TYPE receipt_status AS ENUM ('NOT_REQUIRED', 'PENDING', 'SIGNED', 'FAILED_RETRYABLE');
CREATE TYPE receipt_type AS ENUM ('EXECUTION_RESULT', 'AUTHORIZATION_DENIAL');
CREATE TYPE authorization_decision AS ENUM ('ALLOW', 'DENY');
CREATE TYPE idempotency_status AS ENUM (
    'IN_PROGRESS',
    'ADMITTED',
    'DISPATCHED',
    'UNKNOWN',
    'RECONCILING',
    'COMMITTED',
    'RELEASED'
);
CREATE TYPE tool_outcome AS ENUM ('SUCCESS', 'FAILED_NO_EFFECT', 'UNKNOWN');
CREATE TYPE audit_outbox_status AS ENUM ('PENDING', 'APPENDED', 'FAILED_RETRYABLE');

CREATE TABLE agent_identities (
    agent_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    agent_type TEXT NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at >= 0)
);

CREATE TABLE key_registry (
    key_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL,
    purpose key_purpose NOT NULL,
    algorithm TEXT NOT NULL CHECK (algorithm = 'SM2'),
    public_key_hex TEXT NOT NULL CHECK (public_key_hex ~ '^[0-9a-f]{128}$'),
    status key_state NOT NULL,
    material_state key_material_state NOT NULL,
    private_key_reference TEXT,
    activated_at BIGINT NOT NULL CHECK (activated_at >= 0),
    retired_at BIGINT CHECK (retired_at IS NULL OR retired_at >= activated_at),
    revoked_at BIGINT CHECK (revoked_at IS NULL OR revoked_at >= activated_at),
    compromised_at BIGINT CHECK (compromised_at IS NULL OR compromised_at >= activated_at),
    destroyed_at BIGINT CHECK (destroyed_at IS NULL OR destroyed_at >= activated_at),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    UNIQUE (subject_id, purpose, key_id)
);

CREATE INDEX idx_key_registry_subject_purpose ON key_registry (subject_id, purpose, status);

CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    ticket_id TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    refund_total_fen BIGINT NOT NULL CHECK (refund_total_fen BETWEEN 0 AND 9007199254740991),
    max_tool_calls BIGINT NOT NULL CHECK (max_tool_calls BETWEEN 0 AND 9007199254740991),
    expires_at BIGINT NOT NULL CHECK (expires_at >= 0),
    status task_status NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at)
);

CREATE INDEX idx_tasks_tenant_ticket ON tasks (tenant_id, ticket_id);

CREATE TABLE credentials (
    credential_id TEXT PRIMARY KEY,
    credential_type credential_type NOT NULL,
    parent_credential_id TEXT REFERENCES credentials (credential_id),
    parent_credential_hash TEXT CHECK (parent_credential_hash IS NULL OR parent_credential_hash ~ '^[0-9a-f]{64}$'),
    signed_object_hash TEXT NOT NULL UNIQUE CHECK (signed_object_hash ~ '^[0-9a-f]{64}$'),
    signed_object JSONB NOT NULL,
    issuer_subject_id TEXT NOT NULL,
    issuer_key_id TEXT NOT NULL REFERENCES key_registry (key_id),
    holder_agent_id TEXT NOT NULL REFERENCES agent_identities (agent_id),
    holder_key_id TEXT NOT NULL REFERENCES key_registry (key_id),
    tenant_id TEXT NOT NULL,
    task_id TEXT NOT NULL REFERENCES tasks (task_id),
    verifier_audience TEXT NOT NULL CHECK (verifier_audience = 'secure-tool-gateway'),
    not_before BIGINT NOT NULL CHECK (not_before >= 0),
    expires_at BIGINT NOT NULL CHECK (expires_at >= not_before),
    delegation_depth INTEGER NOT NULL CHECK (delegation_depth BETWEEN 0 AND 16),
    issued_at BIGINT NOT NULL CHECK (issued_at BETWEEN not_before AND expires_at),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    CHECK (
        (credential_type = 'ROOT' AND parent_credential_id IS NULL AND parent_credential_hash IS NULL)
        OR
        (credential_type = 'DELEGATION' AND parent_credential_id IS NOT NULL AND parent_credential_hash IS NOT NULL)
    )
);

CREATE INDEX idx_credentials_task_holder ON credentials (task_id, holder_agent_id);
CREATE INDEX idx_credentials_parent ON credentials (parent_credential_id);

CREATE TABLE credential_revocations (
    credential_id TEXT PRIMARY KEY REFERENCES credentials (credential_id),
    revoked_at BIGINT NOT NULL CHECK (revoked_at >= 0),
    revoked_by TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 256)
);

CREATE TABLE credential_budget_state (
    credential_id TEXT NOT NULL REFERENCES credentials (credential_id),
    quota_type TEXT NOT NULL CHECK (quota_type IN ('refund_total_fen', 'max_tool_calls')),
    limit_value BIGINT NOT NULL CHECK (limit_value BETWEEN 0 AND 9007199254740991),
    reserved_value BIGINT NOT NULL DEFAULT 0 CHECK (reserved_value BETWEEN 0 AND 9007199254740991),
    committed_value BIGINT NOT NULL DEFAULT 0 CHECK (committed_value BETWEEN 0 AND 9007199254740991),
    version BIGINT NOT NULL DEFAULT 0 CHECK (version >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= 0),
    PRIMARY KEY (credential_id, quota_type),
    CHECK (reserved_value + committed_value <= limit_value)
);

CREATE TABLE business_actions (
    business_action_id TEXT PRIMARY KEY,
    action_scope_key TEXT NOT NULL UNIQUE CHECK (action_scope_key ~ '^[0-9a-f]{64}$'),
    trusted_action_slot TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    task_id TEXT NOT NULL REFERENCES tasks (task_id),
    tool_service TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    status business_action_status NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at)
);

CREATE TABLE execution_records (
    execution_id TEXT PRIMARY KEY,
    initial_request_id TEXT NOT NULL UNIQUE,
    request_hash TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    credential_chain_hash TEXT NOT NULL CHECK (credential_chain_hash ~ '^[0-9a-f]{64}$'),
    tenant_id TEXT NOT NULL,
    task_id TEXT NOT NULL REFERENCES tasks (task_id),
    tool_service TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    parameter_hash TEXT NOT NULL CHECK (parameter_hash ~ '^[0-9a-f]{64}$'),
    state execution_state NOT NULL,
    decision authorization_decision,
    reason_code TEXT,
    receipt_status receipt_status NOT NULL DEFAULT 'NOT_REQUIRED',
    business_action_id TEXT REFERENCES business_actions (business_action_id),
    result JSONB,
    business_effect_id TEXT,
    business_result_hash TEXT CHECK (business_result_hash IS NULL OR business_result_hash ~ '^[0-9a-f]{64}$'),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at)
);

CREATE INDEX idx_execution_records_task_state ON execution_records (task_id, state);
CREATE INDEX idx_execution_records_business_action ON execution_records (business_action_id);

CREATE TABLE execution_requests (
    request_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL REFERENCES execution_records (execution_id),
    request_hash TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    issued_at BIGINT NOT NULL CHECK (issued_at >= 0),
    received_at BIGINT NOT NULL CHECK (received_at >= 0),
    admission_outcome TEXT,
    UNIQUE (request_id)
);

CREATE TABLE replay_records (
    request_id TEXT PRIMARY KEY REFERENCES execution_requests (request_id),
    request_hash TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    first_seen_at BIGINT NOT NULL CHECK (first_seen_at >= 0)
);

CREATE TABLE idempotency_records (
    business_idempotency_key TEXT PRIMARY KEY CHECK (business_idempotency_key ~ '^[0-9a-f]{64}$'),
    business_action_id TEXT NOT NULL UNIQUE REFERENCES business_actions (business_action_id),
    parameter_hash TEXT NOT NULL CHECK (parameter_hash ~ '^[0-9a-f]{64}$'),
    execution_id TEXT NOT NULL UNIQUE REFERENCES execution_records (execution_id),
    status idempotency_status NOT NULL,
    result JSONB,
    business_effect_id TEXT,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at)
);

CREATE TABLE tool_execution_attempts (
    execution_attempt_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL REFERENCES execution_records (execution_id),
    envelope_hash TEXT NOT NULL CHECK (envelope_hash ~ '^[0-9a-f]{64}$'),
    received_at BIGINT NOT NULL CHECK (received_at >= 0),
    status TEXT NOT NULL CHECK (status IN ('RECEIVED', 'ACCEPTED', 'REJECTED', 'COMPLETED')),
    tool_outcome tool_outcome,
    UNIQUE (execution_attempt_id)
);

CREATE INDEX idx_tool_attempt_execution ON tool_execution_attempts (execution_id);

CREATE TABLE execution_receipts (
    receipt_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL REFERENCES execution_records (execution_id),
    receipt_type receipt_type NOT NULL,
    decision authorization_decision NOT NULL,
    reason_code TEXT NOT NULL,
    signed_receipt JSONB NOT NULL,
    receipt_hash TEXT NOT NULL UNIQUE CHECK (receipt_hash ~ '^[0-9a-f]{64}$'),
    receipt_status receipt_status NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at),
    UNIQUE (receipt_id)
);

CREATE INDEX idx_execution_receipts_execution ON execution_receipts (execution_id);

CREATE TABLE tickets (
    ticket_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED')),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at)
);

CREATE TABLE knowledge_documents (
    document_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    sensitivity TEXT NOT NULL CHECK (sensitivity IN ('INTERNAL', 'RESTRICTED')),
    created_at BIGINT NOT NULL CHECK (created_at >= 0)
);

CREATE TABLE ticket_document_relations (
    ticket_id TEXT NOT NULL REFERENCES tickets (ticket_id),
    document_id TEXT NOT NULL REFERENCES knowledge_documents (document_id),
    PRIMARY KEY (ticket_id, document_id)
);

CREATE TABLE refunds (
    refund_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL UNIQUE REFERENCES execution_records (execution_id),
    business_action_id TEXT NOT NULL UNIQUE REFERENCES business_actions (business_action_id),
    business_idempotency_key TEXT NOT NULL UNIQUE CHECK (business_idempotency_key ~ '^[0-9a-f]{64}$'),
    parameter_hash TEXT NOT NULL CHECK (parameter_hash ~ '^[0-9a-f]{64}$'),
    tenant_id TEXT NOT NULL,
    task_id TEXT NOT NULL REFERENCES tasks (task_id),
    ticket_id TEXT NOT NULL REFERENCES tickets (ticket_id),
    customer_id TEXT NOT NULL,
    amount_fen BIGINT NOT NULL CHECK (amount_fen BETWEEN 1 AND 9007199254740991),
    status TEXT NOT NULL CHECK (status IN ('COMMITTED', 'REVERSED')),
    created_at BIGINT NOT NULL CHECK (created_at >= 0)
);

CREATE TABLE notifications (
    notification_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL UNIQUE REFERENCES execution_records (execution_id),
    business_action_id TEXT NOT NULL UNIQUE REFERENCES business_actions (business_action_id),
    business_idempotency_key TEXT NOT NULL UNIQUE CHECK (business_idempotency_key ~ '^[0-9a-f]{64}$'),
    parameter_hash TEXT NOT NULL CHECK (parameter_hash ~ '^[0-9a-f]{64}$'),
    tenant_id TEXT NOT NULL,
    task_id TEXT NOT NULL REFERENCES tasks (task_id),
    customer_id TEXT NOT NULL,
    template_id TEXT NOT NULL CHECK (template_id IN ('REFUND_SUCCESS')),
    related_business_effect_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('SENT')),
    created_at BIGINT NOT NULL CHECK (created_at >= 0)
);

CREATE TABLE audit_outbox (
    outbox_event_id TEXT PRIMARY KEY,
    execution_id TEXT REFERENCES execution_records (execution_id),
    event_type TEXT NOT NULL,
    evidence_reference TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
    payload JSONB NOT NULL,
    status audit_outbox_status NOT NULL DEFAULT 'PENDING',
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    appended_at BIGINT CHECK (appended_at IS NULL OR appended_at >= created_at),
    UNIQUE (outbox_event_id)
);

CREATE TABLE audit_chain_head (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    latest_event_sequence BIGINT NOT NULL CHECK (latest_event_sequence >= 0),
    latest_event_hash TEXT NOT NULL CHECK (latest_event_hash ~ '^[0-9a-f]{64}$'),
    updated_at BIGINT NOT NULL CHECK (updated_at >= 0)
);

INSERT INTO audit_chain_head (singleton, latest_event_sequence, latest_event_hash, updated_at)
VALUES (TRUE, 0, repeat('0', 64), 0);

CREATE TABLE audit_events (
    event_sequence BIGINT PRIMARY KEY CHECK (event_sequence > 0),
    event_id TEXT NOT NULL UNIQUE,
    outbox_event_id TEXT NOT NULL UNIQUE REFERENCES audit_outbox (outbox_event_id),
    execution_id TEXT REFERENCES execution_records (execution_id),
    event_type TEXT NOT NULL,
    event_timestamp BIGINT NOT NULL CHECK (event_timestamp >= 0),
    payload_hash TEXT NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
    evidence_reference TEXT NOT NULL,
    previous_event_hash TEXT NOT NULL CHECK (previous_event_hash ~ '^[0-9a-f]{64}$'),
    event_hash TEXT NOT NULL UNIQUE CHECK (event_hash ~ '^[0-9a-f]{64}$')
);

COMMIT;

