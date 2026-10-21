BEGIN;

CREATE TABLE benchmark_principals (
    mode TEXT NOT NULL CHECK (mode IN ('shared_static_credential', 'conventional_rbac')),
    run_id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    token_hash TEXT NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    agent_role TEXT NOT NULL,
    tenant_scope TEXT,
    service_permissions JSONB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    revoked_at BIGINT,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (mode, run_id)
);

CREATE TABLE benchmark_workloads (
    mode TEXT NOT NULL CHECK (mode IN ('shared_static_credential', 'conventional_rbac')),
    workload_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL UNIQUE REFERENCES tasks (task_id),
    intended_tenant_id TEXT NOT NULL,
    intended_ticket_id TEXT NOT NULL,
    intended_customer_id TEXT NOT NULL,
    refund_total_fen BIGINT NOT NULL CHECK (refund_total_fen >= 0),
    max_tool_calls BIGINT NOT NULL CHECK (max_tool_calls >= 0),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (mode, workload_id),
    FOREIGN KEY (mode, run_id) REFERENCES benchmark_principals (mode, run_id)
);

CREATE TABLE benchmark_operations (
    mode TEXT NOT NULL,
    workload_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    parameter_hash TEXT NOT NULL CHECK (parameter_hash ~ '^[0-9a-f]{64}$'),
    execution_id TEXT NOT NULL UNIQUE REFERENCES execution_records (execution_id),
    state TEXT NOT NULL CHECK (state IN ('DISPATCHED', 'COMMITTED', 'RELEASED')),
    result JSONB,
    business_effect_id TEXT,
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at),
    PRIMARY KEY (mode, workload_id, operation_id),
    FOREIGN KEY (mode, workload_id) REFERENCES benchmark_workloads (mode, workload_id)
);

CREATE TABLE benchmark_requests (
    mode TEXT NOT NULL,
    request_id TEXT NOT NULL,
    workload_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    request_hash TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    parameter_hash TEXT NOT NULL CHECK (parameter_hash ~ '^[0-9a-f]{64}$'),
    decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY')),
    reason_code TEXT NOT NULL,
    execution_id TEXT,
    business_effect_id TEXT,
    persistence_ns BIGINT NOT NULL CHECK (persistence_ns >= 0),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    PRIMARY KEY (mode, request_id),
    FOREIGN KEY (mode, workload_id) REFERENCES benchmark_workloads (mode, workload_id)
);

CREATE TABLE benchmark_ablation_budget_runs (
    run_id TEXT PRIMARY KEY,
    limit_value BIGINT NOT NULL CHECK (limit_value >= 0),
    observed_committed BIGINT NOT NULL DEFAULT 0 CHECK (observed_committed >= 0),
    created_at BIGINT NOT NULL CHECK (created_at >= 0)
);

CREATE TABLE benchmark_ablation_effects (
    effect_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    logical_operation_id TEXT NOT NULL,
    amount_fen BIGINT NOT NULL CHECK (amount_fen > 0),
    created_at BIGINT NOT NULL CHECK (created_at >= 0)
);

COMMIT;
