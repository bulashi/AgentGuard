CREATE TABLE agent_workflow_runs (
    run_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL UNIQUE REFERENCES tasks(task_id),
    runtime_mode TEXT NOT NULL CHECK (runtime_mode IN ('deterministic', 'local', 'cloud')),
    scenario TEXT NOT NULL CHECK (scenario IN ('normal', 'policy_injection')),
    model TEXT,
    state TEXT NOT NULL CHECK (state IN ('QUEUED', 'RUNNING', 'COMPLETED', 'DENIED', 'FAILED')),
    reason_code TEXT,
    observation_token_hash TEXT NOT NULL,
    next_sequence INTEGER NOT NULL DEFAULT 0 CHECK (next_sequence BETWEEN 0 AND 128),
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    deadline_at_ms BIGINT NOT NULL,
    finished_at_ms BIGINT,
    CHECK (deadline_at_ms > created_at_ms)
);

CREATE TABLE agent_workflow_events (
    run_id TEXT NOT NULL REFERENCES agent_workflow_runs(run_id),
    sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 128),
    agent_id TEXT NOT NULL CHECK (agent_id IN (
        'agent-coordinator', 'agent-knowledge', 'agent-case', 'agent-refund'
    )),
    action TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('RUNNING', 'COMPLETED', 'DENIED', 'FAILED')),
    timestamp_ms BIGINT NOT NULL,
    recorded_at_ms BIGINT NOT NULL,
    details JSONB NOT NULL,
    PRIMARY KEY (run_id, sequence),
    CHECK (jsonb_typeof(details) = 'object')
);

CREATE INDEX agent_workflow_runs_created_idx ON agent_workflow_runs(created_at_ms DESC);

COMMENT ON TABLE agent_workflow_events IS
    'Operational observations only; not signed execution receipts or security audit events.';
