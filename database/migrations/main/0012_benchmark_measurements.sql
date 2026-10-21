BEGIN;

CREATE TABLE benchmark_measurement_samples (
    sample_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at BIGINT NOT NULL CHECK (created_at >= 0)
);

CREATE INDEX idx_benchmark_measurement_run
ON benchmark_measurement_samples (run_id, created_at);

COMMIT;
