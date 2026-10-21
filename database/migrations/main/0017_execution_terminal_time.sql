BEGIN;

ALTER TABLE execution_records
    ADD COLUMN terminal_at BIGINT,
    ADD COLUMN terminal_state execution_state,
    ADD CONSTRAINT execution_terminal_time_pair CHECK (
        (terminal_at IS NULL AND terminal_state IS NULL)
        OR (
            terminal_at IS NOT NULL AND terminal_state IS NOT NULL
            AND terminal_at BETWEEN created_at AND 9007199254740991
            AND terminal_state IN ('DENIED', 'COMMITTED', 'RELEASED')
            AND terminal_state = state
        )
    );

-- Existing terminal rows remain unobserved; updated_at is not a historical finalization source.
CREATE FUNCTION capture_execution_terminal_time() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    observed_at BIGINT;
    entering_terminal BOOLEAN;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.terminal_at IS NOT NULL OR NEW.terminal_state IS NOT NULL THEN
            RAISE EXCEPTION 'execution terminal time is database-managed'
                USING ERRCODE = '22023';
        END IF;
        entering_terminal := NEW.state IN ('DENIED', 'COMMITTED', 'RELEASED');
    ELSE
        IF NEW.terminal_at IS DISTINCT FROM OLD.terminal_at
           OR NEW.terminal_state IS DISTINCT FROM OLD.terminal_state THEN
            RAISE EXCEPTION 'execution terminal time cannot be supplied or changed'
                USING ERRCODE = '22023';
        END IF;
        IF OLD.state IN ('DENIED', 'COMMITTED', 'RELEASED')
           AND NEW.state IS DISTINCT FROM OLD.state THEN
            RAISE EXCEPTION 'execution terminal state cannot be changed'
                USING ERRCODE = '22023';
        END IF;
        entering_terminal := NEW.state IN ('DENIED', 'COMMITTED', 'RELEASED')
            AND OLD.state NOT IN ('DENIED', 'COMMITTED', 'RELEASED');
    END IF;

    IF entering_terminal THEN
        observed_at := floor(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT;
        IF observed_at < NEW.created_at OR observed_at > 9007199254740991 THEN
            RAISE EXCEPTION 'database terminal clock is outside the execution time range'
                USING ERRCODE = '22023';
        END IF;
        NEW.terminal_at := observed_at;
        NEW.terminal_state := NEW.state;
        NEW.updated_at := GREATEST(NEW.updated_at, observed_at);
        NEW.receipt_status := 'PENDING';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER execution_terminal_time_guard
    BEFORE INSERT OR UPDATE ON execution_records
    FOR EACH ROW EXECUTE FUNCTION capture_execution_terminal_time();

CREATE INDEX idx_execution_receipt_recovery
    ON execution_records (updated_at, execution_id)
    WHERE state IN ('DENIED', 'COMMITTED', 'RELEASED')
      AND receipt_status IN ('NOT_REQUIRED', 'PENDING', 'FAILED_RETRYABLE')
      AND terminal_at IS NOT NULL;

COMMIT;
