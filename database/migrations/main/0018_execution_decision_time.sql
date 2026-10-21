BEGIN;

ALTER TABLE execution_records
    ADD COLUMN decision_at BIGINT,
    ADD COLUMN decision_value authorization_decision,
    ADD CONSTRAINT execution_decision_time_pair CHECK (
        (decision_at IS NULL AND decision_value IS NULL)
        OR (
            decision_at IS NOT NULL AND decision_value IS NOT NULL
            AND decision IS NOT NULL
            AND decision_at BETWEEN created_at AND 9007199254740991
            AND decision_value = decision
            AND (terminal_at IS NULL OR decision_at <= terminal_at)
        )
    );

-- Existing decisions remain unobserved; created_at is not a historical decision source.
CREATE FUNCTION capture_execution_decision_time() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    observed_at BIGINT;
    entering_decision BOOLEAN;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.decision_at IS NOT NULL OR NEW.decision_value IS NOT NULL THEN
            RAISE EXCEPTION 'execution decision time is database-managed'
                USING ERRCODE = '22023';
        END IF;
        entering_decision := (NEW.state = 'ADMITTED' AND NEW.decision = 'ALLOW')
            OR (NEW.state = 'DENIED' AND NEW.decision = 'DENY');
    ELSE
        IF NEW.decision_at IS DISTINCT FROM OLD.decision_at
           OR NEW.decision_value IS DISTINCT FROM OLD.decision_value THEN
            RAISE EXCEPTION 'execution decision time cannot be supplied or changed'
                USING ERRCODE = '22023';
        END IF;
        IF OLD.decision_at IS NOT NULL AND NEW.decision IS DISTINCT FROM OLD.decision THEN
            RAISE EXCEPTION 'authorization decision cannot be changed'
                USING ERRCODE = '22023';
        END IF;
        entering_decision := OLD.state = 'RECEIVED' AND (
            (NEW.state = 'ADMITTED' AND NEW.decision = 'ALLOW')
            OR (NEW.state = 'DENIED' AND NEW.decision = 'DENY')
        );
    END IF;

    IF (NEW.state = 'ADMITTED' AND NEW.decision IS DISTINCT FROM 'ALLOW'::authorization_decision)
       OR (NEW.state = 'DENIED' AND NEW.decision IS DISTINCT FROM 'DENY'::authorization_decision) THEN
        RAISE EXCEPTION 'admission state and authorization decision disagree'
            USING ERRCODE = '22023';
    END IF;

    IF entering_decision THEN
        observed_at := floor(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT;
        IF observed_at < NEW.created_at OR observed_at > 9007199254740991 THEN
            RAISE EXCEPTION 'database decision clock is outside the execution time range'
                USING ERRCODE = '22023';
        END IF;
        NEW.decision_at := observed_at;
        NEW.decision_value := NEW.decision;
        NEW.updated_at := GREATEST(NEW.updated_at, observed_at);
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER execution_decision_time_guard
    BEFORE INSERT OR UPDATE ON execution_records
    FOR EACH ROW EXECUTE FUNCTION capture_execution_decision_time();

COMMIT;
