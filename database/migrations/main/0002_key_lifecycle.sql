BEGIN;

ALTER TABLE key_registry
    ADD COLUMN IF NOT EXISTS subject_type TEXT;

UPDATE key_registry
SET subject_type = 'SERVICE'
WHERE subject_type IS NULL;

ALTER TABLE key_registry
    ALTER COLUMN subject_type SET NOT NULL;

ALTER TABLE key_registry
    ADD COLUMN IF NOT EXISTS replaced_by TEXT REFERENCES key_registry (key_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'key_registry_not_self_replaced'
    ) THEN
        ALTER TABLE key_registry
            ADD CONSTRAINT key_registry_not_self_replaced
            CHECK (replaced_by IS NULL OR replaced_by <> key_id);
    END IF;
END
$$;

COMMIT;
