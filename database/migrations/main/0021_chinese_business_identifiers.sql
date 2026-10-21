BEGIN;

ALTER TABLE coauthorization_keys DROP CONSTRAINT coauthorization_keys_tenant_id_check;
ALTER TABLE coauthorization_keys ADD CONSTRAINT coauthorization_keys_tenant_id_check CHECK (
    char_length(tenant_id) BETWEEN 1 AND 128
    AND tenant_id ~ U&'^[A-Za-z0-9\3007\3400-\4DBF\4E00-\9FFF][A-Za-z0-9\3007\3400-\4DBF\4E00-\9FFF._:()\00B7\FF08\FF09-]*$'
    AND tenant_id !~ U&'[^A-Za-z0-9\3007\3400-\4DBF\4E00-\9FFF._:()\00B7\FF08\FF09-]'
);

COMMIT;
