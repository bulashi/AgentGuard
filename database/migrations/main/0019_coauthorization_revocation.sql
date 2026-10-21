BEGIN;

CREATE TABLE coauthorization_revocation_events (
    revocation_event_id BIGINT GENERATED ALWAYS AS IDENTITY (MAXVALUE 9007199254740991) PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    source_kind TEXT NOT NULL CHECK (source_kind IN (
        'APPROVAL_KEY_REVOKED', 'APPROVAL_KEY_COMPROMISED',
        'APPROVAL_POLICY_REVOKED', 'AUTHORIZATION_WITHDRAWN'
    )),
    source_identifier TEXT NOT NULL CHECK (char_length(source_identifier) BETWEEN 1 AND 128),
    observed_at BIGINT NOT NULL CHECK (observed_at BETWEEN 0 AND 9007199254740991),
    observation_context TEXT NOT NULL CHECK (observation_context IN (
        'REGISTRY_STATUS_UPDATE', 'MIGRATION_RECONCILIATION', 'EXPLICIT_WITHDRAWAL'
    )),
    database_actor TEXT NOT NULL,
    UNIQUE (tenant_id, source_kind, source_identifier)
);

CREATE TABLE coauthorization_revocation_roots (
    revocation_event_id BIGINT NOT NULL REFERENCES coauthorization_revocation_events (revocation_event_id),
    root_credential_id TEXT NOT NULL REFERENCES credentials (credential_id) ON DELETE CASCADE,
    root_revocation_created BOOLEAN NOT NULL,
    PRIMARY KEY (revocation_event_id, root_credential_id)
);
CREATE INDEX idx_coauthorization_revocation_root ON coauthorization_revocation_roots (root_credential_id);
CREATE INDEX idx_coauthorization_authorization_enterprise_key ON coauthorization_authorizations (enterprise_key_id);
CREATE INDEX idx_coauthorization_authorization_finance_key ON coauthorization_authorizations (finance_key_id);

CREATE FUNCTION protect_coauthorization_authorization_binding() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'coauthorization authorization binding is immutable' USING ERRCODE = '22023';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER coauthorization_authorization_binding_immutable BEFORE UPDATE ON coauthorization_authorizations
    FOR EACH ROW EXECUTE FUNCTION protect_coauthorization_authorization_binding();

CREATE FUNCTION apply_coauthorization_revocation(
    target_kind TEXT, target_tenant TEXT, target_identifier TEXT, observation_context TEXT
) RETURNS BIGINT LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    source_status TEXT;
    lower_bound BIGINT := 0;
    observed_time BIGINT;
    event_id BIGINT;
    root_row RECORD;
    root_ids TEXT[] := ARRAY[]::TEXT[];
    root_id TEXT;
    inserted_rows INTEGER;
    prior_revoked_at BIGINT;
BEGIN
    -- Each statement needs a fresh snapshot after the source lifecycle lock wait.
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'coauthorization revocation requires READ COMMITTED'
            USING ERRCODE = '22023';
    END IF;
    IF target_kind NOT IN (
        'APPROVAL_KEY_REVOKED', 'APPROVAL_KEY_COMPROMISED',
        'APPROVAL_POLICY_REVOKED', 'AUTHORIZATION_WITHDRAWN'
    ) OR target_kind IS NULL OR target_tenant IS NULL OR target_identifier IS NULL
       OR observation_context NOT IN (
           'REGISTRY_STATUS_UPDATE', 'MIGRATION_RECONCILIATION', 'EXPLICIT_WITHDRAWAL'
       ) OR observation_context IS NULL
       OR (target_kind = 'AUTHORIZATION_WITHDRAWN') <> (observation_context = 'EXPLICIT_WITHDRAWAL') THEN
        RAISE EXCEPTION 'invalid coauthorization revocation target' USING ERRCODE = '22023';
    END IF;

    IF target_kind IN ('APPROVAL_KEY_REVOKED', 'APPROVAL_KEY_COMPROMISED') THEN
        SELECT status, GREATEST(activated_at, COALESCE(revoked_at, 0), COALESCE(compromised_at, 0))
        INTO source_status, lower_bound
        FROM coauthorization_keys
        WHERE tenant_id = target_tenant AND key_id = target_identifier
        FOR UPDATE NOWAIT;
        IF NOT FOUND OR source_status <> (CASE target_kind
            WHEN 'APPROVAL_KEY_REVOKED' THEN 'REVOKED' ELSE 'COMPROMISED' END) THEN
            RAISE EXCEPTION 'approval key is not in the requested revoked state' USING ERRCODE = '22023';
        END IF;
    ELSIF target_kind = 'APPROVAL_POLICY_REVOKED' THEN
        SELECT status INTO source_status FROM coauthorization_policies
        WHERE tenant_id = target_tenant AND revision = target_identifier FOR UPDATE NOWAIT;
        IF NOT FOUND OR source_status <> 'REVOKED' THEN
            RAISE EXCEPTION 'approval policy is not revoked' USING ERRCODE = '22023';
        END IF;
    END IF;

    -- NOWAIT avoids a policy/key -> root -> task cycle with issuance/admission.
    FOR root_row IN
        SELECT credential.credential_id, credential.created_at, credential.issued_at,
               credential.credential_type, credential.tenant_id, credential.task_id,
               credential.signed_object_hash, binding.authorized_at,
               binding.task_id AS authorization_task_id, binding.bundle_hash,
               binding.approval_payload_hash, challenge.tenant_id AS challenge_tenant_id,
               challenge.task_id AS challenge_task_id, challenge.status AS challenge_status,
               challenge.root_credential_id AS challenge_root_id,
               challenge.root_credential_hash AS challenge_root_hash,
               challenge.bundle_hash AS challenge_bundle_hash,
               challenge.approval_payload_hash AS challenge_payload_hash,
               binding.enterprise_key_id, binding.finance_key_id,
               binding.enterprise_subject_id, binding.finance_subject_id,
               challenge.approval_payload -> 'required_signers' AS required_signers
        FROM coauthorization_authorizations AS binding
        JOIN coauthorization_challenges AS challenge
            ON challenge.challenge_id = binding.challenge_id
        JOIN credentials AS credential
            ON credential.credential_id = binding.root_credential_id
        WHERE (
              (target_kind IN ('APPROVAL_KEY_REVOKED', 'APPROVAL_KEY_COMPROMISED')
               AND (target_identifier IN (binding.enterprise_key_id, binding.finance_key_id)
                    OR target_identifier IN (
                        challenge.approval_payload -> 'required_signers' -> 'enterprise_approver' ->> 'key_id',
                        challenge.approval_payload -> 'required_signers' -> 'finance_approver' ->> 'key_id'
                    )))
              OR (target_kind = 'APPROVAL_POLICY_REVOKED' AND challenge.tenant_id = target_tenant
                  AND challenge.policy_revision = target_identifier)
              OR (target_kind = 'AUTHORIZATION_WITHDRAWN' AND credential.credential_id = target_identifier
                  AND credential.tenant_id = target_tenant)
          )
        ORDER BY credential.credential_id FOR UPDATE OF credential NOWAIT
    LOOP
        IF root_row.credential_type <> 'ROOT' OR root_row.tenant_id <> target_tenant
           OR root_row.challenge_tenant_id <> target_tenant
           OR root_row.authorization_task_id <> root_row.task_id
           OR root_row.challenge_task_id <> root_row.task_id
           OR root_row.challenge_status <> 'CONSUMED'
           OR root_row.challenge_root_id IS DISTINCT FROM root_row.credential_id
           OR root_row.challenge_root_hash IS DISTINCT FROM root_row.signed_object_hash
           OR root_row.challenge_bundle_hash IS DISTINCT FROM root_row.bundle_hash
           OR root_row.challenge_payload_hash IS DISTINCT FROM root_row.approval_payload_hash
           OR root_row.enterprise_key_id IS DISTINCT FROM root_row.required_signers -> 'enterprise_approver' ->> 'key_id'
           OR root_row.finance_key_id IS DISTINCT FROM root_row.required_signers -> 'finance_approver' ->> 'key_id'
           OR root_row.enterprise_subject_id IS DISTINCT FROM root_row.required_signers -> 'enterprise_approver' ->> 'subject_id'
           OR root_row.finance_subject_id IS DISTINCT FROM root_row.required_signers -> 'finance_approver' ->> 'subject_id' THEN
            RAISE EXCEPTION 'coauthorization root binding is inconsistent' USING ERRCODE = '22023';
        END IF;
        IF root_row.created_at NOT BETWEEN 0 AND 9007199254740991
           OR root_row.issued_at NOT BETWEEN 0 AND 9007199254740991
           OR root_row.authorized_at NOT BETWEEN 0 AND 9007199254740991 THEN
            RAISE EXCEPTION 'invalid coauthorization root observation time' USING ERRCODE = '22023';
        END IF;
        root_ids := array_append(root_ids, root_row.credential_id);
        lower_bound := GREATEST(lower_bound, root_row.created_at, root_row.issued_at, root_row.authorized_at);
        SELECT revoked_at INTO prior_revoked_at FROM credential_revocations
        WHERE credential_id = root_row.credential_id FOR UPDATE NOWAIT;
        IF FOUND THEN
            IF prior_revoked_at NOT BETWEEN 0 AND 9007199254740991 THEN
                RAISE EXCEPTION 'invalid existing root revocation time' USING ERRCODE = '22023';
            END IF;
            lower_bound := GREATEST(lower_bound, prior_revoked_at);
        END IF;
    END LOOP;
    IF target_kind = 'AUTHORIZATION_WITHDRAWN' AND cardinality(root_ids) <> 1 THEN
        RAISE EXCEPTION 'withdrawal requires one bound coauthorized root' USING ERRCODE = '22023';
    END IF;

    SELECT revocation_event_id INTO event_id FROM coauthorization_revocation_events
    WHERE tenant_id = target_tenant AND source_kind = target_kind AND source_identifier = target_identifier;
    IF FOUND THEN
        IF EXISTS (
            SELECT candidate.root_id FROM unnest(root_ids) AS candidate(root_id)
            EXCEPT SELECT root_credential_id FROM coauthorization_revocation_roots
                   WHERE revocation_event_id = event_id
        ) THEN
            RAISE EXCEPTION 'new root appeared after a recorded coauthorization revocation' USING ERRCODE = '22023';
        END IF;
        IF EXISTS (
            SELECT 1 FROM unnest(root_ids) AS candidate(root_id)
            LEFT JOIN credential_revocations AS revocation ON revocation.credential_id = candidate.root_id
            WHERE revocation.credential_id IS NULL
        ) THEN
            RAISE EXCEPTION 'recorded coauthorization root revocation disappeared' USING ERRCODE = '22023';
        END IF;
        RETURN event_id;
    END IF;

    observed_time := floor(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT;
    IF observed_time NOT BETWEEN 0 AND 9007199254740991 OR observed_time < lower_bound THEN
        RAISE EXCEPTION 'invalid coauthorization revocation clock' USING ERRCODE = '22023';
    END IF;
    INSERT INTO coauthorization_revocation_events (
        tenant_id, source_kind, source_identifier, observed_at, observation_context, database_actor
    ) VALUES (target_tenant, target_kind, target_identifier, observed_time, observation_context, session_user)
    RETURNING revocation_event_id INTO event_id;

    FOREACH root_id IN ARRAY root_ids LOOP
        INSERT INTO credential_revocations (credential_id, revoked_at, revoked_by, revocation_reason)
        VALUES (root_id, observed_time, 'COAUTH_REGISTRY:' || session_user, target_kind || ':' || target_identifier)
        ON CONFLICT (credential_id) DO NOTHING;
        GET DIAGNOSTICS inserted_rows = ROW_COUNT;
        INSERT INTO coauthorization_revocation_roots (
            revocation_event_id, root_credential_id, root_revocation_created
        ) VALUES (event_id, root_id, inserted_rows = 1);
    END LOOP;
    RETURN event_id;
END;
$$;

REVOKE EXECUTE ON FUNCTION apply_coauthorization_revocation(TEXT, TEXT, TEXT, TEXT) FROM PUBLIC;

CREATE FUNCTION cascade_coauthorization_key_revocation() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status AND NEW.status IN ('REVOKED', 'COMPROMISED') THEN
        PERFORM apply_coauthorization_revocation(
            CASE NEW.status WHEN 'REVOKED' THEN 'APPROVAL_KEY_REVOKED' ELSE 'APPROVAL_KEY_COMPROMISED' END,
            NEW.tenant_id, NEW.key_id, 'REGISTRY_STATUS_UPDATE'
        );
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER coauthorization_key_revocation_cascade AFTER UPDATE OF status ON coauthorization_keys
    FOR EACH ROW EXECUTE FUNCTION cascade_coauthorization_key_revocation();

CREATE FUNCTION cascade_coauthorization_policy_revocation() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status AND NEW.status = 'REVOKED' THEN
        PERFORM apply_coauthorization_revocation(
            'APPROVAL_POLICY_REVOKED', NEW.tenant_id, NEW.revision, 'REGISTRY_STATUS_UPDATE'
        );
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER coauthorization_policy_revocation_cascade AFTER UPDATE OF status ON coauthorization_policies
    FOR EACH ROW EXECUTE FUNCTION cascade_coauthorization_policy_revocation();

-- Legacy revoked sources are observed now, never backdated to an invented event.
DO $$
DECLARE source RECORD;
BEGIN
    FOR source IN SELECT tenant_id, key_id, status FROM coauthorization_keys
        WHERE status IN ('REVOKED', 'COMPROMISED') ORDER BY tenant_id, key_id
    LOOP
        PERFORM apply_coauthorization_revocation(
            CASE source.status WHEN 'REVOKED' THEN 'APPROVAL_KEY_REVOKED' ELSE 'APPROVAL_KEY_COMPROMISED' END,
            source.tenant_id, source.key_id, 'MIGRATION_RECONCILIATION'
        );
    END LOOP;
    FOR source IN SELECT tenant_id, revision FROM coauthorization_policies
        WHERE status = 'REVOKED' ORDER BY tenant_id, revision
    LOOP
        PERFORM apply_coauthorization_revocation(
            'APPROVAL_POLICY_REVOKED', source.tenant_id, source.revision, 'MIGRATION_RECONCILIATION'
        );
    END LOOP;
END;
$$;

COMMIT;
