BEGIN;

-- Existing observations remain legacy; only subsequent inserts require capture.
ALTER TABLE public.coauthorization_revocation_events
    ADD COLUMN audit_required BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE public.coauthorization_revocation_events
    ALTER COLUMN audit_required SET DEFAULT TRUE;

ALTER TABLE public.audit_events DROP CONSTRAINT audit_event_version_type;
ALTER TABLE public.audit_events ADD CONSTRAINT audit_event_version_type CHECK (
    (schema_version = '1.0' AND event_type <> 'COAUTH_ROOT_AUTHORIZED'
        AND event_type <> 'COAUTH_REVOCATION_APPLIED')
    OR (schema_version = '2.0' AND event_type = 'COAUTH_ROOT_AUTHORIZED'
        AND execution_id IS NULL)
    OR (schema_version = '3.0' AND event_type = 'COAUTH_REVOCATION_APPLIED'
        AND execution_id IS NULL)
);

CREATE FUNCTION public.protect_coauthorization_revocation_event() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.audit_required := TRUE;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'coauthorization revocation observations are immutable'
        USING ERRCODE = '22023';
END;
$$;
CREATE TRIGGER coauthorization_revocation_event_immutable
    BEFORE INSERT OR UPDATE ON public.coauthorization_revocation_events
    FOR EACH ROW EXECUTE FUNCTION public.protect_coauthorization_revocation_event();

CREATE FUNCTION public.assert_coauthorization_revocation_journal(event_id BIGINT) RETURNS VOID
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    observation public.coauthorization_revocation_events%ROWTYPE;
    outbox_row public.audit_outbox%ROWTYPE;
    matched_count BIGINT;
    created_count BIGINT;
    candidate_count BIGINT;
    expected_page_count BIGINT;
    actual_page_count BIGINT;
    captured_time BIGINT;
    expected_header JSONB;
    expected_payload JSONB;
    page RECORD;
BEGIN
    SELECT event.* INTO observation FROM public.coauthorization_revocation_events AS event
    WHERE event.revocation_event_id = event_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'coauthorization revocation observation is missing'
            USING ERRCODE = '22023';
    END IF;
    IF (observation.source_kind = 'AUTHORIZATION_WITHDRAWN')
       <> (observation.observation_context = 'EXPLICIT_WITHDRAWAL') THEN
        RAISE EXCEPTION 'coauthorization revocation observation context differs'
            USING ERRCODE = '22023';
    END IF;

    IF observation.source_kind IN ('APPROVAL_KEY_REVOKED', 'APPROVAL_KEY_COMPROMISED') THEN
        IF NOT EXISTS (
            SELECT 1 FROM public.coauthorization_keys AS key
            WHERE key.tenant_id = observation.tenant_id AND key.key_id = observation.source_identifier
              AND key.activated_at <= observation.observed_at
              AND (
                  (observation.source_kind = 'APPROVAL_KEY_REVOKED'
                   AND key.status IN ('REVOKED', 'COMPROMISED')
                   AND key.revoked_at <= observation.observed_at)
                  OR (observation.source_kind = 'APPROVAL_KEY_COMPROMISED'
                      AND key.status = 'COMPROMISED'
                      AND key.compromised_at <= observation.observed_at)
              )
        ) THEN
            RAISE EXCEPTION 'coauthorization revocation key state differs'
                USING ERRCODE = '22023';
        END IF;
    ELSIF observation.source_kind = 'APPROVAL_POLICY_REVOKED' THEN
        IF NOT EXISTS (
            SELECT 1 FROM public.coauthorization_policies AS policy
            WHERE policy.tenant_id = observation.tenant_id
              AND policy.revision = observation.source_identifier AND policy.status = 'REVOKED'
        ) THEN
            RAISE EXCEPTION 'coauthorization revocation policy state differs'
                USING ERRCODE = '22023';
        END IF;
    END IF;

    SELECT COUNT(*), COUNT(*) FILTER (WHERE mapping.root_revocation_created)
    INTO matched_count, created_count
    FROM public.coauthorization_revocation_roots AS mapping
    WHERE mapping.revocation_event_id = event_id;
    IF matched_count > 9007199254740991
       OR (observation.source_kind = 'AUTHORIZATION_WITHDRAWN' AND matched_count <> 1) THEN
        RAISE EXCEPTION 'coauthorization revocation root count is invalid'
            USING ERRCODE = '22023';
    END IF;
    expected_page_count := GREATEST(1::BIGINT, (matched_count + 31) / 32);

    -- Check the complete source match as well as the stored mapping, without a root limit.
    SELECT COUNT(*) INTO candidate_count
    FROM public.coauthorization_authorizations AS binding
    JOIN public.coauthorization_challenges AS challenge ON challenge.challenge_id = binding.challenge_id
    JOIN public.credentials AS credential ON credential.credential_id = binding.root_credential_id
    WHERE (
        (observation.source_kind IN ('APPROVAL_KEY_REVOKED', 'APPROVAL_KEY_COMPROMISED')
         AND (observation.source_identifier IN (binding.enterprise_key_id, binding.finance_key_id)
              OR observation.source_identifier IN (
                  challenge.approval_payload -> 'required_signers' -> 'enterprise_approver' ->> 'key_id',
                  challenge.approval_payload -> 'required_signers' -> 'finance_approver' ->> 'key_id'
              )))
        OR (observation.source_kind = 'APPROVAL_POLICY_REVOKED'
            AND challenge.tenant_id = observation.tenant_id
            AND challenge.policy_revision = observation.source_identifier)
        OR (observation.source_kind = 'AUTHORIZATION_WITHDRAWN'
            AND credential.credential_id = observation.source_identifier
            AND credential.tenant_id = observation.tenant_id)
    );
    IF candidate_count <> matched_count THEN
        RAISE EXCEPTION 'coauthorization revocation mapping omits or adds a source root'
            USING ERRCODE = '22023';
    END IF;

    SELECT outbox.* INTO outbox_row FROM public.audit_outbox AS outbox
    WHERE outbox.outbox_event_id = 'OUTBOX-COAUTH-REV-' || event_id::TEXT || '-1';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'coauthorization revocation first audit page is missing'
            USING ERRCODE = '22023';
    END IF;
    IF jsonb_typeof(outbox_row.payload) IS DISTINCT FROM 'object'
       OR jsonb_typeof(outbox_row.payload -> 'captured_at') IS DISTINCT FROM 'number'
       OR (outbox_row.payload ->> 'captured_at') !~ '^(0|[1-9][0-9]{0,15})$' THEN
        RAISE EXCEPTION 'coauthorization revocation capture time is not a safe integer'
            USING ERRCODE = '22023';
    END IF;
    captured_time := (outbox_row.payload ->> 'captured_at')::BIGINT;
    IF captured_time NOT BETWEEN observation.observed_at AND 9007199254740991 THEN
        RAISE EXCEPTION 'coauthorization revocation capture time predates its observation'
            USING ERRCODE = '22023';
    END IF;

    IF EXISTS (
        SELECT 1 FROM public.coauthorization_revocation_roots AS mapping
        LEFT JOIN public.credentials AS credential ON credential.credential_id = mapping.root_credential_id
        LEFT JOIN public.coauthorization_authorizations AS binding
            ON binding.root_credential_id = mapping.root_credential_id
        LEFT JOIN public.coauthorization_challenges AS challenge ON challenge.challenge_id = binding.challenge_id
        LEFT JOIN public.credential_revocations AS revocation ON revocation.credential_id = mapping.root_credential_id
        WHERE mapping.revocation_event_id = event_id AND (
            credential.credential_id IS NULL OR binding.root_credential_id IS NULL
            OR challenge.challenge_id IS NULL OR revocation.credential_id IS NULL
            OR credential.credential_type IS DISTINCT FROM 'ROOT'
            OR credential.tenant_id IS DISTINCT FROM observation.tenant_id
            OR challenge.tenant_id IS DISTINCT FROM observation.tenant_id
            OR binding.task_id IS DISTINCT FROM credential.task_id
            OR challenge.task_id IS DISTINCT FROM credential.task_id
            OR challenge.status IS DISTINCT FROM 'CONSUMED'
            OR challenge.root_credential_id IS DISTINCT FROM credential.credential_id
            OR challenge.root_credential_hash IS DISTINCT FROM credential.signed_object_hash
            OR challenge.approval_payload_hash IS DISTINCT FROM binding.approval_payload_hash
            OR challenge.bundle_hash IS DISTINCT FROM binding.bundle_hash
            OR binding.enterprise_key_id IS DISTINCT FROM
                challenge.approval_payload -> 'required_signers' -> 'enterprise_approver' ->> 'key_id'
            OR binding.finance_key_id IS DISTINCT FROM
                challenge.approval_payload -> 'required_signers' -> 'finance_approver' ->> 'key_id'
            OR binding.enterprise_subject_id IS DISTINCT FROM
                challenge.approval_payload -> 'required_signers' -> 'enterprise_approver' ->> 'subject_id'
            OR binding.finance_subject_id IS DISTINCT FROM
                challenge.approval_payload -> 'required_signers' -> 'finance_approver' ->> 'subject_id'
            OR credential.created_at NOT BETWEEN 0 AND observation.observed_at
            OR credential.issued_at NOT BETWEEN 0 AND observation.observed_at
            OR binding.authorized_at NOT BETWEEN 0 AND observation.observed_at
            OR revocation.revoked_at NOT BETWEEN 0 AND observation.observed_at
            OR revocation.revoked_at > captured_time
            OR (
                (observation.source_kind IN ('APPROVAL_KEY_REVOKED', 'APPROVAL_KEY_COMPROMISED')
                 AND observation.source_identifier IN (binding.enterprise_key_id, binding.finance_key_id))
                OR (observation.source_kind = 'APPROVAL_POLICY_REVOKED'
                    AND challenge.policy_revision = observation.source_identifier)
                OR (observation.source_kind = 'AUTHORIZATION_WITHDRAWN'
                    AND credential.credential_id = observation.source_identifier)
            ) IS NOT TRUE
            OR (mapping.root_revocation_created AND (
                revocation.revoked_at <> observation.observed_at
                OR revocation.revoked_by <> 'COAUTH_REGISTRY:' || observation.database_actor
                OR revocation.revocation_reason <> observation.source_kind || ':' || observation.source_identifier
            ))
        )
    ) THEN
        RAISE EXCEPTION 'coauthorization revocation root binding is inconsistent'
            USING ERRCODE = '22023';
    END IF;

    SELECT COUNT(*) INTO actual_page_count FROM public.audit_outbox AS outbox
    WHERE outbox.outbox_event_id LIKE 'OUTBOX-COAUTH-REV-' || event_id::TEXT || '-%'
       OR outbox.evidence_reference LIKE 'COAUTH-REV-' || event_id::TEXT || '-P-%'
       OR (outbox.payload -> 'revocation_event_id' = to_jsonb(event_id)
           AND (outbox.event_type = 'COAUTH_REVOCATION_APPLIED'
                OR outbox.payload ->> 'record_type' = 'COAUTH_REVOCATION_APPLIED_V1'));
    IF actual_page_count <> expected_page_count THEN
        RAISE EXCEPTION 'coauthorization revocation audit pages are missing or extra'
            USING ERRCODE = '22023';
    END IF;

    expected_header := jsonb_build_object(
        'schema_version', '1.0', 'record_type', 'COAUTH_REVOCATION_APPLIED_V1',
        'revocation_event_id', observation.revocation_event_id, 'tenant_id', observation.tenant_id,
        'source_kind', observation.source_kind, 'source_identifier', observation.source_identifier,
        'observed_at', observation.observed_at, 'observation_context', observation.observation_context,
        'database_actor', observation.database_actor,
        'capture_kind', CASE WHEN observation.audit_required THEN 'TRANSACTIONAL_CAPTURE'
                            ELSE 'LEGACY_OBSERVATION_LINK' END,
        'captured_at', captured_time, 'page_count', expected_page_count,
        'matched_root_count', matched_count, 'created_root_revocation_count', created_count
    );
    FOR page IN
        WITH ordered_roots AS (
            SELECT (row_number() OVER (ORDER BY mapping.root_credential_id COLLATE "C") - 1) / 32 + 1
                       AS page_number,
                   mapping.root_credential_id,
                   jsonb_build_object(
                       'root_credential_id', mapping.root_credential_id,
                       'root_credential_hash', credential.signed_object_hash,
                       'task_id', credential.task_id, 'challenge_id', binding.challenge_id,
                       'policy_revision', challenge.policy_revision,
                       'approval_payload_hash', binding.approval_payload_hash,
                       'bundle_hash', binding.bundle_hash,
                       'enterprise_key_id', binding.enterprise_key_id,
                       'finance_key_id', binding.finance_key_id,
                       'root_revocation_created', mapping.root_revocation_created,
                       'revoked_at', revocation.revoked_at, 'revoked_by', revocation.revoked_by,
                       'revocation_reason', revocation.revocation_reason
                   ) AS root_payload
            FROM public.coauthorization_revocation_roots AS mapping
            JOIN public.credentials AS credential ON credential.credential_id = mapping.root_credential_id
            JOIN public.coauthorization_authorizations AS binding
                ON binding.root_credential_id = mapping.root_credential_id
            JOIN public.coauthorization_challenges AS challenge ON challenge.challenge_id = binding.challenge_id
            JOIN public.credential_revocations AS revocation ON revocation.credential_id = mapping.root_credential_id
            WHERE mapping.revocation_event_id = event_id
        ), expected_pages AS (
            SELECT page_number, jsonb_agg(root_payload ORDER BY root_credential_id COLLATE "C") AS roots
            FROM ordered_roots GROUP BY page_number
            UNION ALL
            SELECT 1::BIGINT, '[]'::JSONB WHERE matched_count = 0
        )
        SELECT page_number, roots FROM expected_pages ORDER BY page_number
    LOOP
        SELECT outbox.* INTO outbox_row FROM public.audit_outbox AS outbox
        WHERE outbox.outbox_event_id = 'OUTBOX-COAUTH-REV-' || event_id::TEXT || '-' || page.page_number::TEXT;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'coauthorization revocation expected audit page is missing'
                USING ERRCODE = '22023';
        END IF;
        expected_payload := expected_header || jsonb_build_object('page_number', page.page_number, 'roots', page.roots);
        IF outbox_row.execution_id IS NOT NULL
           OR outbox_row.event_type <> 'COAUTH_REVOCATION_APPLIED'
           OR outbox_row.evidence_reference <> 'COAUTH-REV-' || event_id::TEXT || '-P-' || page.page_number::TEXT
           OR outbox_row.status NOT IN ('PENDING', 'APPENDED')
           OR outbox_row.created_at <> captured_time
           OR outbox_row.payload_hash IS NULL OR outbox_row.payload_hash !~ '^[0-9a-f]{64}$'
           OR outbox_row.payload IS DISTINCT FROM expected_payload THEN
            RAISE EXCEPTION 'coauthorization revocation audit page metadata or payload differs'
                USING ERRCODE = '22023';
        END IF;
        -- JSONB numeric equality alone would also accept a decimal such as 1.0.
        IF EXISTS (
            SELECT 1 FROM jsonb_each(outbox_row.payload) AS field(key, value)
            WHERE field.key IN (
                'revocation_event_id', 'observed_at', 'captured_at', 'page_number', 'page_count',
                'matched_root_count', 'created_root_revocation_count'
            ) AND (jsonb_typeof(field.value) IS DISTINCT FROM 'number'
                   OR field.value::TEXT !~ '^(0|[1-9][0-9]{0,15})$')
        ) OR EXISTS (
            SELECT 1 FROM jsonb_array_elements(outbox_row.payload -> 'roots') AS root(value)
            WHERE jsonb_typeof(root.value -> 'revoked_at') IS DISTINCT FROM 'number'
               OR (root.value ->> 'revoked_at') !~ '^(0|[1-9][0-9]{0,15})$'
        ) THEN
            RAISE EXCEPTION 'coauthorization revocation audit page contains a noninteger time or count'
                USING ERRCODE = '22023';
        END IF;
    END LOOP;
    -- SM3(CanonicalJSON(payload)) is computed by Python and rechecked by the worker.
END;
$$;

CREATE FUNCTION public.require_coauthorization_revocation_journal() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    PERFORM public.assert_coauthorization_revocation_journal(NEW.revocation_event_id);
    RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER coauthorization_revocation_event_journal_required
    AFTER INSERT ON public.coauthorization_revocation_events
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION public.require_coauthorization_revocation_journal();

CREATE FUNCTION public.guard_coauthorization_revocation_source() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
    target_kind TEXT;
    target_identifier TEXT;
    observation public.coauthorization_revocation_events%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'coauthorization_keys' THEN
        target_kind := CASE NEW.status WHEN 'REVOKED' THEN 'APPROVAL_KEY_REVOKED'
                       ELSE 'APPROVAL_KEY_COMPROMISED' END;
        target_identifier := NEW.key_id;
    ELSE
        target_kind := 'APPROVAL_POLICY_REVOKED';
        target_identifier := NEW.revision;
    END IF;
    SELECT event.* INTO observation FROM public.coauthorization_revocation_events AS event
    WHERE event.tenant_id = NEW.tenant_id AND event.source_kind = target_kind
      AND event.source_identifier = target_identifier;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'coauthorization revoked source has no corresponding observation'
            USING ERRCODE = '22023';
    END IF;
    IF observation.audit_required THEN
        PERFORM public.assert_coauthorization_revocation_journal(observation.revocation_event_id);
    END IF;
    RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER coauthorization_key_revocation_journal_required
    AFTER UPDATE ON public.coauthorization_keys
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status AND NEW.status IN ('REVOKED', 'COMPROMISED'))
    EXECUTE FUNCTION public.guard_coauthorization_revocation_source();
CREATE CONSTRAINT TRIGGER coauthorization_policy_revocation_journal_required
    AFTER UPDATE ON public.coauthorization_policies
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status AND NEW.status = 'REVOKED')
    EXECUTE FUNCTION public.guard_coauthorization_revocation_source();

REVOKE EXECUTE ON FUNCTION
    public.protect_coauthorization_revocation_event(),
    public.assert_coauthorization_revocation_journal(BIGINT),
    public.require_coauthorization_revocation_journal(),
    public.guard_coauthorization_revocation_source()
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION
    public.protect_coauthorization_revocation_event(),
    public.assert_coauthorization_revocation_journal(BIGINT),
    public.require_coauthorization_revocation_journal(),
    public.guard_coauthorization_revocation_source()
TO CURRENT_USER;

COMMIT;
