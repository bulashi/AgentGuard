BEGIN;

CREATE TABLE coauthorization_keys (
    key_id TEXT PRIMARY KEY CHECK (key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    tenant_id TEXT NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    subject_id TEXT NOT NULL CHECK (subject_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    principal_id TEXT NOT NULL CHECK (principal_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    role TEXT NOT NULL CHECK (role IN ('ENTERPRISE_APPROVER', 'FINANCE_APPROVER')),
    approval_purpose TEXT NOT NULL CHECK (approval_purpose = 'TASK_COAUTHORIZATION_APPROVAL_V1'),
    signing_purpose TEXT NOT NULL CHECK (signing_purpose = 'AUTHORIZATION_ROOT_SIGNING'),
    algorithm TEXT NOT NULL CHECK (algorithm = 'SM2'),
    public_key_hex TEXT NOT NULL UNIQUE CHECK (public_key_hex ~ '^[0-9a-f]{128}$'),
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'RETIRED', 'REVOKED', 'COMPROMISED')),
    activated_at BIGINT NOT NULL CHECK (activated_at BETWEEN 0 AND 9007199254740991),
    expires_at BIGINT NOT NULL CHECK (expires_at BETWEEN 0 AND 9007199254740991 AND expires_at > activated_at),
    retired_at BIGINT CHECK (retired_at BETWEEN activated_at AND 9007199254740991),
    revoked_at BIGINT CHECK (revoked_at BETWEEN activated_at AND 9007199254740991),
    compromised_at BIGINT CHECK (compromised_at BETWEEN activated_at AND 9007199254740991),
    CHECK (status <> 'ACTIVE' OR (retired_at IS NULL AND revoked_at IS NULL AND compromised_at IS NULL)),
    CHECK (status <> 'RETIRED' OR retired_at IS NOT NULL),
    CHECK (status <> 'REVOKED' OR revoked_at IS NOT NULL),
    CHECK (status <> 'COMPROMISED' OR compromised_at IS NOT NULL),
    UNIQUE (tenant_id, role, subject_id, key_id)
);

CREATE TABLE coauthorization_policies (
    tenant_id TEXT NOT NULL,
    revision TEXT NOT NULL CHECK (revision ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    enterprise_subject_id TEXT NOT NULL,
    enterprise_key_id TEXT NOT NULL,
    finance_subject_id TEXT NOT NULL,
    finance_key_id TEXT NOT NULL,
    enterprise_role TEXT NOT NULL DEFAULT 'ENTERPRISE_APPROVER' CHECK (enterprise_role = 'ENTERPRISE_APPROVER'),
    finance_role TEXT NOT NULL DEFAULT 'FINANCE_APPROVER' CHECK (finance_role = 'FINANCE_APPROVER'),
    not_before BIGINT NOT NULL CHECK (not_before BETWEEN 0 AND 9007199254740991),
    expires_at BIGINT NOT NULL CHECK (expires_at BETWEEN 0 AND 9007199254740991 AND expires_at > not_before),
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'RETIRED', 'REVOKED')),
    PRIMARY KEY (tenant_id, revision),
    FOREIGN KEY (tenant_id, enterprise_role, enterprise_subject_id, enterprise_key_id)
        REFERENCES coauthorization_keys (tenant_id, role, subject_id, key_id),
    FOREIGN KEY (tenant_id, finance_role, finance_subject_id, finance_key_id)
        REFERENCES coauthorization_keys (tenant_id, role, subject_id, key_id),
    CHECK (enterprise_subject_id <> finance_subject_id),
    CHECK (enterprise_key_id <> finance_key_id)
);

CREATE UNIQUE INDEX uq_coauthorization_active_policy ON coauthorization_policies (tenant_id)
    WHERE status = 'ACTIVE';

CREATE TABLE coauthorization_challenges (
    challenge_id TEXT PRIMARY KEY CHECK (challenge_id ~ '^COAUTH-[0-9a-f]{64}$'),
    tenant_id TEXT NOT NULL,
    task_id TEXT NOT NULL REFERENCES tasks (task_id),
    policy_revision TEXT NOT NULL,
    approval_payload JSONB NOT NULL,
    approval_payload_hash TEXT NOT NULL CHECK (approval_payload_hash ~ '^[0-9a-f]{64}$'),
    issued_at BIGINT NOT NULL CHECK (issued_at BETWEEN 0 AND 9007199254740991),
    expires_at BIGINT NOT NULL CHECK (expires_at BETWEEN 0 AND 9007199254740991 AND expires_at > issued_at),
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'CONSUMED', 'REVOKED')),
    bundle_hash TEXT CHECK (bundle_hash ~ '^[0-9a-f]{64}$'),
    signed_bundle JSONB,
    root_credential_id TEXT UNIQUE REFERENCES credentials (credential_id),
    root_credential_hash TEXT CHECK (root_credential_hash ~ '^[0-9a-f]{64}$'),
    consumed_at BIGINT CHECK (consumed_at BETWEEN issued_at AND expires_at - 1),
    revoked_at BIGINT CHECK (revoked_at BETWEEN issued_at AND 9007199254740991),
    FOREIGN KEY (tenant_id, policy_revision) REFERENCES coauthorization_policies (tenant_id, revision),
    CHECK (
        (status = 'CONSUMED' AND bundle_hash IS NOT NULL AND signed_bundle IS NOT NULL
         AND root_credential_id IS NOT NULL AND root_credential_hash IS NOT NULL
         AND consumed_at IS NOT NULL AND revoked_at IS NULL)
        OR (status IN ('PENDING', 'REVOKED') AND bundle_hash IS NULL AND signed_bundle IS NULL
            AND root_credential_id IS NULL AND root_credential_hash IS NULL AND consumed_at IS NULL)
    ),
    CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL))
);

CREATE UNIQUE INDEX uq_coauthorization_pending_task ON coauthorization_challenges (task_id)
    WHERE status = 'PENDING';
CREATE INDEX idx_coauthorization_challenge_task ON coauthorization_challenges (task_id, issued_at);

CREATE TABLE coauthorization_authorizations (
    task_id TEXT PRIMARY KEY REFERENCES tasks (task_id),
    challenge_id TEXT NOT NULL UNIQUE REFERENCES coauthorization_challenges (challenge_id),
    root_credential_id TEXT NOT NULL UNIQUE REFERENCES credentials (credential_id),
    approval_payload_hash TEXT NOT NULL CHECK (approval_payload_hash ~ '^[0-9a-f]{64}$'),
    bundle_hash TEXT NOT NULL CHECK (bundle_hash ~ '^[0-9a-f]{64}$'),
    enterprise_subject_id TEXT NOT NULL,
    enterprise_key_id TEXT NOT NULL,
    finance_subject_id TEXT NOT NULL,
    finance_key_id TEXT NOT NULL,
    authorized_at BIGINT NOT NULL CHECK (authorized_at >= 0),
    UNIQUE (task_id, approval_payload_hash)
);

CREATE FUNCTION protect_coauthorization_key() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.key_id, NEW.tenant_id, NEW.subject_id, NEW.principal_id, NEW.role,
           NEW.approval_purpose, NEW.signing_purpose, NEW.algorithm, NEW.public_key_hex,
           NEW.activated_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.key_id, OLD.tenant_id, OLD.subject_id, OLD.principal_id, OLD.role,
           OLD.approval_purpose, OLD.signing_purpose, OLD.algorithm, OLD.public_key_hex,
           OLD.activated_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'coauthorization key identity is immutable; register a new key';
    END IF;
    IF (OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at)
       OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at)
       OR (OLD.compromised_at IS NOT NULL AND NEW.compromised_at IS DISTINCT FROM OLD.compromised_at)
       OR (OLD.status <> 'ACTIVE' AND NEW.status = 'ACTIVE')
       OR (OLD.status = 'REVOKED' AND NEW.status NOT IN ('REVOKED', 'COMPROMISED'))
       OR (OLD.status = 'COMPROMISED' AND NEW.status <> 'COMPROMISED') THEN
        RAISE EXCEPTION 'coauthorization key lifecycle cannot move backwards';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER coauthorization_key_immutable BEFORE UPDATE ON coauthorization_keys
    FOR EACH ROW EXECUTE FUNCTION protect_coauthorization_key();

CREATE FUNCTION protect_coauthorization_policy() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.tenant_id, NEW.revision, NEW.enterprise_subject_id, NEW.enterprise_key_id,
           NEW.finance_subject_id, NEW.finance_key_id, NEW.enterprise_role, NEW.finance_role,
           NEW.not_before, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.tenant_id, OLD.revision, OLD.enterprise_subject_id, OLD.enterprise_key_id,
           OLD.finance_subject_id, OLD.finance_key_id, OLD.enterprise_role, OLD.finance_role,
           OLD.not_before, OLD.expires_at)
       OR (OLD.status <> 'ACTIVE' AND NEW.status = 'ACTIVE')
       OR (OLD.status = 'REVOKED' AND NEW.status <> 'REVOKED') THEN
        RAISE EXCEPTION 'coauthorization policy revision is immutable and cannot reactivate';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER coauthorization_policy_immutable BEFORE UPDATE ON coauthorization_policies
    FOR EACH ROW EXECUTE FUNCTION protect_coauthorization_policy();

CREATE FUNCTION protect_coauthorization_challenge() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.challenge_id, NEW.tenant_id, NEW.task_id, NEW.policy_revision,
           NEW.approval_payload, NEW.approval_payload_hash, NEW.issued_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.challenge_id, OLD.tenant_id, OLD.task_id, OLD.policy_revision,
           OLD.approval_payload, OLD.approval_payload_hash, OLD.issued_at, OLD.expires_at)
       OR OLD.status <> 'PENDING' THEN
        RAISE EXCEPTION 'coauthorization challenge binding is immutable; terminal states cannot change';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER coauthorization_challenge_immutable BEFORE UPDATE ON coauthorization_challenges
    FOR EACH ROW EXECUTE FUNCTION protect_coauthorization_challenge();

COMMIT;
