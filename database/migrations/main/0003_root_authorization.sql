BEGIN;

CREATE TYPE confirmation_source AS ENUM ('USER', 'POLICY');

CREATE TABLE authorization_confirmations (
    confirmation_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL UNIQUE REFERENCES tasks (task_id),
    credential_id TEXT NOT NULL UNIQUE REFERENCES credentials (credential_id),
    confirmer_id TEXT NOT NULL,
    confirmation_source confirmation_source NOT NULL,
    request_hash TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    holder_agent_id TEXT NOT NULL REFERENCES agent_identities (agent_id),
    holder_key_id TEXT NOT NULL REFERENCES key_registry (key_id),
    delegation_depth INTEGER NOT NULL CHECK (delegation_depth BETWEEN 0 AND 16),
    confirmed_at BIGINT NOT NULL CHECK (confirmed_at >= 0)
);

CREATE UNIQUE INDEX uq_root_credential_per_task
    ON credentials (task_id)
    WHERE credential_type = 'ROOT';

UPDATE tasks AS task
SET status = 'PENDING_AUTHORIZATION', updated_at = GREATEST(updated_at, created_at)
WHERE status = 'AUTHORIZED'
  AND NOT EXISTS (
      SELECT 1 FROM credentials AS credential
      WHERE credential.task_id = task.task_id AND credential.credential_type = 'ROOT'
  );

COMMIT;

