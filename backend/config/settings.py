from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGENTGUARD_", extra="ignore")

    env: str = "development"
    database_url: str = "postgresql+psycopg://agentguard:agentguard@localhost:5432/agentguard"
    audit_database_url: str = "postgresql+psycopg://audit:audit@localhost:5433/agentguard_audit"
    storage: str = "postgres"
    tool_kind: str = "ticket"
    gateway_audience: str = "secure-tool-gateway"
    gateway_key_id: str = "gateway-key-01"
    gateway_public_key_hex: str = ""
    gateway_public_key_file: str = "/run/agentguard-keys/gateway.public"
    gateway_private_key_file: str = "/run/agentguard-keys/gateway.private"
    ticket_tool_url: str = "http://ticket-tool:8080"
    knowledge_tool_url: str = "http://knowledge-tool:8080"
    refund_tool_url: str = "http://refund-tool:8080"
    notification_tool_url: str = "http://notification-tool:8080"
    gateway_url: str = "http://secure-gateway:8080"
    business_action_registry_url: str = "http://business-action-registry:8080"
    agent_role: str = "coordinator"
    agent_id: str = "agent-coordinator"
    agent_key_id: str = "agent-coordinator-key-01"
    agent_private_key_file: str = "/run/agentguard-keys/agent.private"
    agent_delegation_url: str = ""
    knowledge_agent_url: str = "http://knowledge-agent:8080"
    case_agent_url: str = "http://case-agent:8080"
    refund_agent_url: str = "http://refund-agent:8080"
    agent_request_timeout_seconds: float = 30.0
    tool_request_timeout_seconds: float = 15.0
    recovery_max_attempts: int = 3
    recovery_deadline_seconds: int = 300
    recovery_dispatch_timeout_seconds: int = 30
    recovery_interval_seconds: int = 5
    recovery_request_timeout_seconds: float = 10.0
    recovery_autorun: bool = True
    authorization_subject_id: str = "authorization-authority"
    authorization_key_id: str = "auth-key-01"
    authorization_private_key_root: str = "/run/agentguard-keys/private"
    authorization_trusted_confirmers: str = "user-admin-01:USER,policy-refund-v1:POLICY"
    coauthorization_required: bool = False
    coauthorization_challenge_ttl_seconds: int = Field(default=300, ge=1, le=3600)
    delegation_agent_id: str = "agent-coordinator"
    delegation_key_id: str = "agent-coordinator-key-01"
    delegation_private_key_root: str = "/run/agentguard-keys/private"
    receipt_private_key_file: str = "/run/agentguard-keys/receipt.private"
    receipt_public_key_file: str = "/run/agentguard-keys/receipt.public"
    receipt_key_id: str = "receipt-key-01"
    receipt_service_url: str = ""
    receipt_request_timeout_seconds: float = 10.0
    audit_private_key_file: str = "/run/agentguard-keys/audit.private"
    audit_public_key_file: str = "/run/agentguard-keys/audit.public"
    audit_key_id: str = "audit-key-01"
    audit_service_url: str = ""
    audit_request_timeout_seconds: float = 10.0
    checkpoint_service_url: str = ""
    authority_url: str = "http://authorization-authority:8080"
    revocation_url: str = "http://revocation-authority:8080"
    coordinator_agent_url: str = "http://coordinator-agent:8080"
    live_refund_agent_url: str = "http://refund-agent-live-demo:8080"
    ui_database_url: str = ""
    ui_artifact_root: str = "artifacts"
    ui_request_timeout_seconds: float = 180.0
    audit_worker_interval_seconds: int = 1
    checkpoint_worker_interval_seconds: int = 2
    freshness_window_seconds: int = 60
    allowed_clock_skew_seconds: int = 5
    envelope_ttl_seconds: int = 30
    checkpoint_interval_events: int = 10
    llm_mode: str = "deterministic"
    llm_request_timeout_seconds: float = 120.0
    workflow_database_url: str = ""
    workflow_timeout_seconds: int = 900
    cloud_llm_enabled: bool = False
    cloud_llm_base_url: str = "https://api.deepseek.com"
    cloud_llm_model: str = "deepseek-flash"
    cloud_llm_api_key: str = ""
    model_configurations_path: str = ""
    operator_auth_required: bool = False
    operator_session_secret: str = Field(default="", repr=False)
    operator_subject_id: str = "native-operator"
    internal_auth_required: bool = False
    internal_auth_service_id: str = ""
    internal_auth_keys: str = "{}"
    internal_auth_nonce_root: str = ""
    benchmark_mode: str = "shared_static_credential"
    benchmark_admin_token: str = "benchmark-admin-local-only"
    benchmark_static_token: str = "benchmark-static-credential-local-only"
    benchmark_rbac_token: str = "benchmark-rbac-credential-local-only"
    benchmark_ticket_tool_url: str = "http://benchmark-ticket-tool:8080"
    benchmark_knowledge_tool_url: str = "http://benchmark-knowledge-tool:8080"
    benchmark_refund_tool_url: str = "http://benchmark-refund-tool:8080"
    benchmark_notification_tool_url: str = "http://benchmark-notification-tool:8080"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
