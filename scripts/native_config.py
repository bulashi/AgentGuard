from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from scripts.native_security import service_identity

# Consume the key before native_runtime launches helpers that inherit its environment.
_CLOUD_LLM_API_KEY = os.environ.pop("AGENTGUARD_CLOUD_LLM_API_KEY", "")
if os.environ.pop("AGENTGUARD_NATIVE_CLOUD_KEY_STDIN", "") == "1":
    _CLOUD_LLM_API_KEY = sys.stdin.readline(1026).rstrip("\r\n")
    if (
        not _CLOUD_LLM_API_KEY
        or len(_CLOUD_LLM_API_KEY) > 1024
        or any(not 33 <= ord(char) <= 126 for char in _CLOUD_LLM_API_KEY)
    ):
        raise ValueError("The native launcher did not supply a usable cloud API key")


@dataclass(frozen=True)
class Service:
    name: str
    module: str
    port: int
    environment: dict[str, str] = field(repr=False)
    windows_service_name: str = ""
    windows_config_path: Path | None = None


def prepare_model_profiles(path: Path) -> None:
    from backend.config.model_profiles import ModelProfileStore, ProfileInput

    store = ModelProfileStore(path)
    if store.public()["items"] or not _CLOUD_LLM_API_KEY:
        return
    requested, base_url, model, key = cloud_configuration()
    if requested:
        store.save(
            "primary",
            ProfileInput(
                name="云端智能体",
                provider_id="deepseek",
                base_url=base_url,
                model=model,
                api_key=key,
                set_default=True,
            ),
        )


def cloud_configuration(
    model_configurations_path: Path | None = None,
) -> tuple[bool, str, str, str]:
    if model_configurations_path is not None:
        from backend.config.model_profiles import ModelProfileStore

        configurations = ModelProfileStore(model_configurations_path).public()
        default = next((item for item in configurations["items"] if item["is_default"]), None)
        if default is None:
            return False, "", "", ""
        return (
            bool(default["enabled"] and default["has_key"]),
            default["base_url"],
            default["model"],
            "",
        )
    enabled = os.getenv("AGENTGUARD_CLOUD_LLM_ENABLED", "false").lower()
    if enabled not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
        raise ValueError("AGENTGUARD_CLOUD_LLM_ENABLED must be an explicit boolean")
    requested = enabled in {"true", "1", "yes", "on"}
    base_url = os.getenv("AGENTGUARD_CLOUD_LLM_BASE_URL", "https://api.deepseek.com")
    model = os.getenv("AGENTGUARD_CLOUD_LLM_MODEL", "deepseek-flash")
    if requested and (base_url != "https://api.deepseek.com" or model != "deepseek-flash"):
        raise ValueError("Native cloud review requires https://api.deepseek.com and deepseek-flash")
    if requested and not _CLOUD_LLM_API_KEY:
        raise ValueError(
            "DeepSeek API key is missing; use the hidden prompt in start-cloud-native.ps1"
        )
    return requested, base_url, model, _CLOUD_LLM_API_KEY if requested else ""


def service_specs(
    main_url: str,
    audit_url: str,
    ui_url: str,
    key_root: Path,
    *,
    with_llm: bool,
    workflow_url: str = "",
    model_configurations_path: Path | None = None,
    internal_keys: dict[str, dict[str, str]] | None = None,
    operator_session_secret: str = "",
    isolation_mode: str = "current-user",
    isolation_root: Path | None = None,
    windows_service_names: dict[str, str] | None = None,
    windows_model_revision: str = "",
) -> list[list[Service]]:
    if isolation_mode not in {"current-user", "scm-virtual-account"}:
        raise ValueError("an explicit supported native isolation mode is required")
    if isolation_mode == "scm-virtual-account" and (
        isolation_root is None or windows_service_names is None
        or internal_keys is None or not operator_session_secret
    ):
        raise ValueError("SCM isolation requires provisioned identities and per-role credentials")
    if with_llm:
        raise ValueError("Managed local models are retired; use start-cloud-native.ps1")
    private = key_root / "private"
    public = key_root / "public"
    cloud_requested, cloud_base_url, cloud_model, cloud_api_key = cloud_configuration(
        model_configurations_path
    )
    coauthorization_required = os.getenv("AGENTGUARD_COAUTHORIZATION_REQUIRED", "false").lower()
    if coauthorization_required not in {"true", "false", "1", "0", "yes", "no", "on", "off"}:
        raise ValueError("AGENTGUARD_COAUTHORIZATION_REQUIRED must be an explicit boolean")
    base = {
        "AGENTGUARD_ENV": "development",
        "AGENTGUARD_DATABASE_URL": main_url,
        "AGENTGUARD_AUDIT_DATABASE_URL": audit_url,
        "AGENTGUARD_LLM_MODE": "deterministic",
    }

    def service(name: str, module: str, port: int, **overrides: str) -> Service:
        environment = base | {f"AGENTGUARD_{key}": value for key, value in overrides.items()}
        if internal_keys is not None:
            identity = service_identity(name)
            environment |= {
                "AGENTGUARD_INTERNAL_AUTH_REQUIRED": "true",
                "AGENTGUARD_INTERNAL_AUTH_SERVICE_ID": identity,
                "AGENTGUARD_INTERNAL_AUTH_KEYS": json.dumps(internal_keys.get(identity, {})),
            }
        if module == "agent_runtime.app":
            environment.pop("AGENTGUARD_DATABASE_URL", None)
            environment.pop("AGENTGUARD_AUDIT_DATABASE_URL", None)
        return Service(name, f"backend.{module}:app", port, environment)

    tools = [
        service(
            f"{kind}-tool",
            "tools.app",
            port,
            TOOL_KIND=kind,
            STORAGE="postgres",
            GATEWAY_KEY_ID="gateway-key-01",
            GATEWAY_PUBLIC_KEY_FILE=str(public / "gateway.public"),
        )
        for kind, port in (
            ("ticket", 18301),
            ("knowledge", 18302),
            ("refund", 18303),
            ("notification", 18304),
        )
    ]
    core = [
        service(
            "authorization-authority",
            "authorization.app",
            18001,
            AUTHORIZATION_SUBJECT_ID="authorization-authority",
            AUTHORIZATION_KEY_ID="auth-key-01",
            AUTHORIZATION_PRIVATE_KEY_ROOT=str(private),
            AUTHORIZATION_TRUSTED_CONFIRMERS="user-admin-01:USER,policy-refund-v1:POLICY",
            COAUTHORIZATION_REQUIRED=coauthorization_required,
            COAUTHORIZATION_CHALLENGE_TTL_SECONDS=os.getenv(
                "AGENTGUARD_COAUTHORIZATION_CHALLENGE_TTL_SECONDS", "300"
            ),
        ),
        service("business-action-registry", "business_action.app", 18002),
        service(
            "secure-gateway",
            "gateway.app",
            18003,
            GATEWAY_AUDIENCE="secure-tool-gateway",
            GATEWAY_KEY_ID="gateway-key-01",
            GATEWAY_PRIVATE_KEY_FILE=str(private / "gateway.private"),
            GATEWAY_PUBLIC_KEY_FILE=str(public / "gateway.public"),
            TICKET_TOOL_URL="http://127.0.0.1:18301",
            KNOWLEDGE_TOOL_URL="http://127.0.0.1:18302",
            REFUND_TOOL_URL="http://127.0.0.1:18303",
            NOTIFICATION_TOOL_URL="http://127.0.0.1:18304",
            RECEIPT_SERVICE_URL="http://127.0.0.1:18006",
            AUDIT_SERVICE_URL="http://127.0.0.1:18007",
        ),
        service("revocation-authority", "revocation.app", 18005),
        service(
            "receipt-service",
            "receipt.app",
            18006,
            RECEIPT_KEY_ID="receipt-key-01",
            RECEIPT_PRIVATE_KEY_FILE=str(private / "receipt.private"),
        ),
        service("audit-append-authority", "audit.app", 18007),
        service(
            "checkpoint-service",
            "checkpoint.app",
            18008,
            AUDIT_KEY_ID="audit-key-01",
            AUDIT_PRIVATE_KEY_FILE=str(private / "audit.private"),
        ),
    ]
    delegations = [
        service(
            f"{role}-delegation-agent",
            "delegation.app",
            port,
            DELEGATION_PRIVATE_KEY_ROOT=str(private),
            DELEGATION_AGENT_ID=f"agent-{role}",
            DELEGATION_KEY_ID=f"agent-{role}-key-01",
        )
        for role, port in (("coordinator", 18101), ("case", 18102), ("refund", 18103))
    ]
    agents = []
    for role, port in (
        ("coordinator", 18201),
        ("knowledge", 18202),
        ("case", 18203),
        ("refund", 18204),
    ):
        overrides = {
            "AGENT_ROLE": role,
            "AGENT_ID": f"agent-{role}",
            "AGENT_KEY_ID": f"agent-{role}-key-01",
            "AGENT_PRIVATE_KEY_FILE": str(private / f"agent-{role}.private"),
            "RECEIPT_PUBLIC_KEY_FILE": str(public / "receipt.public"),
            "GATEWAY_URL": "http://127.0.0.1:18003",
            "BUSINESS_ACTION_REGISTRY_URL": "http://127.0.0.1:18002",
            "AGENT_REQUEST_TIMEOUT_SECONDS": "30",
            "COORDINATOR_AGENT_URL": "http://127.0.0.1:18201",
            "CLOUD_LLM_ENABLED": str(cloud_requested).lower(),
            "CLOUD_LLM_BASE_URL": cloud_base_url,
            "CLOUD_LLM_API_KEY": cloud_api_key,
            "CLOUD_LLM_MODEL": cloud_model,
            "MODEL_CONFIGURATIONS_PATH": str(model_configurations_path)
            if model_configurations_path
            else "",
        }
        if role == "coordinator":
            overrides |= {
                "AGENT_DELEGATION_URL": "http://127.0.0.1:18101",
                "KNOWLEDGE_AGENT_URL": "http://127.0.0.1:18202",
                "CASE_AGENT_URL": "http://127.0.0.1:18203",
                "WORKFLOW_DATABASE_URL": workflow_url,
            }
        if role == "case":
            overrides |= {
                "AGENT_DELEGATION_URL": "http://127.0.0.1:18102",
                "REFUND_AGENT_URL": "http://127.0.0.1:18204",
            }
        agents.append(service(f"{role}-agent", "agent_runtime.app", port, **overrides))
    workers = [
        service(
            "recovery-worker",
            "recovery.app",
            18004,
            REFUND_TOOL_URL="http://127.0.0.1:18303",
            NOTIFICATION_TOOL_URL="http://127.0.0.1:18304",
            RECEIPT_SERVICE_URL="http://127.0.0.1:18006",
            RECOVERY_AUTORUN="true",
            RECOVERY_INTERVAL_SECONDS="60",
        ),
        service(
            "audit-worker",
            "audit.worker_app",
            18009,
            AUDIT_SERVICE_URL="http://127.0.0.1:18007",
            AUDIT_WORKER_INTERVAL_SECONDS="1",
        ),
        service(
            "checkpoint-worker",
            "checkpoint.worker_app",
            18010,
            CHECKPOINT_SERVICE_URL="http://127.0.0.1:18008",
            CHECKPOINT_WORKER_INTERVAL_SECONDS="2",
        ),
    ]
    # The BFF must not inherit the core database or signing-key environment.
    ui = Service(
        "ui-api",
        "backend.ui_api.app:app",
        8090,
        {
            "AGENTGUARD_ENV": "development",
            "AGENTGUARD_UI_DATABASE_URL": ui_url,
            "AGENTGUARD_AUTHORITY_URL": "http://127.0.0.1:18001",
            "AGENTGUARD_REVOCATION_URL": "http://127.0.0.1:18005",
            "AGENTGUARD_COORDINATOR_AGENT_URL": "http://127.0.0.1:18201",
            "AGENTGUARD_REFUND_AGENT_URL": "http://127.0.0.1:18204",
            "AGENTGUARD_BUSINESS_ACTION_REGISTRY_URL": "http://127.0.0.1:18002",
            "AGENTGUARD_GATEWAY_URL": "http://127.0.0.1:18003",
            "AGENTGUARD_LIVE_REFUND_AGENT_URL": "",
            "AGENTGUARD_COAUTHORIZATION_REQUIRED": coauthorization_required,
            "AGENTGUARD_AUDIT_SERVICE_URL": "http://127.0.0.1:18007",
            "AGENTGUARD_CHECKPOINT_SERVICE_URL": "http://127.0.0.1:18008",
            "AGENTGUARD_UI_REQUEST_TIMEOUT_SECONDS": "180",
            "AGENTGUARD_MODEL_CONFIGURATIONS_PATH": str(model_configurations_path)
            if model_configurations_path
            else "",
            "AGENTGUARD_OPERATOR_AUTH_REQUIRED": str(bool(operator_session_secret)).lower(),
            "AGENTGUARD_OPERATOR_SESSION_SECRET": operator_session_secret,
        },
    )
    if internal_keys is not None:
        ui.environment.update(
            {
                "AGENTGUARD_INTERNAL_AUTH_REQUIRED": "true",
                "AGENTGUARD_INTERNAL_AUTH_SERVICE_ID": "ui-api",
                "AGENTGUARD_INTERNAL_AUTH_KEYS": json.dumps(internal_keys.get("ui-api", {})),
            }
        )
    groups = [tools, core, delegations, agents, workers, [ui]]
    if isolation_mode == "scm-virtual-account":
        from scripts.native_windows_isolation import scope_service_groups

        return scope_service_groups(groups, isolation_root, windows_service_names,
                                    model_revision=windows_model_revision)
    return groups
