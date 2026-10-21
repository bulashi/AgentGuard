from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.authorization.contracts import IDENTIFIER_PATTERN, MAX_SAFE_INTEGER
from backend.crypto.canonical_json import canonicalize

SERVICE_PATTERN = r"^[a-z][a-z0-9-]*$"
TOOL_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"
VERSION_PATTERN = r"^v[1-9][0-9]*$"


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def _require_unique(values: list[str], field_name: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} must contain unique values")
    return values


class DelegatedResources(StrictContract):
    ticket_ids: list[str] | None = Field(default=None, max_length=256)
    customer_ids: list[str] | None = Field(default=None, max_length=256)
    document_ids: list[str] | None = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def validate_sets(self) -> DelegatedResources:
        populated = 0
        for field_name in ("ticket_ids", "customer_ids", "document_ids"):
            values = getattr(self, field_name)
            if values is None:
                continue
            populated += 1
            if not values:
                raise ValueError(f"{field_name} cannot be empty when present")
            for value in values:
                if not value or len(value) > 128:
                    raise ValueError(f"{field_name} contains an invalid identifier")
            _require_unique(values, field_name)
        if populated == 0:
            raise ValueError("resources must contain at least one resource set")
        return self


class DelegatedConstraints(StrictContract):
    single_max_fen: int | None = Field(default=None, ge=0, le=MAX_SAFE_INTEGER)
    template_ids: list[str] | None = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def validate_templates(self) -> DelegatedConstraints:
        if self.template_ids is not None:
            if not self.template_ids:
                raise ValueError("template_ids cannot be empty when present")
            for value in self.template_ids:
                if not value or len(value) > 128:
                    raise ValueError("template_ids contains an invalid identifier")
            _require_unique(self.template_ids, "template_ids")
        return self


class DelegatedCapability(StrictContract):
    service: str = Field(min_length=1, max_length=64, pattern=SERVICE_PATTERN)
    tool: str = Field(min_length=3, max_length=96, pattern=TOOL_PATTERN)
    version: str = Field(pattern=VERSION_PATTERN)
    resources: DelegatedResources
    constraints: DelegatedConstraints


class DelegatedQuotas(StrictContract):
    refund_total_fen: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    max_tool_calls: int = Field(ge=0, le=MAX_SAFE_INTEGER)


class DelegateCredentialRequest(StrictContract):
    holder_agent_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    holder_key_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    capabilities: list[DelegatedCapability] = Field(min_length=1, max_length=64)
    quotas: DelegatedQuotas
    not_before: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    expires_at: int = Field(ge=0, le=MAX_SAFE_INTEGER)

    @model_validator(mode="after")
    def validate_request(self) -> DelegateCredentialRequest:
        if self.expires_at < self.not_before:
            raise ValueError("expires_at must not precede not_before")
        encoded = [canonicalize(item.model_dump(mode="json")) for item in self.capabilities]
        if len(encoded) != len(set(encoded)):
            raise ValueError("capabilities must be unique")
        return self

