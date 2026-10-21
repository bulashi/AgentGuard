from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from jsonschema import ValidationError as SchemaValidationError
from pydantic import Field, field_validator, model_validator
from referencing import Resource

from backend.authorization.contracts import IDENTIFIER_PATTERN, MAX_SAFE_INTEGER
from backend.coauthorization.verifier import EXTENSION_SCHEMA_ROOT
from backend.common.schema import PROJECT_ROOT, SchemaStore
from backend.crypto.canonical_json import canonicalize
from backend.crypto.sm import signed_object_hash
from backend.gateway.contracts import StrictContract

PREFIX_SCHEMA_ROOT = PROJECT_ROOT / "protocol" / "extensions" / "audit-prefix-binding-v1"
MAX_PREFIX_EVENTS = 100
EVENT_CORE_FIELDS = (
    "schema_version", "event_sequence", "event_id", "execution_id", "event_type",
    "timestamp", "payload_hash", "evidence_reference", "previous_event_hash", "event_hash",
)


@lru_cache(maxsize=1)
def prefix_schemas() -> SchemaStore:
    store = SchemaStore(PREFIX_SCHEMA_ROOT)
    for root in (
        PROJECT_ROOT / "protocol" / "schemas", EXTENSION_SCHEMA_ROOT,
        PROJECT_ROOT / "protocol" / "extensions" / "dispatch-revocation" / "v1",
    ):
        for document in SchemaStore(Path(root)).documents.values():
            store.registry = store.registry.with_resource(document["$id"], Resource.from_contents(document))
    return store


def event_core(event: dict[str, Any]) -> dict[str, Any]:
    return {key: event[key] for key in EVENT_CORE_FIELDS}


def validate_event_core(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(EVENT_CORE_FIELDS):
        raise ValueError("audit event must contain exactly its versioned core fields")
    if type(value["event_sequence"]) is not int or type(value["timestamp"]) is not int:
        raise ValueError("audit event integers must not be coerced")
    try:
        prefix_schemas().validate("event-core.schema.json", value)
    except SchemaValidationError:
        raise ValueError("audit event violates its versioned schema") from None
    return value


class AuditPrefixRequest(StrictContract):
    schema_version: Literal["1.0"]
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    events: list[dict[str, Any]] = Field(min_length=1, max_length=MAX_PREFIX_EVENTS)

    @field_validator("events", mode="before")
    @classmethod
    def validate_events(cls, value: Any) -> Any:
        if type(value) is not list:
            raise ValueError("audit events must be a list")
        if not 1 <= len(value) <= MAX_PREFIX_EVENTS:
            raise ValueError("audit event batch must contain between 1 and 100 events")
        ids: set[str] = set()
        sequences: set[int] = set()
        for event in value:
            validate_event_core(event)
            if event["event_id"] in ids or event["event_sequence"] in sequences:
                raise ValueError("audit event IDs and sequences must each be unique")
            ids.add(event["event_id"])
            sequences.add(event["event_sequence"])
        return value


class AuditPrefixVerification(StrictContract):
    valid: bool
    checked_events: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    latest_event_sequence: int = Field(ge=0, le=MAX_SAFE_INTEGER)
    latest_event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    rollback_detected: bool
    first_invalid_sequence: int | None = Field(ge=1, le=MAX_SAFE_INTEGER)


class VerifiedAuditCheckpoint(StrictContract):
    signed_checkpoint: dict[str, Any]
    signed_object_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("signed_checkpoint", mode="before")
    @classmethod
    def validate_checkpoint(cls, value: Any) -> Any:
        try:
            prefix_schemas().validate("signed-checkpoint.schema.json", value)
        except SchemaValidationError:
            raise ValueError("checkpoint violates its frozen schema") from None
        payload, signature = value["payload"], value["signature"]
        if any(type(payload[field]) is not int for field in (
            "checkpoint_sequence", "latest_event_sequence", "timestamp",
        )) or type(signature["signed_at"]) is not int:
            raise ValueError("checkpoint integers must not be coerced")
        if (signature["key_purpose"] != "AUDIT_CHECKPOINT_SIGNING"
                or signature["signed_at"] != payload["timestamp"]):
            raise ValueError("checkpoint signature metadata differs from its payload")
        return value

    @model_validator(mode="after")
    def validate_digest(self) -> VerifiedAuditCheckpoint:
        if signed_object_hash(self.signed_checkpoint) != self.signed_object_hash:
            raise ValueError("checkpoint signed-object digest differs")
        return self


class AuditEventBinding(StrictContract):
    event_sequence: int = Field(ge=1, le=MAX_SAFE_INTEGER)
    event_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    matched: bool
    covered: bool
    verified_event: dict[str, Any] | None

    @field_validator("verified_event", mode="before")
    @classmethod
    def validate_verified_event(cls, value: Any) -> Any:
        return None if value is None else validate_event_core(value)

    @model_validator(mode="after")
    def validate_binding(self) -> AuditEventBinding:
        if self.verified_event is None:
            if self.matched or self.covered:
                raise ValueError("missing event cannot match or be covered")
        elif (self.verified_event["event_sequence"] != self.event_sequence
              or self.verified_event["event_id"] != self.event_id
              or (self.matched and self.verified_event["event_hash"] != self.event_hash)):
            raise ValueError("event binding metadata differs from the verified event")
        if self.covered and not self.matched:
            raise ValueError("unmatched event cannot be covered")
        return self


class AuditPrefixResponse(StrictContract):
    schema_version: Literal["1.0"]
    task_id: str = Field(min_length=1, max_length=128, pattern=IDENTIFIER_PATTERN)
    verification: AuditPrefixVerification
    checkpoint: VerifiedAuditCheckpoint | None
    event_bindings: list[AuditEventBinding] = Field(min_length=1, max_length=MAX_PREFIX_EVENTS)

    @model_validator(mode="after")
    def validate_report(self) -> AuditPrefixResponse:
        report = self.verification
        if report.valid and (report.rollback_detected or report.first_invalid_sequence is not None
                             or report.checked_events != report.latest_event_sequence):
            raise ValueError("positive verification report is inconsistent")
        anchor_sequence = None
        anchor_hash = None
        if self.checkpoint is not None:
            payload = self.checkpoint.signed_checkpoint["payload"]
            anchor_sequence = payload["latest_event_sequence"]
            anchor_hash = payload["latest_event_hash"]
            if (not report.valid or anchor_sequence > report.latest_event_sequence
                    or (anchor_sequence == report.latest_event_sequence
                        and payload["latest_event_hash"] != report.latest_event_hash)):
                raise ValueError("checkpoint is not from a consistent verified prefix")
        elif report.valid:
            raise ValueError("positive prefix report requires a verified checkpoint")
        ids: set[str] = set()
        sequences: set[int] = set()
        for binding in self.event_bindings:
            if binding.event_id in ids or binding.event_sequence in sequences:
                raise ValueError("event bindings must have unique IDs and sequences")
            ids.add(binding.event_id)
            sequences.add(binding.event_sequence)
            verified = binding.verified_event
            if report.valid and verified is not None and (
                binding.event_sequence > report.latest_event_sequence
                or (binding.event_sequence == report.latest_event_sequence
                    and verified["event_hash"] != report.latest_event_hash)
                or (binding.event_sequence == anchor_sequence and verified["event_hash"] != anchor_hash)
            ):
                raise ValueError("retained event differs from the verified head or checkpoint")
            if binding.covered and (not report.valid or anchor_sequence is None
                                    or binding.event_sequence > anchor_sequence):
                raise ValueError("event is outside the verified checkpoint prefix")
        return self

    def require_request_binding(self, request: AuditPrefixRequest) -> None:
        if self.task_id != request.task_id or len(self.event_bindings) != len(request.events):
            raise ValueError("prefix report does not bind the requested task/event batch")
        for binding, selected in zip(self.event_bindings, request.events, strict=True):
            if (binding.event_sequence != selected["event_sequence"]
                    or binding.event_id != selected["event_id"]
                    or binding.event_hash != selected["event_hash"]):
                raise ValueError("prefix report event identity differs from the request")
            expected_match = (binding.verified_event is not None
                              and canonicalize(binding.verified_event) == canonicalize(selected))
            if binding.matched != expected_match:
                raise ValueError("prefix report match flag differs from the complete event core")
