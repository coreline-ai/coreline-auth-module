"""Audit storage protocol and redaction helpers."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from coreline_auth.models import AuditEvent

SENSITIVE_AUDIT_KEY_PARTS = ("token", "password", "secret", "credential", "authorization")
MAX_AUDIT_METADATA_KEYS = 50
MAX_AUDIT_METADATA_STRING_LENGTH = 1_000
MAX_AUDIT_METADATA_LIST_ITEMS = 50
MAX_AUDIT_METADATA_DEPTH = 4


class AuditStorage(Protocol):
    def record_audit_event(self, event: AuditEvent) -> AuditEvent: ...

    def list_audit_events(
        self,
        *,
        action: str | None = None,
        actor_user_id: str | None = None,
        target_user_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]: ...


def redact_audit_metadata(value: dict[str, Any]) -> dict[str, Any]:
    return _redact_mapping(value, depth=0)


def _redact_mapping(value: dict[str, Any], *, depth: int) -> dict[str, Any]:
    if depth >= MAX_AUDIT_METADATA_DEPTH:
        return {"_truncated": "max_depth"}
    redacted: dict[str, Any] = {}
    for index, (key, item) in enumerate(value.items()):
        if index >= MAX_AUDIT_METADATA_KEYS:
            redacted["_truncated"] = "max_keys"
            break
        redacted[str(key)[:128]] = _redact_value(str(key), item, depth=depth)
    return redacted


def _redact_value(key: str, value: Any, *, depth: int) -> Any:
    lowered = key.lower()
    if any(part in lowered for part in SENSITIVE_AUDIT_KEY_PARTS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return _redact_mapping(value, depth=depth + 1)
    if isinstance(value, list):
        items = [_redact_value(key, item, depth=depth + 1) for item in value[:MAX_AUDIT_METADATA_LIST_ITEMS]]
        if len(value) > MAX_AUDIT_METADATA_LIST_ITEMS:
            items.append("[TRUNCATED]")
        return items
    if isinstance(value, str) and len(value) > MAX_AUDIT_METADATA_STRING_LENGTH:
        return value[:MAX_AUDIT_METADATA_STRING_LENGTH] + "...[TRUNCATED]"
    return value
