"""Append-only structured audit logging with recursive secret redaction."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import threading
from typing import Any

_SECRET_KEYS = {
    "api_key", "apikey", "authorization", "password", "secret", "token",
    "approval_token", "payment-signature", "payment_signature",
}


def redact(value: Any, key: str = "") -> Any:
    if key.lower() in _SECRET_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    return value


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def write(self, event: str, data: dict[str, Any]) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "data": redact(data),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, sort_keys=True, default=str) + "\n"
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(line)
