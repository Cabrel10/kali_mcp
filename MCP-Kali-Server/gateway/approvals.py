"""Short-lived, one-time human approvals bound to one tool and target."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class ApprovalClaims:
    tool: str
    target: str
    actor: str
    expires_at: int
    nonce: str


class ApprovalStore:
    """Issue and consume HMAC approvals without persisting the signing secret."""

    def __init__(self, *, secret: bytes, clock=time.time) -> None:
        if len(secret) < 8:
            raise ValueError("approval secret must contain at least 8 bytes")
        self._secret = secret
        self._clock = clock
        self._consumed: set[str] = set()
        self._lock = threading.Lock()

    @staticmethod
    def _encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    @staticmethod
    def _decode(data: str) -> bytes:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))

    def issue(self, *, tool: str, target: str, actor: str, ttl_seconds: int = 300) -> str:
        if not tool or not target or not actor:
            raise ValueError("tool, target and actor are required")
        if not 1 <= ttl_seconds <= 900:
            raise ValueError("approval TTL must be between 1 and 900 seconds")
        payload = {
            "tool": tool,
            "target": target,
            "actor": actor,
            "exp": int(self._clock()) + ttl_seconds,
            "nonce": secrets.token_urlsafe(18),
        }
        body = self._encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        signature = self._encode(hmac.new(self._secret, body.encode(), hashlib.sha256).digest())
        return f"{body}.{signature}"

    def _claims(self, token: str) -> ApprovalClaims | None:
        try:
            body, supplied = token.split(".", 1)
            expected = self._encode(hmac.new(self._secret, body.encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(supplied, expected):
                return None
            payload = json.loads(self._decode(body))
            claims = ApprovalClaims(
                tool=str(payload["tool"]),
                target=str(payload["target"]),
                actor=str(payload["actor"]),
                expires_at=int(payload["exp"]),
                nonce=str(payload["nonce"]),
            )
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None
        if claims.expires_at < int(self._clock()):
            return None
        return claims

    def consume(self, token: str, *, tool: str, target: str) -> bool:
        claims = self._claims(token)
        if claims is None or claims.tool != tool or claims.target != target:
            return False
        with self._lock:
            if claims.nonce in self._consumed:
                return False
            self._consumed.add(claims.nonce)
        return True
