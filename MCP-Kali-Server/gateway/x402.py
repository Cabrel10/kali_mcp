"""Minimal x402 v2 resource-server adapter with facilitator verification.

Cryptographic verification and settlement are delegated to an x402 facilitator. The
gateway never treats a syntactically valid header as proof of payment.
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass, field
import json
from typing import Any
from urllib import error, request


@dataclass(frozen=True)
class PaymentConfig:
    enabled: bool = False
    pay_to: str = ""
    price: str = "$0.01"
    amount: str = "10000"
    asset: str = "0x036CbD53842c5426634e7929541eC2318f3dCF7c"
    network: str = "eip155:84532"
    facilitator_url: str = ""
    max_timeout_seconds: int = 300


@dataclass(frozen=True)
class PaymentResult:
    allowed: bool
    verified: bool
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    error: str = ""
    payment_payload: dict[str, Any] | None = None
    requirements: dict[str, Any] | None = None
    settlement: dict[str, Any] | None = None


class PaymentGate:
    def __init__(self, config: PaymentConfig) -> None:
        self.config = config

    @staticmethod
    def _encode(payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        return base64.b64encode(raw).decode()

    @staticmethod
    def _decode(value: str) -> dict[str, Any]:
        decoded = json.loads(base64.b64decode(value, validate=True).decode())
        if not isinstance(decoded, dict):
            raise ValueError("x402 header must contain a JSON object")
        return decoded

    def payment_required(self, resource: str, *, error_message: str = "") -> PaymentResult:
        if not self.config.pay_to:
            raise ValueError("x402 pay_to must be configured when payments are enabled")
        requirement = {
            "scheme": "exact",
            "network": self.config.network,
            "amount": self.config.amount,
            "asset": self.config.asset,
            "payTo": self.config.pay_to,
            "maxTimeoutSeconds": self.config.max_timeout_seconds,
            "extra": {"displayPrice": self.config.price},
        }
        payload = {
            "x402Version": 2,
            "error": error_message or None,
            "resource": {"url": resource, "description": "Authorized MCP tool execution"},
            "accepts": [requirement],
        }
        return PaymentResult(
            allowed=False,
            verified=False,
            status_code=402,
            headers={"PAYMENT-REQUIRED": self._encode(payload)},
            error=error_message,
            requirements=requirement,
        )

    def check(self, signature: str | None, *, resource: str) -> PaymentResult:
        """Perform local preflight checks; facilitator verification remains mandatory."""
        if not self.config.enabled:
            return PaymentResult(allowed=True, verified=False, status_code=200)
        missing = self.payment_required(resource)
        if not signature:
            return missing
        if not self.config.facilitator_url:
            return self.payment_required(resource, error_message="x402 facilitator is not configured")
        try:
            payload = self._decode(signature)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            return self.payment_required(resource, error_message=f"invalid PAYMENT-SIGNATURE: {exc}")
        return PaymentResult(
            allowed=False,
            verified=False,
            status_code=402,
            headers=missing.headers,
            error="payment requires facilitator verification",
            payment_payload=payload,
            requirements=missing.requirements,
        )

    @staticmethod
    def _post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode()
        req = request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with request.urlopen(req, timeout=15) as response:
                result = json.load(response)
        except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"x402 facilitator request failed: {exc}") from exc
        if not isinstance(result, dict):
            raise RuntimeError("x402 facilitator returned a non-object response")
        return result

    async def verify(self, signature: str | None, *, resource: str) -> PaymentResult:
        preflight = self.check(signature, resource=resource)
        if not self.config.enabled or not signature or not self.config.facilitator_url:
            return preflight
        if preflight.payment_payload is None or preflight.requirements is None:
            return preflight
        response = await asyncio.to_thread(
            self._post_json,
            self.config.facilitator_url.rstrip("/") + "/verify",
            {
                "x402Version": 2,
                "paymentPayload": preflight.payment_payload,
                "paymentRequirements": preflight.requirements,
            },
        )
        valid = bool(response.get("isValid") or response.get("valid"))
        if not valid:
            return self.payment_required(resource, error_message=str(response.get("invalidReason", "payment rejected")))
        return PaymentResult(
            allowed=True,
            verified=True,
            status_code=200,
            payment_payload=preflight.payment_payload,
            requirements=preflight.requirements,
        )

    async def settle(self, verified: PaymentResult) -> PaymentResult:
        if not verified.verified or not verified.payment_payload or not verified.requirements:
            raise ValueError("only facilitator-verified payments can be settled")
        response = await asyncio.to_thread(
            self._post_json,
            self.config.facilitator_url.rstrip("/") + "/settle",
            {
                "x402Version": 2,
                "paymentPayload": verified.payment_payload,
                "paymentRequirements": verified.requirements,
            },
        )
        success = bool(response.get("success"))
        header = self._encode(response)
        return PaymentResult(
            allowed=success,
            verified=True,
            status_code=200 if success else 402,
            headers={"PAYMENT-RESPONSE": header},
            error="" if success else str(response.get("errorReason", "settlement failed")),
            payment_payload=verified.payment_payload,
            requirements=verified.requirements,
            settlement=response,
        )
