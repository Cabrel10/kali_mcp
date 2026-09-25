"""Fail-closed scope and tool-risk policy for the HTTP gateway."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import ipaddress
from urllib.parse import urlsplit

from .approvals import ApprovalStore


class Risk(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    DISABLED = "disabled"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    risk: Risk
    reason: str


TOOL_RISKS: dict[str, Risk] = {
    "session_ops": Risk.PASSIVE,
    "recon_engine": Risk.PASSIVE,
    "protocol_deep_scan": Risk.PASSIVE,
    "honeypot_detector": Risk.PASSIVE,
    "reporting_engine": Risk.PASSIVE,
    "osint_harvester": Risk.PASSIVE,
    "bounty_validate": Risk.PASSIVE,
    "bounty_knowledge": Risk.PASSIVE,
    "web_assault": Risk.ACTIVE,
    "api_breaker": Risk.ACTIVE,
    "vuln_scanner_ultra": Risk.ACTIVE,
    "smart_fuzz_engine": Risk.ACTIVE,
    "web_interactor": Risk.ACTIVE,
    "bounty_scanner": Risk.ACTIVE,
    "bounty_graphql": Risk.ACTIVE,
    "injection_matrix": Risk.DISABLED,
    "credential_cracker": Risk.DISABLED,
    "network_dominator": Risk.DISABLED,
    "wireless_audit": Risk.DISABLED,
    "cloud_siege": Risk.DISABLED,
    "ad_annihilator": Risk.DISABLED,
    "exploit_engine": Risk.DISABLED,
    "auth_destroyer": Risk.DISABLED,
    "ssrf_hunter": Risk.DISABLED,
    "post_exploit_ops": Risk.DISABLED,
    "autopilot_commander": Risk.DISABLED,
    "payload_factory": Risk.DISABLED,
    "auto_exploit": Risk.DISABLED,
    "bounty_intruder": Risk.DISABLED,
    "bounty_cloud": Risk.DISABLED,
    "bounty_ad": Risk.DISABLED,
}


class GatewayPolicy:
    def __init__(
        self,
        *,
        allowed_targets: set[str] | None = None,
        approval_store: ApprovalStore | None = None,
    ) -> None:
        self.allowed_targets = {self.normalize_target(item) for item in (allowed_targets or set())}
        self.approval_store = approval_store

    @staticmethod
    def normalize_target(target: str) -> str:
        raw = target.strip()
        if not raw:
            return ""
        parsed = urlsplit(raw if "://" in raw else f"//{raw}")
        host = parsed.hostname or raw.split("/", 1)[0].split(":", 1)[0]
        return host.rstrip(".").lower()

    @staticmethod
    def _is_loopback(host: str) -> bool:
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def _target_in_scope(self, host: str, authorization_reference: str) -> bool:
        if self._is_loopback(host):
            return bool(authorization_reference)
        return host in self.allowed_targets and bool(authorization_reference.strip())

    def authorize(
        self,
        *,
        tool: str,
        target: str,
        authorization_reference: str = "",
        approval_token: str | None = None,
    ) -> PolicyResult:
        risk = TOOL_RISKS.get(tool, Risk.DISABLED)
        if tool not in TOOL_RISKS:
            return PolicyResult(Decision.DENY, risk, "Tool is not in the gateway allowlist.")
        if risk is Risk.DISABLED:
            return PolicyResult(Decision.DENY, risk, "Tool is disabled at the gateway boundary.")

        host = self.normalize_target(target)
        if not self._target_in_scope(host, authorization_reference):
            return PolicyResult(
                Decision.DENY,
                risk,
                "Target is outside the exact authorized scope or lacks an authorization reference.",
            )

        if risk is Risk.ACTIVE:
            if not approval_token or self.approval_store is None:
                return PolicyResult(Decision.REQUIRE_APPROVAL, risk, "Human approval is required.")
            if not self.approval_store.consume(approval_token, tool=tool, target=target):
                return PolicyResult(
                    Decision.REQUIRE_APPROVAL,
                    risk,
                    "Approval is invalid, expired, already consumed, or bound to another request.",
                )
        return PolicyResult(Decision.ALLOW, risk, "Authorized by gateway policy.")
