"""Security contracts for the MCP/Ollama HTTP gateway.

These tests intentionally avoid running offensive tools. All targets are localhost or
synthetic documentation domains.
"""
import base64
import json
import time
import unittest

from gateway.approvals import ApprovalStore
from gateway.policy import Decision, GatewayPolicy, Risk
from gateway.x402 import PaymentConfig, PaymentGate


class GatewayPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = GatewayPolicy()

    def test_localhost_passive_tool_is_allowed(self):
        result = self.policy.authorize(
            tool="recon_engine", target="127.0.0.1", authorization_reference="local-test"
        )
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertEqual(result.risk, Risk.PASSIVE)

    def test_external_target_is_denied_by_default(self):
        result = self.policy.authorize(
            tool="recon_engine", target="example.com", authorization_reference=""
        )
        self.assertEqual(result.decision, Decision.DENY)
        self.assertIn("scope", result.reason.lower())

    def test_exact_external_allowlist_and_authorization_reference_are_required(self):
        policy = GatewayPolicy(allowed_targets={"audit.example"})
        missing_ref = policy.authorize(tool="recon_engine", target="audit.example")
        allowed = policy.authorize(
            tool="recon_engine",
            target="audit.example",
            authorization_reference="SOW-2026-0042",
        )
        subdomain = policy.authorize(
            tool="recon_engine",
            target="other.audit.example",
            authorization_reference="SOW-2026-0042",
        )
        self.assertEqual(missing_ref.decision, Decision.DENY)
        self.assertEqual(allowed.decision, Decision.ALLOW)
        self.assertEqual(subdomain.decision, Decision.DENY)

    def test_active_tool_requires_bound_human_approval(self):
        store = ApprovalStore(secret=b"test-secret")
        policy = GatewayPolicy(approval_store=store)
        pending = policy.authorize(
            tool="web_assault",
            target="localhost",
            authorization_reference="local-test",
        )
        token = store.issue(
            tool="web_assault", target="localhost", actor="auditor@example.test", ttl_seconds=60
        )
        allowed = policy.authorize(
            tool="web_assault",
            target="localhost",
            authorization_reference="local-test",
            approval_token=token,
        )
        replay = policy.authorize(
            tool="web_assault",
            target="localhost",
            authorization_reference="local-test",
            approval_token=token,
        )
        self.assertEqual(pending.decision, Decision.REQUIRE_APPROVAL)
        self.assertEqual(allowed.decision, Decision.ALLOW)
        self.assertEqual(replay.decision, Decision.REQUIRE_APPROVAL)

    def test_approval_cannot_be_reused_for_another_tool_or_target(self):
        store = ApprovalStore(secret=b"test-secret")
        token = store.issue(
            tool="web_assault", target="localhost", actor="auditor@example.test", ttl_seconds=60
        )
        self.assertFalse(store.consume(token, tool="injection_matrix", target="localhost"))
        self.assertFalse(store.consume(token, tool="web_assault", target="127.0.0.1"))
        self.assertTrue(store.consume(token, tool="web_assault", target="localhost"))

    def test_destructive_tools_remain_disabled_even_with_approval(self):
        store = ApprovalStore(secret=b"test-secret")
        token = store.issue(
            tool="auto_exploit", target="localhost", actor="auditor@example.test", ttl_seconds=60
        )
        result = GatewayPolicy(approval_store=store).authorize(
            tool="auto_exploit",
            target="localhost",
            authorization_reference="local-test",
            approval_token=token,
        )
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(result.risk, Risk.DISABLED)

    def test_unknown_tool_is_denied(self):
        result = self.policy.authorize(
            tool="model_hallucinated_tool", target="localhost", authorization_reference="local-test"
        )
        self.assertEqual(result.decision, Decision.DENY)


class X402Tests(unittest.TestCase):
    def test_disabled_payment_gate_never_claims_payment_was_verified(self):
        gate = PaymentGate(PaymentConfig(enabled=False))
        result = gate.check(None, resource="/api/v1/tools/recon_engine")
        self.assertTrue(result.allowed)
        self.assertFalse(result.verified)
        self.assertIsNone(result.settlement)

    def test_missing_signature_returns_v2_payment_required_header(self):
        gate = PaymentGate(
            PaymentConfig(
                enabled=True,
                pay_to="0x0000000000000000000000000000000000000001",
                price="$0.01",
                network="eip155:84532",
            )
        )
        result = gate.check(None, resource="/api/v1/tools/recon_engine")
        self.assertFalse(result.allowed)
        self.assertEqual(result.status_code, 402)
        encoded = result.headers["PAYMENT-REQUIRED"]
        payload = json.loads(base64.b64decode(encoded).decode())
        self.assertEqual(payload["x402Version"], 2)
        self.assertEqual(payload["accepts"][0]["network"], "eip155:84532")
        self.assertEqual(payload["accepts"][0]["payTo"], gate.config.pay_to)

    def test_unconfigured_pay_to_fails_closed(self):
        gate = PaymentGate(PaymentConfig(enabled=True, pay_to=""))
        with self.assertRaises(ValueError):
            gate.check(None, resource="/api/v1/tools/recon_engine")

    def test_signature_is_not_trusted_without_a_facilitator(self):
        gate = PaymentGate(
            PaymentConfig(
                enabled=True,
                pay_to="0x0000000000000000000000000000000000000001",
                facilitator_url="",
            )
        )
        fake_signature = base64.b64encode(json.dumps({"fake": True}).encode()).decode()
        result = gate.check(fake_signature, resource="/api/v1/tools/recon_engine")
        self.assertFalse(result.allowed)
        self.assertFalse(result.verified)
        self.assertIn("facilitator", result.error.lower())


if __name__ == "__main__":
    unittest.main()
