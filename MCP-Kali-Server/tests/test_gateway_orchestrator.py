"""Contracts for deterministic Ollama routing and safe MCP invocation."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from gateway.audit import AuditLog
from gateway.mcp_client import InMemoryMCPClient
from gateway.ollama import (
    DOLPHIN_PHI_MODEL,
    PHI4_MODEL,
    HTTPOllamaTransport,
    ModelRoles,
    OllamaOrchestrator,
    PlanError,
)


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    async def generate(self, model, prompt, *, schema=None):
        self.calls.append({"model": model, "prompt": prompt, "schema": schema})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class OllamaOrchestratorTests(unittest.TestCase):
    def test_phi4_is_primary_for_all_roles_with_dolphin_fallback(self):
        roles = ModelRoles()
        self.assertEqual(roles.router, PHI4_MODEL)
        self.assertEqual(roles.analyzer, PHI4_MODEL)
        self.assertEqual(roles.validator, PHI4_MODEL)
        self.assertEqual(roles.fallback, DOLPHIN_PHI_MODEL)
        self.assertNotIn("smollm", " ".join(vars(roles).values()).lower())

    def test_transport_timeout_is_strictly_bounded(self):
        self.assertEqual(HTTPOllamaTransport(timeout_seconds=30).timeout_seconds, 30)
        for invalid in (0, 121):
            with self.assertRaises(ValueError):
                HTTPOllamaTransport(timeout_seconds=invalid)

    def test_router_accepts_only_strict_known_tool_json(self):
        transport = FakeTransport([
            json.dumps({
                "tool": "recon_engine",
                "arguments": {"target": "localhost", "depth": "light"},
                "rationale": "Local passive inventory",
            })
        ])
        orchestrator = OllamaOrchestrator(transport=transport)
        plan = asyncio.run(orchestrator.plan("inventory localhost", allowed_tools={"recon_engine"}))
        self.assertEqual(plan.tool, "recon_engine")
        self.assertEqual(plan.arguments["target"], "localhost")
        self.assertEqual(transport.calls[0]["model"], PHI4_MODEL)

    def test_transport_failure_retries_once_with_dolphin_phi(self):
        transport = FakeTransport([
            RuntimeError("primary unavailable"),
            json.dumps({
                "tool": "recon_engine",
                "arguments": {"target": "localhost"},
                "rationale": "Fallback local inventory",
            }),
        ])
        orchestrator = OllamaOrchestrator(transport=transport)
        plan = asyncio.run(orchestrator.plan("inventory", allowed_tools={"recon_engine"}))
        self.assertEqual(plan.tool, "recon_engine")
        self.assertEqual(
            [call["model"] for call in transport.calls],
            [PHI4_MODEL, DOLPHIN_PHI_MODEL],
        )

    def test_invalid_primary_output_is_not_retried_with_fallback(self):
        transport = FakeTransport(["not-json"])
        orchestrator = OllamaOrchestrator(transport=transport)
        with self.assertRaises(PlanError):
            asyncio.run(orchestrator.plan("inventory", allowed_tools={"recon_engine"}))
        self.assertEqual(len(transport.calls), 1)

    def test_unknown_or_hallucinated_tool_is_rejected(self):
        transport = FakeTransport([
            json.dumps({"tool": "destroy_everything", "arguments": {}, "rationale": "no"})
        ])
        orchestrator = OllamaOrchestrator(transport=transport)
        with self.assertRaises(PlanError):
            asyncio.run(orchestrator.plan("do it", allowed_tools={"recon_engine"}))

    def test_markdown_wrapped_output_is_rejected_not_repaired_blindly(self):
        transport = FakeTransport([
            "```json\n{\"tool\":\"recon_engine\",\"arguments\":{},\"rationale\":\"x\"}\n```"
        ])
        orchestrator = OllamaOrchestrator(transport=transport)
        with self.assertRaises(PlanError):
            asyncio.run(orchestrator.plan("inventory", allowed_tools={"recon_engine"}))

    def test_analyzer_and_validator_are_used_for_structured_review(self):
        transport = FakeTransport([
            json.dumps({"summary": "one open local port", "severity": "info", "findings": []}),
            json.dumps({"valid": True, "issues": []}),
        ])
        orchestrator = OllamaOrchestrator(transport=transport)
        review = asyncio.run(orchestrator.review({"target": "localhost", "ports": [8000]}))
        self.assertTrue(review["validation"]["valid"])
        self.assertEqual(
            [call["model"] for call in transport.calls],
            [PHI4_MODEL, PHI4_MODEL],
        )


class MCPClientAndAuditTests(unittest.TestCase):
    def test_in_memory_client_never_exposes_unregistered_tools(self):
        async def health(**kwargs):
            return {"ok": True, "kwargs": kwargs}

        client = InMemoryMCPClient({"session_ops": health})
        result = asyncio.run(client.call_tool("session_ops", {"action": "health"}))
        self.assertTrue(result["ok"])
        with self.assertRaises(KeyError):
            asyncio.run(client.call_tool("auto_exploit", {"target": "localhost"}))

    def test_audit_log_redacts_tokens_and_passwords(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp) / "audit.jsonl")
            log.write("request", {
                "tool": "session_ops",
                "api_key": "top-secret",
                "nested": {"password": "hunter2", "target": "localhost"},
            })
            data = json.loads((Path(tmp) / "audit.jsonl").read_text())
        self.assertEqual(data["data"]["api_key"], "[REDACTED]")
        self.assertEqual(data["data"]["nested"]["password"], "[REDACTED]")
        self.assertEqual(data["data"]["nested"]["target"], "localhost")


if __name__ == "__main__":
    unittest.main()
