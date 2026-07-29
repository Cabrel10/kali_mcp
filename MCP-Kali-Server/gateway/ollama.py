"""Constrained three-model Ollama orchestration for MCP planning and review."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
from typing import Any, Protocol
from urllib import error, request


class PlanError(ValueError):
    pass


@dataclass(frozen=True)
class ModelRoles:
    router: str = "qwen3:1.7b"
    analyzer: str = "qwen2.5-coder:3b"
    validator: str = "llama3.2:3b"


@dataclass(frozen=True)
class ToolPlan:
    tool: str
    arguments: dict[str, Any]
    rationale: str


class OllamaTransport(Protocol):
    async def generate(self, model: str, prompt: str, *, schema: dict[str, Any] | None = None) -> str: ...


class HTTPOllamaTransport:
    def __init__(self, base_url: str = "http://127.0.0.1:11434") -> None:
        self.base_url = base_url.rstrip("/")

    def _generate_sync(self, model: str, prompt: str, schema: dict[str, Any] | None) -> str:
        payload: dict[str, Any] = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0},
        }
        if schema is not None:
            payload["format"] = schema
        req = request.Request(
            self.base_url + "/api/generate",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=120) as response:
                result = json.load(response)
        except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Ollama request failed: {exc}") from exc
        text = result.get("response")
        if not isinstance(text, str):
            raise RuntimeError("Ollama returned no textual response")
        return text

    async def generate(self, model: str, prompt: str, *, schema: dict[str, Any] | None = None) -> str:
        return await asyncio.to_thread(self._generate_sync, model, prompt, schema)


_PLAN_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["tool", "arguments", "rationale"],
    "properties": {
        "tool": {"type": "string"},
        "arguments": {"type": "object"},
        "rationale": {"type": "string"},
    },
}
_ANALYSIS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "severity", "findings"],
    "properties": {
        "summary": {"type": "string"},
        "severity": {"enum": ["info", "low", "medium", "high", "critical"]},
        "findings": {"type": "array", "items": {"type": "object"}},
    },
}
_VALIDATION_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["valid", "issues"],
    "properties": {
        "valid": {"type": "boolean"},
        "issues": {"type": "array", "items": {"type": "string"}},
    },
}


def _strict_object(text: str, required: set[str], allowed: set[str]) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PlanError("model output is not strict JSON") from exc
    if not isinstance(value, dict):
        raise PlanError("model output must be a JSON object")
    keys = set(value)
    if not required <= keys or not keys <= allowed:
        raise PlanError("model output does not match the required schema")
    return value


class OllamaOrchestrator:
    def __init__(
        self,
        *,
        transport: OllamaTransport | None = None,
        roles: ModelRoles | None = None,
    ) -> None:
        self.transport = transport or HTTPOllamaTransport()
        self.roles = roles or ModelRoles()

    async def plan(self, objective: str, *, allowed_tools: set[str]) -> ToolPlan:
        if not objective.strip() or not allowed_tools:
            raise PlanError("objective and at least one allowed tool are required")
        prompt = (
            "You are a pentest routing component, not an autonomous attacker. "
            "Select exactly one tool from this allowlist: "
            f"{sorted(allowed_tools)}. Return strict JSON only. Objective: {objective}"
        )
        raw = await self.transport.generate(self.roles.router, prompt, schema=_PLAN_SCHEMA)
        data = _strict_object(raw, {"tool", "arguments", "rationale"}, {"tool", "arguments", "rationale"})
        if data["tool"] not in allowed_tools:
            raise PlanError("model selected a tool outside the explicit allowlist")
        if not isinstance(data["arguments"], dict) or not isinstance(data["rationale"], str):
            raise PlanError("model plan contains invalid field types")
        return ToolPlan(data["tool"], data["arguments"], data["rationale"])

    async def review(self, tool_result: dict[str, Any]) -> dict[str, Any]:
        safe_result = json.dumps(tool_result, sort_keys=True, default=str)[:50_000]
        analysis_raw = await self.transport.generate(
            self.roles.analyzer,
            "Analyze this authorized pentest result. Do not invent evidence. Return strict JSON: " + safe_result,
            schema=_ANALYSIS_SCHEMA,
        )
        analysis = _strict_object(
            analysis_raw,
            {"summary", "severity", "findings"},
            {"summary", "severity", "findings"},
        )
        validation_raw = await self.transport.generate(
            self.roles.validator,
            "Validate that this analysis is supported by the supplied result. Return strict JSON only. "
            + json.dumps({"result": tool_result, "analysis": analysis}, default=str)[:60_000],
            schema=_VALIDATION_SCHEMA,
        )
        validation = _strict_object(validation_raw, {"valid", "issues"}, {"valid", "issues"})
        if not isinstance(validation["valid"], bool) or not isinstance(validation["issues"], list):
            raise PlanError("validator output contains invalid field types")
        return {"analysis": analysis, "validation": validation}
