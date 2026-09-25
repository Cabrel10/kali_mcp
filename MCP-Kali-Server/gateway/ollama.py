"""Constrained three-model Ollama orchestration for MCP planning and review."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import os
from typing import Any, Protocol
from urllib import error, request


class PlanError(ValueError):
    pass


PHI4_MODEL = "hf.co/mradermacher/Phi-4-Mini-Abliterated-GGUF:Q4_K_M"
DOLPHIN_PHI_MODEL = "dolphin-phi:latest"


@dataclass(frozen=True)
class ModelRoles:
    """Use Phi-4 for every constrained reasoning role with one local fallback."""

    router: str = os.getenv("OLLAMA_PRIMARY_MODEL", PHI4_MODEL)
    analyzer: str = os.getenv("OLLAMA_PRIMARY_MODEL", PHI4_MODEL)
    validator: str = os.getenv("OLLAMA_PRIMARY_MODEL", PHI4_MODEL)
    fallback: str = os.getenv("OLLAMA_FALLBACK_MODEL", DOLPHIN_PHI_MODEL)


@dataclass(frozen=True)
class ToolPlan:
    tool: str
    arguments: dict[str, Any]
    rationale: str


class OllamaTransport(Protocol):
    async def generate(self, model: str, prompt: str, *, schema: dict[str, Any] | None = None) -> str: ...


class HTTPOllamaTransport:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        configured_timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "60"))
        )
        if not 1 <= configured_timeout <= 120:
            raise ValueError("Ollama timeout must be between 1 and 120 seconds")
        self.timeout_seconds = configured_timeout

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
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
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

    async def _generate(
        self,
        model: str,
        prompt: str,
        *,
        schema: dict[str, Any],
    ) -> str:
        """Retry transport failures once with the explicit local fallback model."""
        try:
            return await self.transport.generate(model, prompt, schema=schema)
        except (RuntimeError, TimeoutError, asyncio.TimeoutError) as primary_error:
            if model == self.roles.fallback:
                raise
            try:
                return await self.transport.generate(self.roles.fallback, prompt, schema=schema)
            except (RuntimeError, TimeoutError, asyncio.TimeoutError) as fallback_error:
                raise RuntimeError(
                    f"Ollama primary model {model!r} and fallback "
                    f"{self.roles.fallback!r} both failed"
                ) from fallback_error

    async def plan(self, objective: str, *, allowed_tools: set[str]) -> ToolPlan:
        if not objective.strip() or not allowed_tools:
            raise PlanError("objective and at least one allowed tool are required")
        prompt = (
            "You are a pentest routing component, not an autonomous attacker. "
            "Select exactly one tool from this allowlist: "
            f"{sorted(allowed_tools)}. Return strict JSON only. Objective: {objective}"
        )
        raw = await self._generate(self.roles.router, prompt, schema=_PLAN_SCHEMA)
        data = _strict_object(raw, {"tool", "arguments", "rationale"}, {"tool", "arguments", "rationale"})
        if data["tool"] not in allowed_tools:
            raise PlanError("model selected a tool outside the explicit allowlist")
        if not isinstance(data["arguments"], dict) or not isinstance(data["rationale"], str):
            raise PlanError("model plan contains invalid field types")
        return ToolPlan(data["tool"], data["arguments"], data["rationale"])

    async def review(self, tool_result: dict[str, Any]) -> dict[str, Any]:
        safe_result = json.dumps(tool_result, sort_keys=True, default=str)[:50_000]
        analysis_raw = await self._generate(
            self.roles.analyzer,
            "Analyze this authorized pentest result. Do not invent evidence. Return strict JSON: " + safe_result,
            schema=_ANALYSIS_SCHEMA,
        )
        analysis = _strict_object(
            analysis_raw,
            {"summary", "severity", "findings"},
            {"summary", "severity", "findings"},
        )
        validation_raw = await self._generate(
            self.roles.validator,
            "Validate that this analysis is supported by the supplied result. Return strict JSON only. "
            + json.dumps({"result": tool_result, "analysis": analysis}, default=str)[:60_000],
            schema=_VALIDATION_SCHEMA,
        )
        validation = _strict_object(validation_raw, {"valid", "issues"}, {"valid", "issues"})
        if not isinstance(validation["valid"], bool) or not isinstance(validation["issues"], list):
            raise PlanError("validator output contains invalid field types")
        return {"analysis": analysis, "validation": validation}
