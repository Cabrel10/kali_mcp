"""Deterministic MCP clients used by the gateway."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping, Protocol


class MCPToolClient(Protocol):
    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any: ...


class InMemoryMCPClient:
    """Small deterministic adapter for unit tests and local health probes."""

    def __init__(self, tools: Mapping[str, Callable[..., Awaitable[Any]]]) -> None:
        self._tools = dict(tools)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        if name not in self._tools:
            raise KeyError(f"MCP tool is not registered: {name}")
        return await self._tools[name](**arguments)


class FastMCPClientAdapter:
    """Launch a local FastMCP server over stdio for each bounded call."""

    def __init__(self, server_source: str | Path) -> None:
        self.server_source = str(Path(server_source).resolve())

    @staticmethod
    def _normalize(result: Any) -> Any:
        data = getattr(result, "data", None)
        if data is not None:
            return data
        structured = getattr(result, "structured_content", None)
        if structured is not None:
            return structured
        content = getattr(result, "content", None)
        if content:
            texts = [getattr(item, "text", None) for item in content]
            texts = [item for item in texts if item is not None]
            if len(texts) == 1:
                try:
                    return json.loads(texts[0])
                except (json.JSONDecodeError, TypeError):
                    return texts[0]
            return texts
        return result

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        try:
            from fastmcp import Client
        except ImportError as exc:
            raise RuntimeError("fastmcp is required to invoke the MCP server") from exc
        async with Client(self.server_source, mode="legacy") as client:
            result = await client.call_tool(name, arguments)
        return self._normalize(result)
