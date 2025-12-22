#!/usr/bin/env python3
import asyncio
import json
from mcp.server import Server
import mcp.server.stdio
import mcp.types as types

class DebugServer:
    def __init__(self):
        self.server = Server("debug-server")
        self.setup_tools()

    def setup_tools(self):
        @self.server.list_tools()
        async def list_tools():
            print("DEBUG: list_tools called")
            tools = [
                {"name": "test_tool", "description": "A test tool", "inputSchema": {"type": "object"}}
            ]
            print(f"DEBUG: returning {len(tools)} tools")
            return tools

        @self.server.call_tool()
        async def call_tool(name, args):
            print(f"DEBUG: call_tool called with name={name}")
            return [types.TextContent(type="text", text=f"Called {name} with args {args}")]

    async def run(self):
        print("DEBUG: Starting server")
        async with mcp.server.stdio.stdio_server() as (read, write):
            await self.server.run(read, write, self.server.create_initialization_options())

if __name__ == "__main__":
    server = DebugServer()
    asyncio.run(server.run())