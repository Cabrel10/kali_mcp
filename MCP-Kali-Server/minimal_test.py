#!/usr/bin/env python3
import asyncio
from mcp.server import Server
import mcp.server.stdio
import mcp.types as types

# Create server instance
server = Server("minimal-test")

@server.list_tools()
async def list_tools():
    print("DEBUG: list_tools called")
    tools = [
        {"name": "test_tool", "description": "A test tool", "inputSchema": {"type": "object"}}
    ]
    print(f"DEBUG: Returning {len(tools)} tools")
    return tools

@server.call_tool()
async def call_tool(name, args):
    print(f"DEBUG: call_tool called with name={name}")
    return [types.TextContent(type="text", text=f"Called {name} with args {args}")]

async def run_server():
    print("DEBUG: Starting server")
    async with mcp.server.stdio.stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(run_server())