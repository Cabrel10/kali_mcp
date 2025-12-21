import asyncio
import json
from mcp.server import Server, TextContent
import mcp.server.stdio
from src.core.async_executor import AsyncExecutor
from src.core.task_manager import TaskManager
from src.core.database import DatabaseManager
from src.modules.network_recon import NetworkRecon
from src.modules.vulnerability_scanner import VulnerabilityScanner
from src.tools.distributed_engine import DistributedEngine
from src.core.triage import TriageEngine

class MCPOptimizedServer:
    def __init__(self):
        self.server = Server("kali-tactical-elite")
        self.executor = AsyncExecutor()
        self.db = DatabaseManager()
        self.tasks = TaskManager()
        
        # Modules
        self.recon = NetworkRecon(self.executor, self.db)
        self.vuln = VulnerabilityScanner(self.executor, self.db)
        self.swarm = DistributedEngine(self.executor)
        
        self.setup_tools()

    def setup_tools(self):
        @self.server.list_tools()
        async def list_tools():
            return [
                {"name": "tactical_recon", "description": "Reconnaissance complète et plan d'attaque"},
                {"name": "distributed_assault", "description": "Attaque via pool d'IP (Swarm mode)"},
                {"name": "check_task", "description": "Vérifier le statut d'un scan long"}
            ]

        @self.server.call_tool()
        async def call_tool(name, args):
            target = args.get("target")
            
            if name == "tactical_recon":
                # 1. Recon rapide
                data = await self.recon.quick_scan(target)
                # 2. Triage intelligent
                plan = TriageEngine.generate_plan(data)
                return [TextContent(type="text", text=json.dumps({"recon": data, "next_steps": plan}, indent=2))]

            if name == "distributed_assault":
                task_id = self.tasks.create_task(target, "swarm")
                asyncio.create_task(self.swarm.launch_swarm(target, "recon"))
                return [TextContent(type="text", text=f"Attaque distribuée lancée. ID: {task_id}")]

    async def run(self):
        async with mcp.server.stdio.stdio_server() as (read, write):
            await self.server.run(read, write, self.server.create_initialization_options())

if __name__ == "__main__":
    server = MCPOptimizedServer()
    asyncio.run(server.run())
