import asyncio
import json
from mcp.server import Server
import mcp.server.stdio
import mcp.types as types
from src.core.async_executor import AsyncExecutor
from src.core.task_manager import TaskManager
from src.core.database import DatabaseManager
from src.modules.network_recon import NetworkRecon
from src.modules.vulnerability_scanner import VulnerabilityScanner
from src.tools.distributed_engine import DistributedEngine
from src.core.triage import TriageEngine
from src.tools.document_analyzer import DocumentAnalyzer
from src.tools.database_expert import DatabaseExpert
from src.tools.reverse_engineer import ReverseEngineer
from src.tools.osint_hunter import OSINTHunter
from src.tools.wireless_expert import WirelessExpert
from src.tools.post_exploit import PostExploit
from src.tools.evasion_engine import EvasionEngine

class MCPOptimizedServer:
    def __init__(self):
        self.server = Server("kali-tactical-elite")
        self.executor = AsyncExecutor()
        self.db = DatabaseManager()
        self.tasks = TaskManager()
        
        # Modules
        self.recon = NetworkRecon()
        self.vuln = VulnerabilityScanner()
        self.swarm = DistributedEngine(self.executor)
        
        # Advanced Tools
        self.doc_analyzer = DocumentAnalyzer()
        self.db_expert = DatabaseExpert()
        self.reverse_engineer = ReverseEngineer(self.executor)
        self.osint_hunter = OSINTHunter(self.executor)
        self.wireless_expert = WirelessExpert(self.executor)
        self.post_exploit = PostExploit(self.executor)
        self.evasion = EvasionEngine(self.executor, self.swarm)
        
        self.setup_tools()

    def setup_tools(self):
        @self.server.list_tools()
        async def list_tools():
            return [
                {"name": "tactical_recon", "description": "Reconnaissance complète et plan d'attaque", "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}},
                {"name": "distributed_assault", "description": "Attaque via pool d'IP (Swarm mode)", "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}},
                {"name": "check_task", "description": "Vérifier le statut d'un scan long", "inputSchema": {"type": "object", "properties": {"task_id": {"type": "string"}}, "required": ["task_id"]}},
                {"name": "analyze_document", "description": "Analyser un document pour métadonnées et menaces", "inputSchema": {"type": "object", "properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}},
                {"name": "crack_hashes", "description": "Cracker des hashes de mot de passe", "inputSchema": {"type": "object", "properties": {"hashes": {"type": "array", "items": {"type": "string"}}}, "required": ["hashes"]}},
                {"name": "reverse_engineer_binary", "description": "Analyser un fichier binaire", "inputSchema": {"type": "object", "properties": {"file_path": {"type": "string"}}, "required": ["file_path"]}},
                {"name": "check_site_legitimacy", "description": "Vérifier la légitimité d'un site web", "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
                {"name": "scan_wifi_networks", "description": "Scanner les réseaux WiFi à proximité", "inputSchema": {"type": "object", "properties": {"interface": {"type": "string"}}, "required": ["interface"]}},
                {"name": "lateral_movement", "description": "Mouvement latéral SMB via NetExec", "inputSchema": {"type": "object", "properties": {"target_range": {"type": "string"}, "user": {"type": "string"}, "password": {"type": "string"}}, "required": ["target_range", "user", "password"]}},
                {"name": "ghost_mode_toggle", "description": "Activer/Désactiver l'évasion Ghost Mode", "inputSchema": {"type": "object", "properties": {"enable": {"type": "boolean"}}, "required": ["enable"]}},
                {"name": "deploy_persistence", "description": "Déployer un implant Sliver C2", "inputSchema": {"type": "object", "properties": {"target_ip": {"type": "string"}, "user": {"type": "string"}, "password": {"type": "string"}, "lhost": {"type": "string"}}, "required": ["target_ip", "user", "password", "lhost"]}}
            ]

        @self.server.call_tool()
        async def call_tool(name, args):
            target = args.get("target")
            
            if name == "tactical_recon":
                data = await self.recon.quick_recon(target)
                plan = TriageEngine.generate_plan(data)
                return [types.TextContent(type="text", text=json.dumps({"recon": data, "next_steps": plan}, indent=2))]

            if name == "distributed_assault":
                task_id = self.tasks.create_task(target, "swarm")
                asyncio.create_task(self.swarm.launch_swarm(target, "recon"))
                return [types.TextContent(type="text", text=f"Attaque distribuée lancée. ID: {task_id}")]

            if name == "check_task":
                task_id = args.get("task_id")
                status = self.tasks.get_task_status(task_id)
                return [types.TextContent(type="text", text=json.dumps(status, indent=2))]

            if name == "analyze_document":
                file_path = args.get("file_path")
                data = await self.doc_analyzer.analyze_document(file_path)
                return [types.TextContent(type="text", text=json.dumps(data, indent=2))]

            if name == "crack_hashes":
                hashes = args.get("hashes")
                data = await self.db_expert.crack_hashes(hashes)
                return [types.TextContent(type="text", text=json.dumps(data, indent=2))]

            if name == "reverse_engineer_binary":
                file_path = args.get("file_path")
                data = await self.reverse_engineer.analyze_binary(file_path)
                return [types.TextContent(type="text", text=json.dumps(data, indent=2))]

            if name == "check_site_legitimacy":
                domain = args.get("domain")
                data = await self.osint_hunter.check_legitimacy(domain)
                return [types.TextContent(type="text", text=json.dumps(data, indent=2))]
                
            if name == "scan_wifi_networks":
                interface = args.get("interface")
                data = await self.wireless_expert.scan_wifi_networks(interface)
                return [types.TextContent(type="text", text=json.dumps(data, indent=2))]

            if name == "lateral_movement":
                return [types.TextContent(type="text", text=json.dumps(
                    await self.post_exploit.smb_lateral_movement(args['target_range'], args['user'], args['password'])
                ))]
            
            if name == "ghost_mode_toggle":
                enable = args.get("enable", False)
                result = await self.evasion.toggle_ghost_mode(enable)
                return [types.TextContent(type="text", text=result)]

            if name == "deploy_persistence":
                return [types.TextContent(type="text", text=json.dumps(
                    await self.post_exploit.deploy_persistence(args['target_ip'], args['user'], args['password'], args['lhost'])
                ))]

    async def run(self):
        async with mcp.server.stdio.stdio_server() as (read, write):
            await self.server.run(read, write, self.server.create_initialization_options())

if __name__ == "__main__":
    server = MCPOptimizedServer()
    asyncio.run(server.run())
