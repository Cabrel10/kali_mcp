#!/usr/bin/env python3
"""
Kali MCP Tactical Server - Main Server
Professional penetration testing server with MCP protocol
"""

import asyncio
import json
import logging
from typing import Dict, List, Any

# MCP imports
import mcp.types as types
from mcp.server import Server
from mcp.server.models import InitializationOptions
import mcp.server.stdio

# Core components
from .core.config import TacticalConfig
from .core.task_manager import TaskManager, get_task_manager
from .core.database import DatabaseManager, get_database
from .core.output_processor import OutputProcessor

# Modules
from .modules.network_recon import NetworkRecon
from .modules.vulnerability_scanner import VulnerabilityScanner
from .modules.web_assault import WebAssault

# Tools
from .tools.document_analyzer import DocumentAnalyzer
from .tools.database_expert import DatabaseExpert
from .tools.evasion_engine import EvasionEngine
from .tools.distributed_attack import DistributedAttack
from .tools.osint_hunter import OSINTHunter
from .tools.reverse_engineer import ReverseEngineer

# Utils
from .utils.triage_engine import TriageEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class KaliTacticalServer:
    """Main Kali MCP Tactical Server"""
    
    def __init__(self):
        """Initialize server"""
        self.server = Server("kali-tactical-server")
        self.config = TacticalConfig
        
        # Validate configuration
        if not self.config.validate():
            logger.warning("Configuration validation failed - some features may not work")
        
        # Initialize components
        self.task_manager = get_task_manager()
        self.db = get_database()
        self.processor = OutputProcessor()
        
        # Initialize modules
        self.network_recon = NetworkRecon()
        self.vuln_scanner = VulnerabilityScanner()
        self.web_assault = WebAssault()
        
        # Initialize tools
        self.doc_analyzer = DocumentAnalyzer()
        self.db_expert = DatabaseExpert()
        self.evasion = EvasionEngine()
        self.distributed = DistributedAttack()
        self.osint = OSINTHunter()
        self.reverse_eng = ReverseEngineer()
        
        # Initialize triage engine
        self.triage = TriageEngine()
        
        # Register tools
        self._register_tools()
        
        logger.info("🚀 Kali Tactical Server initialized")
    
    def _register_tools(self):
        """Register all MCP tools"""
        
        @self.server.list_tools()
        async def list_tools() -> List[types.Tool]:
            """List all available tools"""
            return [
                # ===== RECONNAISSANCE =====
                types.Tool(
                    name="tactical_recon",
                    description="🎯 Complete tactical reconnaissance: port scan + service detection + web probing",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Target IP/domain"},
                            "intensity": {"type": "string", "description": "fast/deep", "default": "fast"}
                        },
                        "required": ["target"]
                    }
                ),
                
                types.Tool(
                    name="port_scan",
                    description="📊 Advanced port scanning with naabu/nmap",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string"},
                            "strategy": {"type": "string", "description": "stealth/fast/comprehensive/mikrotik", "default": "fast"}
                        },
                        "required": ["target"]
                    }
                ),
                
                # ===== VULNERABILITY SCANNING =====
                types.Tool(
                    name="nuclei_scan",
                    description="💣 Vulnerability scanning with Nuclei templates",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string"},
                            "intensity": {"type": "string", "description": "fast/deep/full", "default": "fast"}
                        },
                        "required": ["target"]
                    }
                ),
                
                types.Tool(
                    name="sql_injection_test",
                    description="🗃️ SQL injection detection with SQLMap",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"}
                        },
                        "required": ["url"]
                    }
                ),
                
                # ===== WEB ATTACKS =====
                types.Tool(
                    name="web_fuzzing",
                    description="📁 Directory/file fuzzing with ffuf/gobuster",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "mode": {"type": "string", "description": "quick/comprehensive/api", "default": "comprehensive"}
                        },
                        "required": ["url"]
                    }
                ),
                
                types.Tool(
                    name="xss_scan",
                    description="⚡ XSS vulnerability scanning",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"}
                        },
                        "required": ["url"]
                    }
                ),
                
                types.Tool(
                    name="subdomain_takeover",
                    description="🔓 Subdomain takeover detection",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {"type": "string"}
                        },
                        "required": ["domain"]
                    }
                ),
                
                # ===== ADVANCED TOOLS =====
                types.Tool(
                    name="analyze_document",
                    description="📄 Document forensics and metadata analysis",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string"}
                        },
                        "required": ["file_path"]
                    }
                ),
                
                types.Tool(
                    name="crack_hashes",
                    description="🔑 Password hash cracking with hashcat",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "hashes": {"type": "array", "items": {"type": "string"}},
                            "hash_type": {"type": "string", "description": "md5/sha1/sha256/auto", "default": "auto"}
                        },
                        "required": ["hashes"]
                    }
                ),
                
                types.Tool(
                    name="scam_detection",
                    description="🕵️ Analyze site legitimacy and detect scams",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "domain": {"type": "string"}
                        },
                        "required": ["domain"]
                    }
                ),
                
                # ===== EVASION & STEALTH =====
                types.Tool(
                    name="stealth_scan",
                    description="👻 Ultra-stealth scan for MikroTik/sensitive targets",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string"}
                        },
                        "required": ["target"]
                    }
                ),
                
                types.Tool(
                    name="rotate_ip",
                    description="🔄 Rotate attack IP (Tor/VPN)",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                
                # ===== DISTRIBUTED ATTACKS =====
                types.Tool(
                    name="distributed_scan",
                    description="🌊 Distributed port scan using IP pool",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {"type": "string"},
                            "ports": {"type": "array", "items": {"type": "integer"}}
                        },
                        "required": ["target", "ports"]
                    }
                ),
                
                # ===== TASK MANAGEMENT =====
                types.Tool(
                    name="check_task",
                    description="⏳ Check status of background task",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "task_id": {"type": "string"}
                        },
                        "required": ["task_id"]
                    }
                ),
                
                types.Tool(
                    name="list_tasks",
                    description="📋 List all tasks",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                
                # ===== INTELLIGENCE =====
                types.Tool(
                    name="tactical_triage",
                    description="🧠 Analyze results and generate action plan",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "scan_data": {"type": "string", "description": "JSON scan results"}
                        },
                        "required": ["scan_data"]
                    }
                ),
                
                types.Tool(
                    name="get_stats",
                    description="📊 Get server statistics",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                )
            ]
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: Any) -> List[types.TextContent]:
            """Handle tool calls"""
            try:
                logger.info(f"Tool called: {name} with args: {arguments}")
                
                # Route to appropriate handler
                handler = self._get_tool_handler(name)
                
                if not handler:
                    return [types.TextContent(
                        type="text",
                        text=f"❌ Unknown tool: {name}"
                    )]
                
                # Execute handler
                result = await handler(arguments)
                
                # Format result
                if isinstance(result, dict):
                    text = json.dumps(result, indent=2, ensure_ascii=False)
                elif isinstance(result, str):
                    text = result
                else:
                    text = str(result)
                
                return [types.TextContent(type="text", text=text)]
            
            except Exception as e:
                logger.error(f"Error in tool {name}: {str(e)}", exc_info=True)
                return [types.TextContent(
                    type="text",
                    text=f"❌ Error: {str(e)}"
                )]
    
    def _get_tool_handler(self, tool_name: str):
        """Get handler function for tool"""
        handlers = {
            # Reconnaissance
            "tactical_recon": self._handle_tactical_recon,
            "port_scan": self._handle_port_scan,
            
            # Vulnerabilities
            "nuclei_scan": self._handle_nuclei_scan,
            "sql_injection_test": self._handle_sql_injection,
            
            # Web attacks
            "web_fuzzing": self._handle_web_fuzzing,
            "xss_scan": self._handle_xss_scan,
            "subdomain_takeover": self._handle_subdomain_takeover,
            
            # Advanced tools
            "analyze_document": self._handle_analyze_document,
            "crack_hashes": self._handle_crack_hashes,
            "scam_detection": self._handle_scam_detection,
            
            # Evasion
            "stealth_scan": self._handle_stealth_scan,
            "rotate_ip": self._handle_rotate_ip,
            
            # Distributed
            "distributed_scan": self._handle_distributed_scan,
            
            # Task management
            "check_task": self._handle_check_task,
            "list_tasks": self._handle_list_tasks,
            
            # Intelligence
            "tactical_triage": self._handle_tactical_triage,
            "get_stats": self._handle_get_stats
        }
        
        return handlers.get(tool_name)
    
    # ===== TOOL HANDLERS =====
    
    async def _handle_tactical_recon(self, args: Dict) -> Dict:
        """Handle complete tactical reconnaissance"""
        target = args['target']
        intensity = args.get('intensity', 'fast')
        
        result = await self.network_recon.quick_recon(target, intensity)
        
        # Store in database
        self.db.add_target(target, target_type='reconnaissance')
        
        return result
    
    async def _handle_port_scan(self, args: Dict) -> Dict:
        """Handle port scanning"""
        target = args['target']
        strategy = args.get('strategy', 'fast')
        
        return await self.network_recon.tactical_port_scan(target, strategy)
    
    async def _handle_nuclei_scan(self, args: Dict) -> Dict:
        """Handle Nuclei vulnerability scan"""
        target = args['target']
        intensity = args.get('intensity', 'fast')
        
        return await self.vuln_scanner.smart_nuclei_scan(target, intensity)
    
    async def _handle_sql_injection(self, args: Dict) -> Dict:
        """Handle SQL injection testing"""
        url = args['url']
        
        return await self.vuln_scanner.sql_injection_check(url)
    
    async def _handle_web_fuzzing(self, args: Dict) -> Dict:
        """Handle web directory fuzzing"""
        url = args['url']
        mode = args.get('mode', 'comprehensive')
        
        return await self.web_assault.advanced_fuzzing(url, mode)
    
    async def _handle_xss_scan(self, args: Dict) -> Dict:
        """Handle XSS scanning"""
        url = args['url']
        
        return await self.web_assault.xss_scan(url)
    
    async def _handle_subdomain_takeover(self, args: Dict) -> Dict:
        """Handle subdomain takeover detection"""
        domain = args['domain']
        
        return await self.web_assault.subdomain_takeover_check(domain)
    
    async def _handle_analyze_document(self, args: Dict) -> Dict:
        """Handle document analysis"""
        file_path = args['file_path']
        
        return await self.doc_analyzer.analyze_document(file_path)
    
    async def _handle_crack_hashes(self, args: Dict) -> Dict:
        """Handle hash cracking"""
        hashes = args['hashes']
        hash_type = args.get('hash_type', 'auto')
        
        return await self.db_expert.crack_hashes(hashes, hash_type)
    
    async def _handle_scam_detection(self, args: Dict) -> Dict:
        """Handle scam detection"""
        domain = args['domain']
        
        return await self.osint.analyze_site_legitimacy(domain)
    
    async def _handle_stealth_scan(self, args: Dict) -> Dict:
        """Handle stealth scanning"""
        target = args['target']
        
        return await self.evasion.stealth_scan_mikrotik(target)
    
    async def _handle_rotate_ip(self, args: Dict) -> Dict:
        """Handle IP rotation"""
        return await self.evasion.rotate_ip()
    
    async def _handle_distributed_scan(self, args: Dict) -> Dict:
        """Handle distributed scanning"""
        target = args['target']
        ports = args['ports']
        
        return await self.distributed.distributed_port_scan(target, ports)
    
    async def _handle_check_task(self, args: Dict) -> Dict:
        """Handle task status check"""
        task_id = args['task_id']
        
        status = self.task_manager.get_task_status(task_id)
        return status or {'error': 'Task not found'}
    
    async def _handle_list_tasks(self, args: Dict) -> Dict:
        """Handle task listing"""
        tasks = self.task_manager.list_tasks()
        stats = self.task_manager.get_stats()
        
        return {
            'tasks': tasks[:20],  # Last 20 tasks
            'stats': stats
        }
    
    async def _handle_tactical_triage(self, args: Dict) -> str:
        """Handle tactical triage"""
        scan_data_str = args['scan_data']
        
        try:
            scan_data = json.loads(scan_data_str)
        except json.JSONDecodeError:
            return "❌ Invalid JSON scan data"
        
        plan = self.triage.analyze_and_decide(scan_data)
        return self.triage.format_action_plan(plan)
    
    async def _handle_get_stats(self, args: Dict) -> Dict:
        """Handle statistics request"""
        return {
            'config': self.config.to_dict(),
            'database': self.db.get_statistics(),
            'tasks': self.task_manager.get_stats(),
            'evasion': self.evasion.get_evasion_stats()
        }
    
    async def run(self):
        """Run the MCP server"""
        logger.info("Starting Kali Tactical Server...")
        
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="kali-tactical-server",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=types.NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )


async def main():
    """Main entry point"""
    server = KaliTacticalServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
