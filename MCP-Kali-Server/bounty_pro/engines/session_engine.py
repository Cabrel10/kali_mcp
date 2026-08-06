"""
Burp Session Handling & Macros Engine
======================================
Advanced session management capabilities equivalent to Burp Pro:
- Macros (automated multi-step sequences)
- Session handling rules (auto re-authenticate, CSRF token refresh)
- Cookie jar management
- Scope-aware session validation
- Auto-detect and handle session invalidation
"""

import asyncio
import re
import time
import json
import uuid
from typing import Dict, Any, Optional, List, Tuple, Callable
from dataclasses import dataclass, field
from collections import OrderedDict


@dataclass
class MacroStep:
    """A single step in a macro sequence"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    url: str = ""
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    extract_params: List[Dict] = field(default_factory=list)  # {name, regex, from: "body"|"header"|"cookie"}
    validate: Dict = field(default_factory=dict)  # {status_code, body_contains, body_not_contains}


@dataclass 
class Macro:
    """A complete macro (sequence of requests)"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    steps: List[MacroStep] = field(default_factory=list)
    description: str = ""
    extracted_values: Dict[str, str] = field(default_factory=dict)


@dataclass
class SessionRule:
    """A session handling rule"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    enabled: bool = True
    scope: List[str] = field(default_factory=list)  # URL patterns
    tools: List[str] = field(default_factory=list)  # intruder, scanner, repeater, etc.
    actions: List[Dict] = field(default_factory=list)  # Actions to take
    conditions: List[Dict] = field(default_factory=list)  # When to trigger


class SessionHandlingEngine:
    """
    Manages session state during automated testing.
    Equivalent to Burp's Session Handling Rules.
    
    Features:
    - Auto-refresh expired sessions
    - Extract and inject CSRF tokens automatically
    - Cookie jar across all tools
    - Detect session invalidation
    - Multi-step authentication macros
    """
    
    def __init__(self):
        self.cookie_jar: Dict[str, Dict[str, str]] = {}  # domain -> {name: value}
        self.macros: Dict[str, Macro] = {}
        self.rules: List[SessionRule] = []
        self.session_tokens: Dict[str, str] = {}  # token_name -> current_value
        self.csrf_tokens: Dict[str, str] = {}  # url_pattern -> csrf_token
        self.last_valid_session: float = 0
        self.session_check_interval: int = 60  # seconds
        self.send_fn: Optional[Callable] = None
    
    def create_macro(self, name: str, steps: List[Dict]) -> Macro:
        """Create a new macro from step definitions"""
        macro = Macro(name=name)
        
        for step_def in steps:
            step = MacroStep(
                url=step_def.get("url", ""),
                method=step_def.get("method", "GET"),
                headers=step_def.get("headers", {}),
                body=step_def.get("body", ""),
                extract_params=step_def.get("extract", []),
                validate=step_def.get("validate", {})
            )
            macro.steps.append(step)
        
        self.macros[macro.id] = macro
        return macro
    
    def create_csrf_macro(self, login_url: str, form_url: str, 
                         token_name: str = "csrf_token",
                         token_regex: str = None) -> Macro:
        """Create a macro specifically for CSRF token extraction"""
        if not token_regex:
            token_regex = f'name=["\']?{token_name}["\']?[^>]*value=["\']([^"\']+)["\']'
        
        macro = Macro(
            name=f"CSRF Token Extraction ({token_name})",
            steps=[
                MacroStep(
                    url=form_url,
                    method="GET",
                    extract_params=[{
                        "name": token_name,
                        "regex": token_regex,
                        "from": "body"
                    }]
                )
            ]
        )
        
        self.macros[macro.id] = macro
        return macro
    
    def create_auth_macro(self, login_url: str, username: str, 
                         password: str, csrf_url: str = None,
                         csrf_field: str = "csrf_token") -> Macro:
        """Create a complete authentication macro with CSRF handling"""
        steps = []
        
        # Step 1: Get login page (and CSRF token if needed)
        if csrf_url:
            steps.append(MacroStep(
                url=csrf_url or login_url,
                method="GET",
                extract_params=[{
                    "name": csrf_field,
                    "regex": f'name=["\']?{csrf_field}["\']?[^>]*value=["\']([^"\']+)["\']',
                    "from": "body"
                }]
            ))
        
        # Step 2: Submit login
        body_parts = [f"username={username}", f"password={password}"]
        if csrf_url:
            body_parts.append(f"{csrf_field}={{{{{csrf_field}}}}}")  # Will be replaced
        
        steps.append(MacroStep(
            url=login_url,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="&".join(body_parts),
            extract_params=[{
                "name": "session_cookie",
                "regex": r"Set-Cookie:\s*(\S+)",
                "from": "header"
            }],
            validate={
                "status_code": [200, 302],
                "body_not_contains": ["Invalid", "incorrect", "failed"]
            }
        ))
        
        macro = Macro(
            name=f"Authentication ({username})",
            steps=steps
        )
        
        self.macros[macro.id] = macro
        return macro
    
    async def execute_macro(self, macro_id: str, send_fn: Callable = None) -> Dict:
        """Execute a macro and return extracted values"""
        macro = self.macros.get(macro_id)
        if not macro:
            return {"error": f"Macro {macro_id} not found"}
        
        fn = send_fn or self.send_fn
        if not fn:
            return {"error": "No send function provided"}
        
        extracted = {}
        results = []
        
        for step in macro.steps:
            # Replace extracted values in the request
            url = self._replace_tokens(step.url, extracted)
            body = self._replace_tokens(step.body, extracted)
            headers = {k: self._replace_tokens(v, extracted) 
                      for k, v in step.headers.items()}
            
            # Execute request
            from bounty_pro.engines.burp_engine import HTTPRequest, HTTPResponse
            request = HTTPRequest(
                method=step.method,
                url=url,
                headers=headers,
                body=body
            )
            
            response = await fn(request)
            
            step_result = {
                "url": url,
                "method": step.method,
                "status": response.status_code if response else 0,
                "extracted": {}
            }
            
            # Extract parameters from response
            if response:
                for param in step.extract_params:
                    value = self._extract_value(response, param)
                    if value:
                        extracted[param["name"]] = value
                        step_result["extracted"][param["name"]] = value
                
                # Validate response
                if step.validate:
                    valid = self._validate_response(response, step.validate)
                    step_result["valid"] = valid
                
                # Update cookie jar
                self._update_cookies(url, response)
            
            results.append(step_result)
        
        macro.extracted_values = extracted
        
        return {
            "macro": macro.name,
            "steps_executed": len(results),
            "extracted_values": extracted,
            "results": results,
            "success": all(r.get("valid", True) for r in results)
        }
    
    def add_session_rule(self, name: str, scope: List[str], 
                        actions: List[Dict], conditions: List[Dict] = None,
                        tools: List[str] = None) -> SessionRule:
        """
        Add a session handling rule.
        
        Conditions: [{type: "status_code", value: 401}, {type: "body_contains", value: "session expired"}]
        Actions: [{type: "run_macro", macro_id: "..."}, {type: "update_cookie", name: "...", value: "..."}]
        """
        rule = SessionRule(
            name=name,
            scope=scope,
            tools=tools or ["scanner", "intruder", "repeater"],
            actions=actions,
            conditions=conditions or []
        )
        self.rules.append(rule)
        return rule
    
    async def process_response(self, url: str, response: Any, 
                              tool: str = "scanner") -> Dict:
        """
        Process a response through session handling rules.
        Returns any remediation actions taken.
        """
        actions_taken = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Check scope
            if not any(re.search(pattern, url) for pattern in rule.scope):
                continue
            
            # Check tool
            if tool not in rule.tools:
                continue
            
            # Check conditions
            if self._conditions_met(response, rule.conditions):
                # Execute actions
                for action in rule.actions:
                    result = await self._execute_action(action)
                    actions_taken.append({
                        "rule": rule.name,
                        "action": action["type"],
                        "result": result
                    })
        
        return {"actions_taken": actions_taken}
    
    def get_cookie(self, domain: str, name: str) -> Optional[str]:
        """Get a cookie value from the jar"""
        domain_cookies = self.cookie_jar.get(domain, {})
        return domain_cookies.get(name)
    
    def set_cookie(self, domain: str, name: str, value: str) -> None:
        """Set a cookie in the jar"""
        if domain not in self.cookie_jar:
            self.cookie_jar[domain] = {}
        self.cookie_jar[domain][name] = value
    
    def get_all_cookies(self, domain: str = None) -> Dict:
        """Get all cookies, optionally filtered by domain"""
        if domain:
            return self.cookie_jar.get(domain, {})
        return dict(self.cookie_jar)
    
    def inject_cookies(self, request: Any, domain: str) -> Any:
        """Inject stored cookies into a request"""
        cookies = self.cookie_jar.get(domain, {})
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            request.headers["Cookie"] = cookie_str
        return request
    
    def _replace_tokens(self, text: str, tokens: Dict[str, str]) -> str:
        """Replace {{token_name}} placeholders with extracted values"""
        for name, value in tokens.items():
            text = text.replace(f"{{{{{name}}}}}", value)
        return text
    
    def _extract_value(self, response: Any, param: Dict) -> Optional[str]:
        """Extract a value from response based on param definition"""
        source = param.get("from", "body")
        regex = param.get("regex", "")
        
        if source == "body":
            text = response.body if hasattr(response, 'body') else str(response)
        elif source == "header":
            text = "\n".join(f"{k}: {v}" for k, v in 
                           (response.headers.items() if hasattr(response, 'headers') else {}))
        elif source == "cookie":
            text = response.headers.get("Set-Cookie", "") if hasattr(response, 'headers') else ""
        else:
            text = str(response)
        
        match = re.search(regex, text)
        if match:
            return match.group(1) if match.groups() else match.group(0)
        return None
    
    def _validate_response(self, response: Any, validate: Dict) -> bool:
        """Validate a response against expected conditions"""
        if "status_code" in validate:
            expected = validate["status_code"]
            if isinstance(expected, list):
                if response.status_code not in expected:
                    return False
            elif response.status_code != expected:
                return False
        
        if "body_contains" in validate:
            if validate["body_contains"] not in response.body:
                return False
        
        if "body_not_contains" in validate:
            for pattern in validate["body_not_contains"]:
                if pattern.lower() in response.body.lower():
                    return False
        
        return True
    
    def _update_cookies(self, url: str, response: Any) -> None:
        """Update cookie jar from response"""
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        
        set_cookie = response.headers.get("Set-Cookie", "") if hasattr(response, 'headers') else ""
        if set_cookie:
            # Parse Set-Cookie header
            parts = set_cookie.split(";")
            if "=" in parts[0]:
                name, value = parts[0].split("=", 1)
                self.set_cookie(domain, name.strip(), value.strip())
    
    def _conditions_met(self, response: Any, conditions: List[Dict]) -> bool:
        """Check if rule conditions are met"""
        if not conditions:
            return True
        
        for condition in conditions:
            ctype = condition.get("type", "")
            value = condition.get("value", "")
            
            if ctype == "status_code":
                if hasattr(response, 'status_code') and response.status_code != int(value):
                    return False
            elif ctype == "body_contains":
                if hasattr(response, 'body') and value not in response.body:
                    return False
            elif ctype == "header_contains":
                if hasattr(response, 'headers'):
                    header_text = str(response.headers)
                    if value not in header_text:
                        return False
        
        return True
    
    async def _execute_action(self, action: Dict) -> Dict:
        """Execute a session handling action"""
        action_type = action.get("type", "")
        
        if action_type == "run_macro":
            macro_id = action.get("macro_id", "")
            result = await self.execute_macro(macro_id, self.send_fn)
            return result
        
        elif action_type == "update_cookie":
            domain = action.get("domain", "")
            name = action.get("name", "")
            value = action.get("value", "")
            self.set_cookie(domain, name, value)
            return {"updated": f"{name}={value}"}
        
        elif action_type == "set_header":
            return {"header_set": action.get("name", ""), "value": action.get("value", "")}
        
        return {"unknown_action": action_type}
    
    def export_config(self) -> Dict:
        """Export session handling configuration"""
        return {
            "macros": [
                {
                    "id": m.id,
                    "name": m.name,
                    "steps": len(m.steps),
                    "extracted_values": m.extracted_values
                } for m in self.macros.values()
            ],
            "rules": [
                {
                    "id": r.id,
                    "name": r.name,
                    "enabled": r.enabled,
                    "scope": r.scope,
                    "tools": r.tools,
                    "actions_count": len(r.actions)
                } for r in self.rules
            ],
            "cookie_jar_domains": list(self.cookie_jar.keys()),
            "session_tokens": list(self.session_tokens.keys()),
            "csrf_tokens": list(self.csrf_tokens.keys())
        }
