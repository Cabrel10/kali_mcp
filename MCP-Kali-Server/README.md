# Kali MCP Tactical Server v4

**Professional Penetration Testing & Bug Bounty Platform with MCP Protocol**

A comprehensive, forensic-grade penetration testing server with 59 tools, hierarchical session management, trace logging, tool chaining, and CVE cartography. Designed for AI-driven security operations via the Model Context Protocol (MCP).

---

## What's New in v4

- **Hierarchical Session Storage** — `sessions/{session_id}/{target}/{tool}/{execution_id}/` with full forensic traces
- **Trace Logging** — JSONL forensic logs for every operation step (timestamps, elapsed_ms, phase, data)
- **Real-time Progress** — Percentage-based progress reporting during tool execution
- **Tool Chaining Engine** — Cross-references results between tools, auto-enriches output with context from prior runs
- **CVE Cartography** — Maps discovered services to CVEs with severity ratings and patch recommendations
- **Input Validation & Security** — Sanitizes all inputs, blocks shell injection, validates ports/timeouts/paths
- **Enhanced Payloads** — Time-based blind SQLi, DOM XSS, polyglot XSS, SSRF, auth bypass, and more
- **Bug Bounty Platforms** — HackerOne, Bugcrowd, Intigriti, Immunefi scope checking
- **Crypto/DeFi Auditing** — Smart contract analysis, DeFi protocol scanning, blockchain TX tracing
- **Self-Audit** — Server can audit its own security posture

---

## Architecture

### v4 Infrastructure Classes

| Class | Purpose |
|-------|---------|
| `SessionManager` | Singleton. Creates hierarchical session dirs, generates execution IDs, manages session lifecycle |
| `TraceLogger` | Writes `trace.jsonl` per execution with forensic-level per-step logging |
| `ProgressReporter` | Percentage-based real-time progress with step descriptions |
| `ToolChainEngine` | Singleton. Cross-references tool results, auto-enriches outputs with prior context |
| `CVECartographer` | Maps services to CVEs using local curated DB (13+ service families) + NVD API |
| `InputValidator` | Sanitizes targets, blocks shell injection, validates ports/timeouts/paths |
| `PayloadGenerator` | 8 payload categories: SQLi, XSS, LFI, RCE, SSTI, XXE, SSRF, Auth Bypass |

### v4 Tool Pattern

Every tool follows this pattern for consistency and traceability:

```python
@mcp.tool()
@resolve_references
async def tool_name(target: str, ...) -> str:
    target = InputValidator.sanitize_target(target)
    trace, progress, exec_dir = _init_tool_context("tool_name", target, N_steps)
    inputs = {"target": target, ...}

    progress.update("Step description", "detail")
    result = run_command_advanced(cmd, timeout=timeout, trace=trace)

    # ... processing ...

    output = chain_engine.enrich_with_context("tool_name", target, output)
    log_tool_execution("tool_name", target, inputs, output, trace, progress)
    return json.dumps(output, indent=2)
```

### Directory Structure

```
MCP-Kali-Server/
├── kali_mcp_server.py          # Main server (7288 lines, 59 tools)
├── test_all_tools.py           # Full test suite (59 tool tests)
├── main.py                     # Entry point
├── requirements.txt            # Python dependencies
├── README.md                   # This file
│
├── sessions/                   # Hierarchical session storage (runtime)
│   └── {session_id}/
│       └── {target}/
│           └── {tool}/
│               └── {execution_id}/
│                   ├── trace.jsonl    # Forensic trace log
│                   ├── result.json    # Tool output
│                   └── progress.json  # Progress snapshots
│
├── cve_cache/                  # CVE data cache (runtime)
│   └── nvd_{service}.json
│
└── chain_data/                 # Tool chain cross-reference data (runtime)
    └── {target}/
        └── {tool}.json
```

---

## 46 Tools — Complete Reference

### Core (5)

| Tool | Description |
|------|-------------|
| `start_session` | Initialize a new pentest session with target scope and metadata |
| `server_health` | Health check — returns server status, tool count, uptime |
| `execute_command` | Execute arbitrary shell commands with trace logging |
| `get_chain_summary` | View cross-reference summary for a target across all tools |
| `session_summary` | Get full session report with all execution traces |

### Reconnaissance (4)

| Tool | Description |
|------|-------------|
| `nmap_scan` | Advanced Nmap scanning with service/version/script detection |
| `cve_cartography` | Map discovered services to CVEs with severity + patch recommendations |
| `vulnx_scan` | VulnX CMS vulnerability scanner integration |
| `web_tech_detect` | Web technology fingerprinting (CMS, frameworks, libraries, headers) |

### Web Scanning (5)

| Tool | Description |
|------|-------------|
| `gobuster_scan` | Directory/file brute-forcing with Gobuster |
| `nikto_scan` | Nikto web server vulnerability scanning |
| `ffuf_fuzz` | FFUF fuzzing (directories, parameters, vhosts) |
| `wpscan_audit` | WordPress security audit with WPScan |
| `nuclei_scan` | Nuclei vulnerability scanning with severity filtering |

### Injection Testing (8)

| Tool | Description |
|------|-------------|
| `sqlmap_scan` | Automated SQL injection with SQLMap |
| `sql_injection_test` | Manual SQL injection testing with curated payloads |
| `xss_scan` | XSS detection (reflected, stored, DOM-based, polyglot) |
| `lfi_scan` | Local File Inclusion testing (Linux + Windows paths) |
| `command_injection_test` | OS command injection testing (blind + bypass) |
| `ssti_scanner` | Server-Side Template Injection across multiple engines |
| `ssrf_scanner` | Server-Side Request Forgery detection |
| `idor_tester` | Insecure Direct Object Reference testing |

### Brute Force (2)

| Tool | Description |
|------|-------------|
| `hydra_attack` | Hydra password brute-forcing (SSH, FTP, HTTP, etc.) |
| `john_crack` | John the Ripper hash cracking |

### Exploitation (2)

| Tool | Description |
|------|-------------|
| `metasploit_exploit` | Metasploit Framework module execution |
| `reverse_shell_generator` | Generate reverse shell payloads (bash, python, nc, php, etc.) |

### DNS & Subdomain (3)

| Tool | Description |
|------|-------------|
| `subdomain_enum` | Subdomain enumeration with Subfinder |
| `subdomain_scanner` | Active subdomain scanning with HTTP probing |
| `dns_recon` | DNS reconnaissance (records, zone transfer, DNSSEC) |

### Network (2)

| Tool | Description |
|------|-------------|
| `arp_scan` | ARP-based network discovery on local segment |
| `enum4linux_scan` | SMB/NetBIOS enumeration with enum4linux |

### Security Scanners (4)

| Tool | Description |
|------|-------------|
| `cors_scanner` | CORS misconfiguration detection |
| `jwt_analyzer` | JWT token analysis (decode, weakness detection) |
| `header_security_audit` | HTTP security header audit (CSP, HSTS, X-Frame, etc.) |
| `waf_fingerprint` | WAF detection and fingerprinting |

### OSINT (2)

| Tool | Description |
|------|-------------|
| `origin_ip_hunter` | Find origin IP behind CDN/WAF (DNS history, SSL, etc.) |
| `osint_domain_intel` | Full OSINT domain intelligence gathering |

### API & HTTP (2)

| Tool | Description |
|------|-------------|
| `api_endpoint_discovery` | API endpoint discovery and enumeration |
| `run_curl_advanced` | Advanced cURL execution with custom headers/methods |

### Bug Bounty (3)

| Tool | Description |
|------|-------------|
| `scope_check` | Verify target against bug bounty program scope (HackerOne, Bugcrowd, Intigriti, Immunefi) |
| `generate_report` | Generate professional bug bounty / pentest reports |
| `get_payloads` | Retrieve curated payload sets by category (sqli, xss, lfi, rce, ssti, xxe, ssrf, auth_bypass) |

### Crypto / DeFi (3)

| Tool | Description |
|------|-------------|
| `smart_contract_audit` | Solidity smart contract security analysis |
| `defi_protocol_scan` | DeFi protocol security assessment |
| `blockchain_tx_analyzer` | Blockchain transaction tracing and analysis |

### Enhanced Detection (13) — Deep Vulnerability Discovery

| Tool | Description |
|------|-------------|
| `smart_vulnerability_detector` | Intelligent vuln detection: 403 bypass, cloud SSRF, info disclosure, method enum |
| `context_fuzzer` | Context-aware fuzzer: adapts wordlists per stack, 403/422/401 analysis, bypass |
| `target_profiler` | Stack profiling with custom attack vectors per technology (Go/Python/PHP/AWS) |
| `advanced_arp_discovery` | 4 fallback modes (arp-scan → nmap → ip neighbor → /proc/net/arp) + ARP spoofing detection |
| `advanced_smb_enum` | Multi-tool SMB (enum4linux → smbmap → smbclient → nmap scripts) + EternalBlue check |
| `enhanced_ssrf_scanner` | Cloud metadata (AWS/GCP/Azure), internal services, protocol payloads, blind SSRF |
| `enhanced_jwt_analyzer` | alg:none bypass, key confusion, claim manipulation, kid injection, exploit generation |
| `enhanced_idor_scanner` | UUID/base64/hash ID detection, horizontal + vertical privilege escalation |
| `enhanced_api_discovery` | Swagger/OpenAPI parsing, GraphQL introspection, method probing, error-based params |
| `enhanced_cors_scanner` | null origin, credentials+reflection, subdomain bypass, full takeover detection |
| `enhanced_waf_bypass` | Active bypass per WAF type (Cloudflare/AWS/ModSec/Imperva), 14+ techniques |
| `cloud_storage_enum` | AWS S3, GCS, Azure Blob enumeration with 25+ naming variants |
| `exploitation_chain` | Auto-chains: SSRF→creds, SQLi→RCE, IDOR→dump, XSS→takeover, LFI→RCE |

### Self-Audit (1)

| Tool | Description |
|------|-------------|
| `server_security_audit` | Audit the MCP server's own security posture |

---

## Quick Start

### Prerequisites

- **Python 3.10+**
- **Kali Linux** (recommended) or any Linux with pentest tools
- **FastMCP 3.4.4+**

### Installation

```bash
# Clone the repository
git clone https://github.com/Cabrel10/kali_mcp.git
cd kali_mcp/MCP-Kali-Server

# Install Python dependencies
pip install fastmcp aiohttp aiofiles

# Run the server
python3 kali_mcp_server.py
```

### Sudoers Configuration

Many pentest tools require root privileges. Configure passwordless sudo for the tools you need:

```bash
# Edit sudoers with visudo (NEVER edit /etc/sudoers directly)
sudo visudo -f /etc/sudoers.d/kali-mcp

# Add these lines (replace 'kali' with your username):
kali ALL=(ALL) NOPASSWD: /usr/bin/nmap
kali ALL=(ALL) NOPASSWD: /usr/bin/arp-scan
kali ALL=(ALL) NOPASSWD: /usr/sbin/enum4linux
kali ALL=(ALL) NOPASSWD: /usr/bin/hydra
kali ALL=(ALL) NOPASSWD: /usr/bin/john
kali ALL=(ALL) NOPASSWD: /usr/share/metasploit-framework/msfconsole
kali ALL=(ALL) NOPASSWD: /usr/bin/nikto
kali ALL=(ALL) NOPASSWD: /usr/bin/wpscan
kali ALL=(ALL) NOPASSWD: /usr/bin/sqlmap
```

> **Security Note:** Only grant NOPASSWD for specific binaries. Never use `ALL=(ALL) NOPASSWD: ALL` in production.

### MCP Client Configuration

Add to your AI client's MCP config (Claude Desktop, etc.):

```json
{
  "mcpServers": {
    "kali-tactical": {
      "command": "python3",
      "args": ["/path/to/MCP-Kali-Server/kali_mcp_server.py"],
      "env": {}
    }
  }
}
```

---

## Usage Examples

### 1. Start a Session and Scan

```json
// Step 1: Start session
{"tool": "start_session", "arguments": {"target": "example.com", "scope": "*.example.com"}}

// Step 2: Nmap scan
{"tool": "nmap_scan", "arguments": {"target": "example.com", "scan_type": "default", "ports": "1-1000"}}

// Step 3: CVE cartography on discovered services
{"tool": "cve_cartography", "arguments": {"target": "example.com"}}

// Step 4: Get chain summary (cross-referenced results)
{"tool": "get_chain_summary", "arguments": {"target": "example.com"}}
```

### 2. Web Application Assessment

```json
// Technology detection
{"tool": "web_tech_detect", "arguments": {"target": "https://example.com"}}

// Directory fuzzing
{"tool": "gobuster_scan", "arguments": {"target": "https://example.com", "wordlist": "/usr/share/wordlists/dirb/common.txt"}}

// Nuclei vulnerability scan
{"tool": "nuclei_scan", "arguments": {"target": "https://example.com", "severity": "critical,high"}}

// Security headers audit
{"tool": "header_security_audit", "arguments": {"target": "https://example.com"}}
```

### 3. Injection Testing

```json
// SQL injection
{"tool": "sql_injection_test", "arguments": {"target": "https://example.com/page?id=1"}}

// XSS scanning
{"tool": "xss_scan", "arguments": {"target": "https://example.com/search?q=test"}}

// SSTI detection
{"tool": "ssti_scanner", "arguments": {"target": "https://example.com/template?name=test"}}
```

### 4. Bug Bounty Workflow

```json
// Check scope before testing
{"tool": "scope_check", "arguments": {"target": "example.com", "platform": "hackerone", "program": "example"}}

// Get payloads
{"tool": "get_payloads", "arguments": {"category": "sqli"}}

// Generate report after findings
{"tool": "generate_report", "arguments": {"target": "example.com", "format": "markdown"}}
```

### 5. Tool Chaining (Automatic)

The ToolChainEngine automatically enriches outputs. When you run `nuclei_scan` after `nmap_scan` on the same target, the nuclei output will include:
- Previously discovered open ports and services (from nmap)
- Subdomain data (if `subdomain_enum` was run)
- Technology stack (if `web_tech_detect` was run)
- Known CVEs (if `cve_cartography` was run)

No manual cross-referencing needed.

---

## Session & Trace System

### Forensic Trace Logs

Every tool execution produces a `trace.jsonl` file:

```jsonl
{"timestamp": "2026-07-11T05:08:18.123", "elapsed_ms": 0, "phase": "init", "step": "Starting nmap_scan", "data": {"target": "example.com"}}
{"timestamp": "2026-07-11T05:08:18.456", "elapsed_ms": 333, "phase": "execute", "step": "Running nmap", "data": {"cmd": "nmap -sV example.com"}}
{"timestamp": "2026-07-11T05:08:25.789", "elapsed_ms": 7666, "phase": "parse", "step": "Parsing output", "data": {"ports_found": 5}}
{"timestamp": "2026-07-11T05:08:25.890", "elapsed_ms": 7767, "phase": "complete", "step": "Done", "data": {"status": "success"}}
```

### Session Directory Example

```
sessions/
└── pentest_20260711_050818/
    └── example.com/
        ├── nmap_scan/
        │   └── exec_a1b2c3d4/
        │       ├── trace.jsonl
        │       ├── result.json
        │       └── progress.json
        ├── nuclei_scan/
        │   └── exec_e5f6g7h8/
        │       ├── trace.jsonl
        │       ├── result.json
        │       └── progress.json
        └── cve_cartography/
            └── exec_i9j0k1l2/
                ├── trace.jsonl
                └── result.json
```

---

## CVE Cartography

The `CVECartographer` provides:

1. **Local CVE Database** — Curated entries for 13+ service families:
   - Apache HTTPD, Nginx, OpenSSH, MySQL, PostgreSQL, Redis
   - MongoDB, Elasticsearch, Docker, Kubernetes, ProFTPD
   - vsftpd, Microsoft IIS, and more

2. **NVD API Integration** — Queries NIST NVD for real-time CVE data

3. **Output per service:**
   ```json
   {
     "service": "apache/2.4.49",
     "cves": [
       {
         "id": "CVE-2021-41773",
         "severity": "critical",
         "cvss": 9.8,
         "description": "Path traversal and RCE",
         "patch": "Upgrade to Apache 2.4.51+"
       }
     ]
   }
   ```

---

## Security Hardening

### Input Validation

All tool inputs pass through `InputValidator`:

- **Targets**: Stripped of shell metacharacters, validated as hostname/IP/CIDR
- **Ports**: Must be valid integers 1-65535
- **Timeouts**: Bounded between 5-3600 seconds
- **Paths**: Blocked from traversal (`../`, `/etc/shadow`, etc.)
- **Shell injection**: Backticks, `$()`, pipes, semicolons stripped from user inputs

### Server Self-Audit

Run `server_security_audit` to check:
- File permissions on server code
- Exposed secrets in environment
- Dependency versions
- Network exposure
- Log file security

---

## Tool Requirements

### Pre-installed on Kali Linux
- `nmap`, `nikto`, `sqlmap`, `hydra`, `john`, `enum4linux`
- `curl`, `whois`, `dig`, `arp-scan`
- `metasploit-framework`

### Install Separately

```bash
# Go-based tools
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/ffuf/ffuf/v2@latest

# Update Nuclei templates
nuclei -update-templates

# Ruby-based
gem install wpscan

# Python-based
pip install vulnx

# System packages
sudo apt install -y arp-scan enum4linux smbclient
```

---

## Testing

```bash
# Run full test suite (59 tools)
python3 test_all_tools.py

# Quick syntax check
python3 -c "import py_compile; py_compile.compile('kali_mcp_server.py', doraise=True)"

# Verify tool count
python3 -c "
import kali_mcp_server
tools = [a for a in dir(kali_mcp_server) if not a.startswith('_')]
print(f'Module loaded successfully')
"
```

---

## Troubleshooting

### "Permission denied" on tool execution
Configure sudoers as described in the Sudoers Configuration section above.

### "Command not found" for a tool
Install the missing tool:
```bash
which nmap || sudo apt install -y nmap
which nuclei || go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Session directory not created
Ensure the server has write permissions to its working directory:
```bash
chmod 755 /path/to/MCP-Kali-Server/
```

### NVD API rate limiting
The CVECartographer caches results in `cve_cache/`. If you hit NVD rate limits, cached data will be used. For higher limits, set a NVD API key:
```bash
export NVD_API_KEY=your_key_here
```

---

## License

This project is for **educational and authorized security testing purposes only**.

**Unauthorized access to computer systems is illegal.** Always obtain written authorization before testing.

---

## Credits

Built with:
- [FastMCP](https://github.com/jlowin/fastmcp) — MCP Protocol Framework
- [ProjectDiscovery](https://github.com/projectdiscovery) — nuclei, subfinder, httpx
- [Nmap](https://nmap.org/) — Network scanning
- [SQLMap](https://sqlmap.org/) — SQL injection
- [OWASP](https://owasp.org/) — Security methodology

---

**With great power comes great responsibility. Always obtain proper authorization before testing.**
