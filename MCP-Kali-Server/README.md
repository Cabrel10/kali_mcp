# Kali MCP Server v6.3 — Autonomous Pentest Engine + Protocol Intelligence + Web Interactor

> 27 unified mega-modules | Protocol Intelligence Layer | Web Interactor (Playwright) | Honeypot Detection | Auto-Exploitation | Universal Stealth (9 tools) | Kill chain tracking | CVSS v3.1 scoring | MITRE ATT&CK mapping | Parallel execution | Cross-module correlation

## Architecture

```
72 fragmented tools -> 27 unified mega-modules
Manual decisions    -> Autonomous orchestration + auto-exploitation
Flat outputs        -> CVSS-scored, correlated, MITRE-mapped intelligence
Sequential scans    -> Parallel execution with kill-chain tracking
Static modules      -> Cross-module interconnection (findings feed next modules)
Command wrappers    -> Native protocol dissection (TCP/TLS/HTTP/DNS)
Blind scanning      -> Honeypot detection before engagement
Manual exploitation -> Context-aware auto-exploit with adapted parameters
No browser testing  -> Headless Playwright with anti-bot evasion + proof capture
Exposed IP          -> Universal proxy chain + IP rotation (never expose host)
```

### Protocol Intelligence Layer (4 classes) — `protocol_intelligence.py`

| Class | Purpose |
|-------|---------|
| `ProtocolAnalyzer` | Native TCP/TLS/HTTP/DNS dissection without external tools. OS fingerprint from TTL/window, WAF detection (7+ signatures), technology fingerprinting (40+ patterns), security header audit |
| `SmartFuzzer` | Auto-discovers parameters from HTML forms/JS/URLs. Establishes response baselines, detects anomalies (size/time/error). Tech-specific payloads: SQLi (MySQL/PostgreSQL/MSSQL/Oracle), SSTI (Jinja2/Twig/Freemarker), XSS, LFI, CMDi, SSRF, Open Redirect |
| `NetworkIntelligence` | Topology mapping with `networkx`. OS fingerprint from TTL, role detection (domain_controller, web_server, database, mail, etc.), subnet discovery, attack surface scoring |
| `ExploitAdvisor` | Maps service+version to specific CVEs/Metasploit modules with confidence scores. Tech-specific payload generation (MySQL vs PostgreSQL SQLi, Jinja2 vs Twig SSTI) |

### Universal Stealth Layer — `StealthConfig`

| Level | Name | Features |
|-------|------|----------|
| 0 | OFF | Direct execution, no modifications |
| 1 | BASIC | Random delays (0.3-1.5s), session-fixed UA, DNS-over-HTTPS, ban detection |
| 2 | ENHANCED | Rotating UA, proxy chain, MAC rotation, tool-specific evasion (nikto -Pause, sqlmap --random-agent --tamper, hydra -W, gobuster --delay, ffuf -rate, nuclei -rate-limit), TLS fingerprint variation |
| 3 | MAXIMUM | Multi-hop proxy, TCP fingerprint modification, nmap decoys+fragmentation, packet padding, sqlmap tamper scripts (between,randomcase,space2comment), aggressive delay (1-5s) |

**Automatically adapted tools:** nmap, curl, nikto, sqlmap, hydra, gobuster, ffuf, nuclei, wpscan

**Ban detection & recovery:** Detects 403/429/503/captcha/cloudflare patterns → auto-rotates proxy from pool → resets ban counter

### Core Infrastructure (6 classes)

| Class | Purpose |
|-------|---------|
| `ScanDepth` | Enum: `stealth / light / deep / aggressive` |
| `PentestMemory` | Cross-module finding storage, tech stack tracking, decision log |
| `RateLimitDetector` | Auto-detect 429/WAF, exponential backoff, per-target state |
| `IntelligentOrchestrator` | Response code analysis (403/405/422/500), stack-adapted configs (Spring/Django/Express/Flask/PHP/Go/ASP.NET), next-tool recommendations |
| `SessionManager` | Execution tracking, timing, input/output logging |
| `InputValidator` | Command injection prevention, input sanitization |

### Intelligence Engine (5 classes)

| Class | Purpose |
|-------|---------|
| `CVSSCalculator` | Dynamic CVSS v3.1 scoring with 25+ vulnerability type presets + context boost |
| `VulnCorrelator` | Cross-module correlation, 12 exploit chain patterns, 18 service vuln maps, attack surface scoring, MITRE aggregation |
| `KillChainTracker` | 7-phase Lockheed Martin kill chain with MITRE ATT&CK mapping per phase |
| `DeepOutputParser` | Parse nmap XML (NSE vulns, CVEs), error pages (tech fingerprint, info leaks), nuclei JSON, credentials (hydra/hashcat/john/secretsdump) |
| `ParallelExecutor` | Concurrent tool execution with semaphore, timeout handling, result aggregation |

### Adaptive Command Execution

| Feature | Description |
|---------|-------------|
| `TOOL_TIMEOUT_PROFILES` | Per-tool timeout limits (nmap stealth=90s, aggressive=300s; curl=30s; nuclei deep=180s) |
| `get_adaptive_timeout()` | Calculates optimal timeout based on tool + scan depth |
| `validate_xml_output()` | Repairs truncated nmap XML (closed tags, partial recovery) |
| `run_command()` | SIGINT before KILL for graceful termination, partial output recovery |
| `adapt_command()` | Universal stealth injection into ALL subprocess commands |

### 27 Mega-Modules

| # | Module | Capabilities | Key Tools |
|---|--------|-------------|-----------|
| 1 | `session_ops` | Session management, health check, memory query, recommendations, **stealth management** (set/status/config/mac_rotate/proxy_rotate/proxy_pool/ban_check) | built-in |
| 2 | `recon_engine` | Port scan, service fingerprint, tech detection, origin IP, TLS audit, NSE vuln extraction, service risk mapping | nmap, whatweb, openssl, dig |
| 3 | `web_assault` | Directory brute, vuln scan, source map extraction, WAF detection/bypass | nikto, gobuster/ffuf, curl |
| 4 | `injection_matrix` | SQLi, XSS, LFI, CMDi, SSTI — all register VulnFindings with CVSS + MITRE | sqlmap, custom payloads |
| 5 | `credential_cracker` | Entropy estimation, dictionary/mask/markov/rules attacks, online brute, deep credential extraction | hashcat, john, hydra |
| 6 | `network_dominator` | ARP spoofing, SMB enum, NTLM relay, responder, impacket suite | bettercap, responder, impacket |
| 7 | `wireless_audit` | Monitor/managed switch, scan, handshake, PMKID, WPA crack, **auto-pivot** (connect, ARP scan, gateway recon), restore | aircrack-ng, hcxdumptool, bettercap, wpa_supplicant |
| 8 | `cloud_siege` | S3/GCS/Azure bucket enum, metadata SSRF, IAM analysis, IMDSv1/v2 | aws-cli, gcloud, curl |
| 9 | `ad_annihilator` | BloodHound, Certipy (AD CS ESC1-8), Kerberoast, AS-REP, password spray | bloodhound, certipy, impacket |
| 10 | `api_breaker` | GraphQL introspection, REST enum, Actuator exploit, 405 bypass, auth testing | curl, custom |
| 11 | `vuln_scanner_ultra` | Nuclei (stack-adapted templates), CVE mapping, nmap vuln scripts | nuclei, nmap, searchsploit |
| 12 | `exploit_engine` | Metasploit, deserialization, Log4Shell, reverse shell gen, chain exploits | msfconsole, ysoserial |
| 13 | `auth_destroyer` | JWT attacks (none/kid/jwk), **BOLA/IDOR** (10 param names, method override, INT_MAX), CORS bypass, default creds | custom |
| 14 | `ssrf_hunter` | URL-based, blind, DNS rebind, cloud metadata, protocol smuggling (gopher/dict) | curl, collaborator |
| 15 | `crypto_forensics` | Cipher analysis, encrypted file/msg decryption, TLS audit, hash ID (15+ patterns), smart contract audit | openssl, testssl.sh, sslscan, john |
| 16 | `osint_harvester` | Subdomain enum, DNS records, WHOIS, crt.sh, Google dorking, zone transfer | subfinder, amass, dig |
| 17 | `post_exploit_ops` | Privesc, **deep persistence** (10 Linux + 7 Windows techniques with real commands), lateral movement, pivoting, exfil, payload gen | linpeas, ligolo-ng, chisel, mimikatz |
| 18 | `reporting_engine` | Executive/technical/full reports with CVSS, MITRE, kill chain, exploit chains | built-in |
| 19 | `autopilot_commander` | Full autonomous pentest with parallel execution, kill chain tracking, correlation-driven targeting | orchestrates all modules |
| 20 | `payload_factory` | Payload generation (XSS/SQLi/LFI/SSTI/XXE/CMDi), command execution, WPScan | wpscan, custom |
| 21 | `forensics_engine` | Log analysis, malware/botnet detection, USB forensics (HID attacks), memory analysis (Volatility), ransomware analysis, YARA scanning, IOC extraction, network forensics, timeline | chkrootkit, rkhunter, volatility, yara |
| 22 | `race_condition_tester` | Turbo Intruder-style concurrent requests, TOCTOU, session race, limit bypass, timing attacks | curl, custom |
| **23** | **`protocol_deep_scan`** | Native TCP/TLS/HTTP/DNS analysis without external tools, OS fingerprint, WAF detection, technology fingerprint, security headers | asyncio sockets |
| **24** | **`smart_fuzz_engine`** | Baseline-aware fuzzing, auto-discover parameters, tech-specific payloads, anomaly detection | httpx, SmartFuzzer |
| **25** | **`honeypot_detector`** | Banner analysis, timing analysis, behavioral tests, protocol anomaly, signature match (8 honeypots: Cowrie, Dionaea, Kippo, Glastopf, Honeyd, T-Pot, Conpot, ElasticHoney) | ProtocolAnalyzer |
| **26** | **`auto_exploit`** | MSF auto-config, sqlmap auto, hydra auto, web exploit chains (LFI→RCE, SSTI→RCE, SSRF→Cloud, XSS→Session), privesc suggest (SUID, kernel, sudo, Docker, capabilities) | metasploit, sqlmap, hydra |
| **27** | **`web_interactor`** | **Headless Chromium via Playwright**, anti-bot evasion (navigator.webdriver override, canvas noise), form manipulation, CSRF extraction, **XSS validation in real browser**, session/cookie analysis, **IP protection via proxy**, ban detection + auto-rotation, proof capture (screenshots, HAR, console) | playwright, httpx |

## Cross-Module Interconnections

```
wireless_audit (crack WPA) → auto-connect → ARP scan → recon_engine (pivot hosts)
recon_engine (services) → VulnCorrelator → autopilot (correlation-driven attacks)
protocol_deep_scan (native TCP/TLS) → ExploitAdvisor → auto_exploit (MSF configs)
honeypot_detector (check target) → auto_exploit (skip if honeypot detected)
web_interactor (browser XSS) → VulnFinding → VulnCorrelator → exploit chains
injection_matrix (findings) → VulnFinding → VulnCorrelator → exploit chains
smart_fuzz_engine (anomalies) → VulnFinding → auto_exploit (targeted exploitation)
credential_cracker → DeepParser → VulnCorrelator → kill chain advancement
forensics_engine (IOCs) → PentestMemory → all modules access shared context
race_condition_tester → VulnFinding → reporting_engine (executive report)
crypto_forensics (TLS issues) → VulnCorrelator → risk rating
post_exploit_ops (persistence) → KillChainTracker → reporting_engine
StealthConfig → run_command/run_command_shell → ALL tool executions stealth-adapted
```

## Exploit Chain Detection

The VulnCorrelator automatically detects 12 attack chains:

| Chain | Requirements | Impact |
|-------|-------------|--------|
| SSRF → Cloud Metadata → IAM Takeover | ssrf + cloud_detected | cloud_account_takeover |
| SQLi → Data Exfil → Credential Reuse | sqli + open_ports | database_compromise |
| LFI → Source Code → Hardcoded Secrets | lfi + web_vulns | credential_theft |
| Default Creds → Admin Panel → RCE | default_credentials + web_vulns | remote_code_execution |
| Kerberoast → Crack → Domain Admin | kerberoast + credentials | domain_admin |
| SMB Relay → NTLM → Lateral Movement | smb_signing_disabled + ntlm_hashes | lateral_movement |
| SSTI → RCE → Shell | ssti | remote_code_execution |
| Log4Shell → JNDI → Remote Class Loading | log4shell | remote_code_execution |
| XXE → SSRF → Internal Service Access | xxe | internal_network_access |
| JWT None Alg → Auth Bypass → Privesc | jwt_none_alg | privilege_escalation |
| AS-REP Roast → Crack → Initial Access | as_rep_roast | domain_user_access |
| WPA Handshake → Crack → WiFi → Pivot | wpa_handshake | network_access |

## Installation

```bash
pip install -r requirements.txt
# Kali Linux recommended — all pentest tools pre-installed
# For browser testing: playwright install chromium
```

## Usage

```bash
# Run as MCP server
python kali_mcp_server.py

# Run tests (80 tests covering all 27 modules + intelligence engine + stealth + web interactor)
python test_all_tools.py
```

### Example: Configure Stealth + Proxy Pool

```python
# Set stealth level 2 (enhanced)
await session_ops(action="stealth_set", session_name="2")

# Configure proxy pool for IP rotation (never exposes host IP)
await session_ops(action="stealth_proxy_pool",
    target='["socks5://proxy1:1080","socks5://proxy2:1080","socks5://proxy3:1080"]')

# All subsequent commands auto-inject: UA rotation, proxy, tool-specific flags
# nmap: -T1 --scan-delay 1s --randomize-hosts --proxies
# curl: -A 'rotating-ua' --proxy socks5://...
# sqlmap: --random-agent --delay=2 --proxy socks5://...
# nikto: -Pause 2 -Tuning x -useproxy socks5://...
# hydra: -W 5 -c 3
# gobuster: --delay 500ms --threads 5
# nuclei: -rate-limit 20 -bulk-size 5 -proxy socks5://...
```

### Example: Web Interactor (Browser Testing)

```python
# Navigate + extract forms + test XSS in real browser
result = await web_interactor(
    url="https://target.com/login",
    actions="navigate,extract,xss_test,session_test",
    stealth_level=2,
    screenshot=True,
    max_retries=3,
)
# Returns: forms extracted, CSRF tokens, XSS execution proof,
#          cookie security analysis, screenshot (base64)

# Fill and submit form
result = await web_interactor(
    url="https://target.com/login",
    actions="navigate,fill_form,click",
    form_data='{"#username": "admin", "#password": "test123"}',
    selectors='["#submit-btn"]',
    screenshot=True,
)
```

### Example: Autonomous Pentest

```python
result = await autopilot_commander(
    target="10.10.10.100",
    depth="deep",
    scope="full",
    aggressive=False,
    max_duration=1800
)
```

### Example: Protocol Intelligence + Auto-Exploit

```python
# Native protocol analysis (no nmap needed)
result = await protocol_deep_scan(target="10.0.0.1", depth="deep")

# Smart fuzzing with baseline detection
result = await smart_fuzz_engine(target="https://api.target.com", depth="deep")

# Check if target is a honeypot before engaging
result = await honeypot_detector(target="suspicious-host.com", depth="deep")

# Auto-exploit based on discovered vulnerabilities
result = await auto_exploit(target="10.0.0.1", strategy="safe_check")
```

## Intelligence Output Format

Every module returns structured JSON with:

```json
{
  "target": "10.10.10.100",
  "modules": { "...": "..." },
  "correlation": {
    "risk_rating": "CRITICAL",
    "attack_surface_score": 85.0,
    "exploit_chains": [{"chain": "SSRF -> Cloud -> IAM", "severity": "critical"}],
    "mitre_coverage": ["T1190", "T1552.005", "T1078.004"],
    "recommended_attack_path": [{"step": "...", "impact": "..."}]
  },
  "kill_chain": {
    "completion": "3/7",
    "completion_pct": 42.9,
    "next_phase": {"phase": "installation", "recommended_tools": ["post_exploit_ops"]}
  },
  "intelligence_summary": {
    "risk_rating": "CRITICAL",
    "modules_executed": ["recon", "web", "injection"],
    "exploitable_vulns": 5
  }
}
```

## Stats

- **8,462 lines** of Python (main server)
- **1,721 lines** protocol intelligence layer
- **27 mega-modules** (22 core + protocol intelligence + honeypot + auto-exploit + web interactor)
- **20+ classes** (6 core + 5 intelligence + 4 protocol + 6 data/enum)
- **12 exploit chain patterns** auto-detected
- **25+ CVSS vulnerability presets** with context boost
- **7 kill chain phases** with MITRE ATT&CK mapping
- **18 service vulnerability maps** (SSH, SMB, HTTP, LDAP, Redis, Docker, K8s, ...)
- **9 tools auto-stealth-adapted** (nmap, curl, nikto, sqlmap, hydra, gobuster, ffuf, nuclei, wpscan)
- **4 stealth levels** with ban detection + proxy rotation
- **8 honeypot signatures** with behavioral scoring
- **80 automated tests** covering all layers

## Test Coverage

```
Section 1:  Core Infrastructure          — 6 tests (ScanDepth, PentestMemory, RateLimitDetector, Orchestrator, SessionManager, InputValidator)
Section 2:  Intelligence Engine          — 5 tests (CVSSCalculator, VulnCorrelator, KillChainTracker, DeepOutputParser, ParallelExecutor)
Section 3:  Module Signatures (27)       — 27 tests (all 27 tools: exist, async, correct params)
Section 4:  Async Execution              — 10 tests (session_ops, recon, creds, reporting, payload, osint, forensics, race, crypto, persist)
Section 5:  Enhanced Features            — 6 tests (wireless pivot, crypto decrypt, deep persistence, IDOR, forensics submodules, race submodules)
Section 6:  Protocol Intelligence        — 8 tests (imports, TCP analyzer, DNS analyzer, fuzzer payloads, network intel, exploit advisor, deep scan exec, fuzz exec)
Section 7:  Honeypot + Auto-Exploit      — 5 tests (exec honeypot, exec auto-exploit, signatures DB, scoring weights, source verification)
Section 8:  Stealth + Adaptive           — 8 tests (config levels, nmap adaptation, adaptive timeouts, XML validation, session ops, run_command sig, universal adapt, ban detection)
Section 9:  Web Interactor               — 3 tests (signature, source verification, execution)
Section 10: Integration                  — 2 tests (full correlation pipeline, cross-module interconnection)
─────────────────────────────────────────────────
Total: 80 tests | ALL PASSED
Compatible: fastmcp 2.x (FunctionTool) + fastmcp 3.x (raw function)
```

## License

MIT

## Author

Cabrel10 / MorningStar
