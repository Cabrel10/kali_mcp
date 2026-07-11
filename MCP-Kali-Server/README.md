# Kali MCP Server v6.2 — Autonomous Pentest Engine (Mythos-tier)

> 22 unified mega-modules | 17 intelligence classes | Kill chain tracking | CVSS v3.1 scoring | MITRE ATT&CK mapping | Parallel execution | Cross-module correlation | Digital forensics | Race condition testing

## Architecture

```
72 fragmented tools -> 22 unified mega-modules
Manual decisions    -> Autonomous orchestration  
Flat outputs        -> CVSS-scored, correlated, MITRE-mapped intelligence
Sequential scans    -> Parallel execution with kill-chain tracking
Static modules      -> Cross-module interconnection (findings feed next modules)
```

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

### Data Classes & Enums (6)

| Class | Purpose |
|-------|---------|
| `VulnFinding` | Structured vuln with CVSS score/vector, MITRE techniques, kill chain phase, remediation |
| `KillChainPhase` | 7-phase enum: reconnaissance → weaponization → delivery → exploitation → installation → C2 → actions |
| `VulnerabilityLevel` | Severity enum for categorization |
| `ToolStatus` | Execution status tracking |
| `TraceEntry` | Audit trail for tool executions |
| `ToolExecution` | Dataclass for individual execution tracking |

### 22 Mega-Modules

| # | Module | Capabilities | Key Tools |
|---|--------|-------------|-----------|
| 1 | `session_ops` | Session management, health check, memory query, recommendations | built-in |
| 2 | `recon_engine` | Port scan, service fingerprint, tech detection, origin IP, TLS audit, NSE vuln extraction, service risk mapping | nmap, whatweb, openssl, dig |
| 3 | `web_assault` | Directory brute, vuln scan, source map extraction, WAF detection/bypass | nikto, gobuster/ffuf, curl |
| 4 | `injection_matrix` | SQLi, XSS, LFI, CMDi, SSTI — all register VulnFindings with CVSS + MITRE | sqlmap, custom payloads |
| 5 | `credential_cracker` | Entropy estimation, dictionary/mask/markov/rules attacks, online brute, deep credential extraction | hashcat, john, hydra |
| 6 | `network_dominator` | ARP spoofing, SMB enum, NTLM relay, responder, impacket suite | bettercap, responder, impacket |
| 7 | `wireless_audit` | **Monitor↔managed mode switch**, scan, handshake, PMKID, WPA crack, **auto-pivot after crack** (connect, ARP scan, gateway recon), restore mode | aircrack-ng, hcxdumptool, bettercap, wpa_supplicant |
| 8 | `cloud_siege` | S3/GCS/Azure bucket enum, metadata SSRF, IAM analysis, IMDSv1/v2 | aws-cli, gcloud, curl |
| 9 | `ad_annihilator` | BloodHound, Certipy (AD CS ESC1-8), Kerberoast, AS-REP, password spray | bloodhound, certipy, impacket |
| 10 | `api_breaker` | GraphQL introspection, REST enum, Actuator exploit, 405 bypass, auth testing | curl, custom |
| 11 | `vuln_scanner_ultra` | Nuclei (stack-adapted templates), CVE mapping, nmap vuln scripts | nuclei, nmap, searchsploit |
| 12 | `exploit_engine` | Metasploit, deserialization, Log4Shell, reverse shell gen, chain exploits | msfconsole, ysoserial |
| 13 | `auth_destroyer` | JWT attacks (none/kid/jwk), **BOLA/IDOR** (10 param names, method override, INT_MAX), CORS bypass, default creds, header/path mutation | custom |
| 14 | `ssrf_hunter` | URL-based, blind, DNS rebind, cloud metadata, protocol smuggling (gopher/dict) | curl, collaborator |
| 15 | `crypto_forensics` | **Cipher analysis** (entropy, magic bytes, format detection), **encrypted file/msg decryption** (OpenSSL brute, john for archives, Caesar/ROT/Base64/hex/Vigenere), **TLS audit** (testssl.sh, sslscan, weak protocols), **hash ID** (15+ patterns with hashcat modes), smart contract audit, DeFi analysis | openssl, testssl.sh, sslscan, john, hashid |
| 16 | `osint_harvester` | Subdomain enum, DNS records, WHOIS, crt.sh, Google dorking, zone transfer | subfinder, amass, dig |
| 17 | `post_exploit_ops` | Privesc, **deep persistence** (10 Linux: LD_PRELOAD, PAM backdoor, systemd timer, rc.local, MOTD, init.d... + 7 Windows: golden ticket, WMI, COM hijack, DLL hijack...), lateral movement, pivoting, exfil, **payload generation** (msfvenom, python, powershell) | linpeas, ligolo-ng, chisel, mimikatz |
| 18 | `reporting_engine` | Executive/technical/full reports with CVSS, MITRE, kill chain, exploit chains, header audit | built-in |
| 19 | `autopilot_commander` | Full autonomous pentest with parallel execution, kill chain tracking, correlation-driven targeting | orchestrates all modules |
| 20 | `payload_factory` | Payload generation (XSS/SQLi/LFI/SSTI/XXE/CMDi), command execution, WPScan | wpscan, custom |
| **21** | **`forensics_engine`** | **Log analysis** (auth failures, brute force, privesc, suspicious patterns), **malware/botnet detection** (C2 ports, mining, rootkits, hidden files, DNS tunneling), **USB forensics** (HID attacks, Rubber Ducky, BadUSB), **memory analysis** (Volatility), **ransomware analysis** (40+ extensions, entropy, decryptor lookup), **YARA scanning**, **IOC extraction**, **network forensics** (ARP spoof detection), **timeline reconstruction** | chkrootkit, rkhunter, volatility, yara, lsusb |
| **22** | **`race_condition_tester`** | **Turbo Intruder-style concurrent requests**, **TOCTOU** (price manipulation, role escalation, quantity abuse), **session race** (concurrent login), **limit bypass** (coupon reuse, vote stuffing), **timing attacks** (username enumeration via response time differential) | curl, custom |

## Cross-Module Interconnections

```
wireless_audit (crack WPA) → auto-connect → ARP scan → recon_engine (pivot hosts)
recon_engine (services) → VulnCorrelator → autopilot (correlation-driven attacks)
injection_matrix (findings) → VulnFinding → VulnCorrelator → exploit chains
credential_cracker → DeepParser → VulnCorrelator → kill chain advancement
forensics_engine (IOCs) → PentestMemory → all modules access shared context
race_condition_tester → VulnFinding → reporting_engine (executive report)
crypto_forensics (TLS issues) → VulnCorrelator → risk rating
post_exploit_ops (persistence) → KillChainTracker → reporting_engine
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
pip install fastmcp
# Kali Linux recommended — all pentest tools pre-installed
```

## Usage

```bash
# Run as MCP server
python kali_mcp_server.py

# Run tests (51 tests covering all 22 modules + intelligence engine)
python test_all_tools.py
```

### Example: Autonomous Pentest

```python
result = await autopilot_commander(
    target="10.10.10.100",
    depth="deep",
    scope="full",        # web|network|cloud|internal|full|api|wireless
    aggressive=False,
    max_duration=1800
)
# Returns: intelligence summary, exploit chains, MITRE coverage, kill chain progress
```

### Example: WiFi Audit with Auto-Pivot

```python
result = await wireless_audit(
    interface="wlan0",
    target_bssid="AA:BB:CC:DD:EE:FF",
    depth="aggressive",
    modules="all",       # monitor,scan,capture,pmkid,crack,pivot,restore
    wordlist="auto"
)
# Cracks WPA → connects to network → ARP scans for hosts → scans gateway → suggests next tools
```

### Example: Digital Forensics

```python
result = await forensics_engine(
    target="192.168.1.50",
    modules="all",       # log_analysis,malware_detect,usb_forensics,memory_analysis,
                         # ransomware_analysis,yara_scan,ioc_extract,network_forensics,
                         # botnet_detect,timeline
    depth="deep"
)
# Returns: suspicious processes, rootkit checks, USB HID attacks, IOCs, timeline
```

### Example: Race Condition Testing

```python
result = await race_condition_tester(
    target="https://shop.example.com",
    modules="all",       # concurrent_requests,toctou,session_race,limit_bypass,timing_attack
    endpoint="/api/checkout",
    method="POST",
    concurrent=50,
    timeout=60
)
# Returns: TOCTOU vulnerabilities, limit bypass results, timing differentials
```

### Example: Crypto Forensics (Enhanced)

```python
# Hash identification
result = await crypto_forensics(
    target="$2b$12$LJ3m4ys3Lg...",
    modules="hash_id"
)

# Encrypted file decryption
result = await crypto_forensics(
    target="/path/to/encrypted.file",
    modules="cipher_analysis,decrypt"
)

# TLS audit
result = await crypto_forensics(
    target="vulnerable-server.com",
    modules="tls_audit",
    depth="aggressive"
)
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

- **5,692 lines** of Python
- **22 mega-modules** (consolidated from 72 + 2 new forensics/race)
- **17 classes** (6 core + 5 intelligence + 6 data/enum)
- **12 exploit chain patterns** auto-detected
- **25+ CVSS vulnerability presets** with context boost
- **7 kill chain phases** with MITRE ATT&CK mapping
- **18 service vulnerability maps** (SSH, SMB, HTTP, LDAP, Redis, Docker, K8s, ...)
- **15+ hash identification patterns** with hashcat modes
- **40+ ransomware extension signatures**
- **10 Linux + 7 Windows persistence techniques** with real commands
- **51 automated tests** covering all layers

## Test Coverage

```
Section 1: Core Infrastructure      — 6 tests (ScanDepth, PentestMemory, RateLimitDetector, Orchestrator, SessionManager, InputValidator)
Section 2: Intelligence Engine       — 5 tests (CVSSCalculator, VulnCorrelator, KillChainTracker, DeepOutputParser, ParallelExecutor)
Section 3: Module Signatures         — 22 tests (all 22 tools: exist, async, correct params)
Section 4: Async Execution           — 10 tests (session_ops, recon, creds, reporting, payload, osint, forensics, race, crypto, persist)
Section 5: Enhanced Feature Tests    — 6 tests (wireless pivot, crypto decrypt, deep persistence, IDOR, forensics submodules, race submodules)
Section 6: Integration               — 2 tests (full correlation pipeline, cross-module interconnection)
─────────────────────────────────────────────────
Total: 51 tests | ALL PASSED
```

## License

MIT

## Author

Cabrel10 / MorningStar
