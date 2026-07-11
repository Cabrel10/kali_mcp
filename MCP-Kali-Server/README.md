# Kali MCP Server v6 — Autonomous Pentest Engine

> 20 unified mega-modules | 11 intelligence classes | Kill chain tracking | CVSS scoring | MITRE ATT&CK mapping | Parallel execution | Cross-module correlation

## Architecture

```
72 fragmented tools -> 20 unified mega-modules
Manual decisions    -> Autonomous orchestration  
Flat outputs        -> CVSS-scored, correlated, MITRE-mapped intelligence
Sequential scans    -> Parallel execution with kill-chain tracking
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
| `CVSSCalculator` | Dynamic CVSS v3.1 scoring with 25+ vulnerability type presets |
| `VulnCorrelator` | Cross-module correlation, 12 exploit chain patterns, attack surface scoring, MITRE technique aggregation |
| `KillChainTracker` | 7-phase Lockheed Martin kill chain with MITRE ATT&CK mapping per phase |
| `DeepOutputParser` | Parse nmap XML (NSE vulns, CVEs), error pages (tech fingerprint, info leaks, stack traces), nuclei JSON, credentials (hydra/hashcat/john/secretsdump) |
| `ParallelExecutor` | Concurrent tool execution with semaphore, timeout handling, result aggregation |

### 20 Mega-Modules

| # | Module | Capabilities | Key Tools |
|---|--------|-------------|-----------|
| 1 | `recon_engine` | Port scan, service fingerprint, tech detection, origin IP hunting, TLS audit | nmap, whatweb, openssl, dig |
| 2 | `web_assault` | Directory brute, vulnerability scan, source map extraction, WAF detection/bypass | nikto, gobuster/ffuf, curl |
| 3 | `injection_matrix` | SQLi, XSS, LFI, CMDi, SSTI, JSON parameter fuzzing | sqlmap, custom payloads |
| 4 | `credential_cracker` | Entropy estimation, dictionary/mask/markov/rules attacks, online brute force | hashcat, john, hydra |
| 5 | `network_dominator` | ARP spoofing, SMB enum, NTLM relay, responder, impacket | bettercap, responder, impacket |
| 6 | `wireless_audit` | Monitor mode, scan, handshake capture, PMKID, WPA crack | aircrack-ng, hcxdumptool, bettercap |
| 7 | `cloud_siege` | S3/GCS/Azure bucket enum, metadata SSRF, IAM analysis | aws-cli, gcloud, curl |
| 8 | `ad_annihilator` | BloodHound, Certipy (AD CS ESC1-8), Kerberoast, AS-REP, password spray | bloodhound, certipy, impacket |
| 9 | `api_breaker` | GraphQL introspection, REST enum, Actuator exploit, 405 bypass, auth testing | curl, custom |
| 10 | `vuln_scanner_ultra` | Nuclei (stack-adapted templates), CVE mapping, nmap vuln scripts | nuclei, nmap, searchsploit |
| 11 | `exploit_engine` | Metasploit, deserialization, Log4Shell, reverse shell generation, chain exploits | msfconsole, ysoserial |
| 12 | `auth_destroyer` | JWT attacks (none alg, kid injection), IDOR, CORS bypass, default creds, header/path mutation | custom |
| 13 | `ssrf_hunter` | URL-based, blind, DNS rebind, cloud metadata, protocol smuggling (gopher/dict) | curl, collaborator |
| 14 | `crypto_forensics` | Smart contract audit, DeFi analysis, transaction tracing | custom |
| 15 | `osint_harvester` | Subdomain enum, DNS records, WHOIS, crt.sh, Google dorking | subfinder, amass, dig |
| 16 | `post_exploit_ops` | Privilege escalation, persistence, lateral movement, pivoting, exfiltration | linpeas, ligolo-ng, chisel |
| 17 | `reporting_engine` | Executive/technical/full reports with CVSS, MITRE, kill chain, exploit chains, header audit | built-in |
| 18 | `autopilot_commander` | Full autonomous pentest with parallel execution, kill chain tracking, correlation-driven targeting | orchestrates all modules |
| 19 | `session_ops` | Session management, health check, memory query, recommendations | built-in |
| 20 | `payload_factory` | Payload generation (XSS/SQLi/LFI/SSTI/XXE/CMDi), command execution, WPScan | wpscan, custom |

## Exploit Chain Detection

The VulnCorrelator automatically detects 12 attack chains:

| Chain | Requirements | Impact |
|-------|-------------|--------|
| SSRF -> Cloud Metadata -> IAM Takeover | ssrf + cloud_detected | cloud_account_takeover |
| SQLi -> Data Exfil -> Credential Reuse | sqli + open_ports | database_compromise |
| LFI -> Source Code -> Hardcoded Secrets | lfi + web_vulns | credential_theft |
| Default Creds -> Admin Panel -> RCE | default_credentials + web_vulns | remote_code_execution |
| Kerberoast -> Crack -> Domain Admin | kerberoast + credentials | domain_admin |
| SMB Relay -> NTLM -> Lateral Movement | smb_signing_disabled + ntlm_hashes | lateral_movement |
| SSTI -> RCE -> Shell | ssti | remote_code_execution |
| Log4Shell -> JNDI -> Remote Class Loading | log4shell | remote_code_execution |
| XXE -> SSRF -> Internal Service Access | xxe | internal_network_access |
| JWT None Alg -> Auth Bypass -> Privesc | jwt_none_alg | privilege_escalation |
| AS-REP Roast -> Crack -> Initial Access | as_rep_roast | domain_user_access |
| WPA Handshake -> Crack -> WiFi -> Pivot | wpa_handshake | network_access |

## Installation

```bash
pip install fastmcp
# Kali Linux recommended — all pentest tools pre-installed
```

## Usage

```bash
# Run as MCP server
python kali_mcp_server.py

# Run tests (38 tests covering all modules + intelligence engine)
python test_all_tools.py
```

### Example: Autonomous Pentest

```python
# The autopilot runs modules in parallel, tracks kill chain, builds attack paths
result = await autopilot_commander(
    target="10.10.10.100",
    depth="deep",
    scope="full",        # web|network|cloud|internal|full|api|wireless
    aggressive=False,
    max_duration=1800
)
# Returns: intelligence summary, exploit chains, MITRE coverage, kill chain progress
```

### Example: Credential Cracking with Entropy Estimation

```python
result = await credential_cracker(
    target="10.10.10.100",
    hash_value="5f4dcc3b5aa765d61d8327deb882cf99",
    hash_type="auto",     # auto-detected from length/prefix
    technique="auto",     # dictionary -> mask -> rules -> markov
    entropy_limit=60,     # skip hashes above this entropy
    timeout=600
)
# Returns: hash_analysis (type, entropy, crackability, estimated_time), cracked credentials
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
  "recommendations": [{"module": "ssrf_hunter", "reason": "SSRF potential detected"}]
}
```

## Stats

- **4,395 lines** of Python
- **20 mega-modules** (consolidated from 72)
- **11 core + intelligence classes**
- **12 exploit chain patterns**
- **25+ CVSS vulnerability presets**
- **7 kill chain phases** with MITRE ATT&CK mapping
- **18 service vulnerability maps** (SSH, SMB, HTTP, LDAP, Redis, Docker, K8s, ...)
- **38 automated tests** covering all layers

## License

MIT

## Author

Cabrel10 / MorningStar
