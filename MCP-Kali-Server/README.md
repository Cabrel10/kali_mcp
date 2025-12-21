# 🎯 Kali MCP Tactical Server

**Professional Penetration Testing Platform with MCP Protocol**

A comprehensive, intelligent, and highly automated penetration testing server designed for AI-driven security operations.

---

## 🌟 Features

### 🔍 **Reconnaissance & Intelligence**
- **Fast Port Scanning** with naabu/nmap
- **Service Fingerprinting** with intelligent recommendations
- **Web Technology Detection** (CMS, frameworks, libraries)
- **OSINT Gathering** (WHOIS, DNS, SSL analysis)
- **Subdomain Enumeration** with subfinder

### 💣 **Vulnerability Assessment**
- **Nuclei Integration** with 2024/2025 CVE templates
- **SQL Injection Testing** with SQLMap
- **XSS Detection** with dalfox
- **CVE Matching** and exploit search
- **Web Vulnerability Scanning** (comprehensive)

### 🌐 **Web Application Attacks**
- **Directory Fuzzing** with ffuf/gobuster
- **API Endpoint Discovery**
- **Subdomain Takeover Detection**
- **Technology Stack Analysis**

### 🛡️ **Evasion & Stealth**
- **Adaptive Rate Limiting** to avoid detection
- **IP Rotation** (Tor/VPN integration)
- **Proxy Pool Management**
- **MikroTik Stealth Mode** (ultra-slow scanning)
- **User-Agent Rotation**

### 🌊 **Distributed Operations**
- **IP Pool Distribution** for parallel attacks
- **Bypasses per-IP rate limits**
- **Distributed Port Scanning**
- **Parallel Web Fuzzing**

### 📄 **Advanced Tools**
- **Document Forensics** (metadata, malware detection)
- **Hash Cracking** with hashcat
- **Database Exploitation** (extraction, manipulation)
- **Binary Analysis** with radare2/strings
- **Scam Detection** and site legitimacy analysis

### 🧠 **Tactical Intelligence**
- **Automated Triage** - analyzes results and suggests actions
- **Decision Matrix** - technology-specific attack patterns
- **Execution Flow Generation** - prioritized action plans
- **Database Caching** - avoids redundant scans

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
cd MCP-Kali-Server

# Install dependencies
./start.sh
```

### Configuration

1. Copy `.env.example` to `.env`
2. Configure your settings:

```bash
# Basic configuration
OPENROUTER_API_KEY=your_key_here
DB_PATH=/tmp/kali_mcp_tactical.db

# Scanner settings
SCAN_TIMEOUT=300
MAX_PARALLEL_TASKS=10

# Evasion settings
ENABLE_GHOST_MODE=true
MIKROTIK_STEALTH_MODE=true
AUTO_ROTATE_IP_ON_BAN=true

# IP Pool (comma-separated)
IP_POOL=socks5://127.0.0.1:9050,socks5://127.0.0.1:9052
```

### Running the Server

```bash
# Start the MCP server
./start.sh

# Or directly with Python
python3 main.py
```

---

## 📋 Available Tools

### Reconnaissance
- `tactical_recon` - Complete tactical reconnaissance
- `port_scan` - Advanced port scanning
- `service_fingerprinting` - Service detection and recommendations

### Vulnerability Scanning
- `nuclei_scan` - Nuclei vulnerability scanning
- `sql_injection_test` - SQL injection detection
- `check_cve` - CVE matching for services

### Web Attacks
- `web_fuzzing` - Directory/file fuzzing
- `xss_scan` - XSS vulnerability scanning
- `subdomain_takeover` - Subdomain takeover detection
- `api_discovery` - API endpoint enumeration

### Advanced Operations
- `analyze_document` - Document forensics
- `crack_hashes` - Password hash cracking
- `scam_detection` - Site legitimacy analysis
- `enumerate_subdomains` - Subdomain enumeration

### Evasion & Stealth
- `stealth_scan` - Ultra-stealth MikroTik scanning
- `rotate_ip` - IP address rotation
- `check_if_banned` - Ban detection

### Distributed Operations
- `distributed_scan` - Distributed port scanning
- `distributed_fuzzing` - Parallel web fuzzing
- `distributed_brute_force` - Distributed password attacks

### Task Management
- `check_task` - Check background task status
- `list_tasks` - List all tasks

### Intelligence
- `tactical_triage` - Generate action plans from scan results
- `get_stats` - Server statistics

---

## 🎯 Usage Examples

### Basic Reconnaissance

```python
# Quick reconnaissance
{
    "tool": "tactical_recon",
    "arguments": {
        "target": "example.com",
        "intensity": "fast"
    }
}

# Response includes:
# - Open ports
# - Services detected
# - Web technologies
# - Recommendations
```

### Vulnerability Scanning

```python
# Nuclei scan for critical vulnerabilities
{
    "tool": "nuclei_scan",
    "arguments": {
        "target": "https://example.com",
        "intensity": "deep"
    }
}

# Returns:
# - Critical vulnerabilities
# - High/Medium/Low severity issues
# - CVE IDs
# - Exploit recommendations
```

### Stealth Operations

```python
# MikroTik stealth scan (ultra-slow to avoid blacklisting)
{
    "tool": "stealth_scan",
    "arguments": {
        "target": "192.168.1.1"
    }
}

# Features:
# - Rate: 10 packets/second maximum
# - 8-15 second delays between requests
# - Targeted ports: 22,23,80,443,8291,8728,8729
```

### Distributed Attack

```python
# Distribute port scan across IP pool
{
    "tool": "distributed_scan",
    "arguments": {
        "target": "example.com",
        "ports": [80, 443, 8080, 8443, 3000]
    }
}

# Bypasses per-IP rate limits by using multiple sources
```

### Tactical Intelligence

```python
# Generate action plan from scan results
{
    "tool": "tactical_triage",
    "arguments": {
        "scan_data": "{...scan results JSON...}"
    }
}

# Returns prioritized action plan with:
# - Immediate actions
# - Exploitation opportunities
# - Investigation paths
# - Execution flow
```

---

## 🛠️ Tool Requirements

### Essential Tools (Pre-installed on Kali Linux)
- `nmap` - Port scanning
- `curl` - HTTP requests
- `whois` - Domain information

### Recommended Tools (Install separately)
```bash
# Go-based tools (fastest)
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/hahwul/dalfox/v2@latest

# Update Nuclei templates
nuclei -update-templates

# Other tools
sudo apt install -y sqlmap hashcat gobuster exiftool
```

---

## 📊 Architecture

```
MCP-Kali-Server/
├── src/
│   ├── core/                 # Core engine components
│   │   ├── config.py         # Configuration management
│   │   ├── async_executor.py # Async command execution
│   │   ├── output_processor.py # Output parsing
│   │   ├── task_manager.py   # Background task management
│   │   └── database.py       # SQLite caching
│   │
│   ├── modules/              # Main tactical modules
│   │   ├── network_recon.py  # Network reconnaissance
│   │   ├── vulnerability_scanner.py # Vulnerability scanning
│   │   └── web_assault.py    # Web application attacks
│   │
│   ├── tools/                # Advanced specialized tools
│   │   ├── document_analyzer.py # Document forensics
│   │   ├── database_expert.py # Database operations
│   │   ├── evasion_engine.py # Stealth techniques
│   │   ├── distributed_attack.py # Distributed operations
│   │   ├── osint_hunter.py   # OSINT gathering
│   │   └── reverse_engineer.py # Binary analysis
│   │
│   ├── utils/                # Utilities
│   │   └── triage_engine.py  # Intelligence and decision-making
│   │
│   └── server.py             # Main MCP server
│
├── data/                     # Runtime data
│   ├── cache/                # Cached scan results
│   ├── logs/                 # Server logs
│   └── results/              # Scan results
│
├── .env                      # Configuration (create from .env.example)
├── requirements.txt          # Python dependencies
├── main.py                   # Entry point
└── start.sh                  # Start script
```

---

## 🔒 Security Considerations

### Rate Limiting & Detection Avoidance
- **Adaptive delays** based on scan intensity
- **MikroTik stealth mode** uses 8-15 second delays
- **Automatic ban detection** and IP rotation

### IP Pool Configuration
Configure multiple proxy sources for distributed attacks:
```bash
IP_POOL=socks5://127.0.0.1:9050,socks5://127.0.0.1:9052,socks5://127.0.0.1:9053
```

### User-Agent Rotation
Automatically rotates through realistic user-agent strings.

---

## 📈 Performance Metrics

| Operation | Traditional Time | Optimized Time | Speedup |
|-----------|-----------------|----------------|---------|
| Port Scan (1000 ports) | 5-10 minutes | 30-60 seconds | **10x** |
| Web Directory Fuzzing | 10-15 minutes | 2-3 minutes | **5x** |
| Vulnerability Scan | 15-20 minutes | 3-5 minutes | **5x** |
| Distributed Attack | N/A | Real-time | **∞** |

**Token Efficiency:** 90% reduction in LLM token usage through intelligent output processing.

---

## 🤝 Integration with AI

### With Claude/Gemini

Configure the MCP server in your AI client:

```json
{
  "mcpServers": {
    "kali-tactical": {
      "command": "/path/to/MCP-Kali-Server/start.sh",
      "args": [],
      "env": {}
    }
  }
}
```

### AI Prompt Guidance

```
You are a professional penetration tester with access to a Kali MCP Tactical Server.

WORKFLOW:
1. Always start with `tactical_recon` for new targets
2. Analyze results and use `tactical_triage` to generate action plan
3. Execute high-priority actions first (critical vulnerabilities)
4. Use stealth mode for sensitive targets (MikroTik, corporate)
5. Leverage distributed attacks to bypass rate limits
6. Cache results automatically to avoid redundant scans

BEST PRACTICES:
- For web apps: recon → web_fuzzing → nuclei_scan → xss_scan
- For infrastructure: port_scan → service_fingerprinting → exploit_search
- For stealth: Always use stealth_scan for MikroTik devices
- For speed: Use distributed_scan with IP pool for large port ranges
```

---

## 🐛 Troubleshooting

### "Nuclei not available"
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
export PATH=$PATH:$HOME/go/bin
nuclei -update-templates
```

### "Task timeout"
Increase timeout in `.env`:
```bash
SCAN_TIMEOUT=600  # 10 minutes
```

### "IP banned"
Enable auto-rotation:
```bash
AUTO_ROTATE_IP_ON_BAN=true
```

And configure Tor:
```bash
sudo apt install tor
sudo service tor start
```

---

## 📝 License

This project is for **educational and authorized security testing purposes only**.

**Unauthorized access to computer systems is illegal.**

---

## 🙏 Credits

Built with:
- [MCP Protocol](https://github.com/anthropics/mcp) by Anthropic
- [ProjectDiscovery Tools](https://github.com/projectdiscovery) (nuclei, httpx, naabu, subfinder)
- [FFUF](https://github.com/ffuf/ffuf)
- [SQLMap](https://sqlmap.org/)
- [Hashcat](https://hashcat.net/)

---

## 📧 Support

For issues, improvements, or questions:
- Open an issue on GitHub
- Check the logs in `data/logs/`
- Review configuration in `.env`

---

**🎯 Remember: With great power comes great responsibility. Always obtain proper authorization before testing.**
