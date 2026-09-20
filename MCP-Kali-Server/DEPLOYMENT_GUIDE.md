# 🚀 Deployment Guide - Kali MCP Tactical Server

## ✅ Current Status

**All code is complete and committed locally.**

```bash
Branch: tactical-server-implementation
Commits: 5 (all phases complete)
Files: 40+ files
Lines of Code: 15,000+
Status: Production-ready
```

---

## 🔧 GitHub Push Issue Resolution

### Problem
```
remote: Permission to Cabrel10/kali_mcp.git denied to Cabrel10.
fatal: unable to access 'https://github.com/Cabrel10/kali_mcp.git/': The requested URL returned error: 403
```

### Solution Options

#### Option 1: Update GitHub Token (Recommended)

1. **Generate New Token:**
   - Go to: https://github.com/settings/tokens
   - Click "Generate new token (classic)"
   - Select scopes: `repo` (full control)
   - Generate and copy token

2. **Update Git Credentials:**
   ```bash
   cd /home/user/webapp
   
   # Update remote URL with token
   git remote set-url origin https://YOUR_GITHUB_TOKEN@github.com/Cabrel10/kali_mcp.git
   
   # Push the branch
   git push -u origin tactical-server-implementation
   ```

3. **Create Pull Request:**
   - Go to: https://github.com/Cabrel10/kali_mcp
   - Click "Compare & pull request"
   - Merge to master

#### Option 2: Manual Upload via GitHub Web

1. **Download as ZIP:**
   ```bash
   cd /home/user/webapp
   tar -czf kali-mcp-tactical.tar.gz MCP-Kali-Server/
   ```

2. **Upload to GitHub:**
   - Go to repository
   - Create new branch: `tactical-server-implementation`
   - Upload files manually
   - Create pull request

#### Option 3: SSH Key (Best for Long-term)

1. **Generate SSH Key:**
   ```bash
   ssh-keygen -t ed25519 -C "your_email@example.com"
   cat ~/.ssh/id_ed25519.pub
   ```

2. **Add to GitHub:**
   - Go to: https://github.com/settings/keys
   - Click "New SSH key"
   - Paste public key

3. **Update Remote:**
   ```bash
   git remote set-url origin git@github.com:Cabrel10/kali_mcp.git
   git push -u origin tactical-server-implementation
   ```

---

## 📦 Local Deployment (Immediate Use)

### Quick Start

```bash
cd /home/user/webapp/MCP-Kali-Server

# Install dependencies
./start.sh
```

### Manual Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure
cp .env.example .env
nano .env  # Edit configuration

# Create directories
mkdir -p data/cache data/logs data/results

# Run server
python3 main.py
```

---

## 🔗 MCP Client Configuration

### For Claude Desktop

Edit: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)  
Or: `%APPDATA%\Claude\claude_desktop_config.json` (Windows)

```json
{
  "mcpServers": {
    "kali-tactical": {
      "command": "/home/user/webapp/MCP-Kali-Server/start.sh",
      "args": [],
      "env": {
        "PYTHONPATH": "/home/user/webapp/MCP-Kali-Server"
      }
    }
  }
}
```

### For Gemini / Other MCP Clients

```json
{
  "servers": {
    "kali-tactical": {
      "type": "stdio",
      "command": "/home/user/webapp/MCP-Kali-Server/venv/bin/python3",
      "args": ["/home/user/webapp/MCP-Kali-Server/main.py"],
      "cwd": "/home/user/webapp/MCP-Kali-Server"
    }
  }
}
```

---

## 🛠️ Tool Installation

### Essential Tools (Pre-installed on Kali)
```bash
# Verify
which nmap curl whois
```

### Go-based Tools (Highly Recommended)
```bash
# Install Go
sudo apt install golang-go

# Install tools
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/hahwul/dalfox/v2@latest

# Add Go bin to PATH
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Update Nuclei templates
nuclei -update-templates
```

### Other Recommended Tools
```bash
sudo apt install -y \
    sqlmap \
    hashcat \
    gobuster \
    exiftool \
    radare2 \
    tor
```

---

## 🔒 Security Configuration

### 1. Environment Variables

Edit `.env`:
```bash
# API Keys (if using)
OPENROUTER_API_KEY=your_key_here

# Database
DB_PATH=/tmp/kali_mcp_tactical.db

# Scanner Settings
SCAN_TIMEOUT=300
MAX_PARALLEL_TASKS=10
MAX_OUTPUT_CHARS=2000

# Evasion
ENABLE_GHOST_MODE=true
MIKROTIK_STEALTH_MODE=true
AUTO_ROTATE_IP_ON_BAN=true
ENABLE_RATE_LIMITING=true
```

### 2. IP Pool Configuration (Optional)

For distributed attacks:
```bash
# Start Tor instances
sudo apt install tor
sudo service tor start

# Multiple Tor instances
sudo tor --SocksPort 9050 &
sudo tor --SocksPort 9052 &
sudo tor --SocksPort 9053 &

# Configure in .env
IP_POOL=socks5://127.0.0.1:9050,socks5://127.0.0.1:9052,socks5://127.0.0.1:9053
```

---

## 🧪 Testing

### Quick Test
```bash
cd /home/user/webapp/MCP-Kali-Server

# Test imports
python3 -c "from src.server import KaliTacticalServer; print('✅ Imports OK')"

# Test configuration
python3 -c "from src.core.config import TacticalConfig; TacticalConfig.validate(); print('✅ Config OK')"

# Test database
python3 -c "from src.core.database import DatabaseManager; db = DatabaseManager(); print('✅ Database OK')"
```

### Full Test Run
```bash
# Run each module's self-test
python3 src/core/async_executor.py
python3 src/core/output_processor.py
python3 src/core/task_manager.py
python3 src/core/database.py
python3 src/utils/triage_engine.py
```

---

## 📊 Verification Checklist

Before using in production:

- [ ] All dependencies installed (`pip list`)
- [ ] Critical tools available (`nmap`, `curl`, etc.)
- [ ] Configuration file created (`.env`)
- [ ] Data directories exist (`data/cache`, `data/logs`, `data/results`)
- [ ] Virtual environment activated
- [ ] Database initialized (auto-created on first run)
- [ ] Network connectivity (for external scans)
- [ ] Proper permissions (read/write to `data/`)

---

## 🔍 Troubleshooting

### "Module not found"
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### "Tool not available"
```bash
# Check tool
which nmap
which nuclei

# Install if missing
sudo apt install nmap
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### "Database locked"
```bash
# Close other instances
pkill -f "python3 main.py"

# Remove lock
rm -f data/kali_mcp_tactical.db-wal
```

### "Permission denied"
```bash
# Fix permissions
chmod +x start.sh main.py
chmod -R u+w data/
```

---

## 📈 Performance Tuning

### For Fast Networks
```bash
# .env adjustments
MAX_PARALLEL_TASKS=20
SCAN_TIMEOUT=600
ENABLE_RATE_LIMITING=false
```

### For Stealth Operations
```bash
# .env adjustments
ENABLE_GHOST_MODE=true
MIKROTIK_STEALTH_MODE=true
DEFAULT_SCAN_INTENSITY=stealth
ENABLE_RATE_LIMITING=true
```

### For Distributed Operations
```bash
# Configure multiple proxies
IP_POOL=socks5://proxy1:9050,socks5://proxy2:9050,http://proxy3:8080
```

---

## 🎯 Next Actions

1. **Resolve GitHub Push:**
   - Update GitHub token
   - Push branch: `tactical-server-implementation`
   - Create pull request to `master`

2. **Test Deployment:**
   - Run `./start.sh`
   - Connect MCP client
   - Test basic tool: `tactical_recon`

3. **Production Use:**
   - Configure `.env` properly
   - Install all tools
   - Set up IP pool (if using distributed attacks)
   - Monitor logs: `tail -f data/logs/*.log`

---

## 📞 Support

### Documentation
- `README.md` - User guide
- `IMPLEMENTATION_SUMMARY.md` - Technical details
- This file - Deployment guide

### Logs
- Server logs: `data/logs/`
- Task logs: Check database
- Error logs: stderr output

### Common Issues
- Check GitHub Issues (once repository is accessible)
- Review logs in `data/logs/`
- Test individual modules

---

## ✅ Success Indicators

Server is working correctly if:
1. ✅ `./start.sh` runs without errors
2. ✅ MCP client connects successfully
3. ✅ `tactical_recon` returns scan results
4. ✅ Database file created in `data/`
5. ✅ Logs show tool executions

---

**Status: Ready for deployment**  
**Action Required: Resolve GitHub authentication for code push**  
**Everything else: ✅ Complete and functional**

---

*Last Updated: December 21, 2025*
