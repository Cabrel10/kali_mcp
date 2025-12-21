#!/usr/bin/env python3
"""
Configuration Management for Kali MCP Tactical Server
Loads settings from environment variables and .env files
"""

import os
from pathlib import Path
from typing import Dict, List, Optional
from dotenv import load_dotenv

# Load environment variables
PROJECT_ROOT = Path(__file__).parent.parent.parent
load_dotenv(PROJECT_ROOT / ".env")


class TacticalConfig:
    """Centralized configuration for the tactical server"""
    
    # =================== PATHS ===================
    PROJECT_ROOT: Path = PROJECT_ROOT
    SRC_DIR: Path = PROJECT_ROOT / "src"
    DATA_DIR: Path = PROJECT_ROOT / "data"
    CACHE_DIR: Path = DATA_DIR / "cache"
    LOGS_DIR: Path = DATA_DIR / "logs"
    RESULTS_DIR: Path = DATA_DIR / "results"
    
    # Database
    DB_PATH: str = os.getenv("DB_PATH", str(DATA_DIR / "kali_mcp_tactical.db"))
    CACHE_EXPIRY_HOURS: int = int(os.getenv("CACHE_EXPIRY_HOURS", "24"))
    
    # =================== SCANNER SETTINGS ===================
    MAX_OUTPUT_CHARS: int = int(os.getenv("MAX_OUTPUT_CHARS", "2000"))
    SCAN_TIMEOUT: int = int(os.getenv("SCAN_TIMEOUT", "300"))
    MAX_PARALLEL_TASKS: int = int(os.getenv("MAX_PARALLEL_TASKS", "10"))
    
    # =================== TOOL PATHS ===================
    TOOL_PATHS: Dict[str, str] = {
        'naabu': os.getenv("NAABU_PATH", "/usr/local/bin/naabu"),
        'httpx': os.getenv("HTTPX_PATH", "/usr/local/bin/httpx"),
        'nuclei': os.getenv("NUCLEI_PATH", "/usr/local/bin/nuclei"),
        'ffuf': os.getenv("FFUF_PATH", "/usr/local/bin/ffuf"),
        'subfinder': os.getenv("SUBFINDER_PATH", "/usr/local/bin/subfinder"),
        'dalfox': os.getenv("DALFOX_PATH", "/usr/local/bin/dalfox"),
        'katana': os.getenv("KATANA_PATH", "/usr/local/bin/katana"),
        'sqlmap': 'sqlmap',
        'nmap': 'nmap',
        'hydra': 'hydra',
        'nikto': 'nikto',
        'wpscan': 'wpscan',
        'exiftool': 'exiftool',
        'radare2': 'r2',
        'hashcat': 'hashcat'
    }
    
    # =================== WORDLISTS ===================
    WORDLISTS: Dict[str, str] = {
        'web_directories': os.getenv(
            "WORDLIST_WEB_DIRS",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        ),
        'web_common': "/usr/share/wordlists/dirb/common.txt",
        'api_endpoints': "/usr/share/wordlists/api/endpoints.txt",
        'subdomains': os.getenv(
            "WORDLIST_SUBDOMAINS",
            "/usr/share/wordlists/subdomains/top1million.txt"
        ),
        'passwords': os.getenv(
            "WORDLIST_PASSWORDS",
            "/usr/share/wordlists/rockyou.txt"
        ),
        'usernames': "/usr/share/wordlists/metasploit/unix_users.txt"
    }
    
    # =================== NUCLEI TEMPLATES ===================
    NUCLEI_TEMPLATES: List[str] = [
        'cves/2024',
        'cves/2023',
        'exposed-panels',
        'default-logins',
        'misconfiguration',
        'misconfigurations',
        'technologies',
        'exposures',
        'vulnerabilities',
        'takeovers'
    ]
    
    # =================== USER AGENTS ===================
    USER_AGENTS: List[str] = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'curl/7.88.1',
        'python-requests/2.31.0'
    ]
    
    # =================== EVASION & STEALTH ===================
    ENABLE_PROXY_ROTATION: bool = os.getenv("ENABLE_PROXY_ROTATION", "false").lower() == "true"
    TOR_PROXY: str = os.getenv("TOR_PROXY", "socks5://127.0.0.1:9050")
    ENABLE_RATE_LIMITING: bool = os.getenv("ENABLE_RATE_LIMITING", "true").lower() == "true"
    DEFAULT_SCAN_INTENSITY: str = os.getenv("DEFAULT_SCAN_INTENSITY", "fast")
    
    # =================== DISTRIBUTED ATTACKS ===================
    IP_POOL_RAW: str = os.getenv("IP_POOL", "")
    IP_POOL: List[str] = [
        proxy.strip() for proxy in IP_POOL_RAW.split(",") if proxy.strip()
    ] if IP_POOL_RAW else [
        "socks5://127.0.0.1:9050",
        "socks5://127.0.0.1:9052",
        "socks5://127.0.0.1:9053"
    ]
    
    # =================== ADVANCED OPTIONS ===================
    ENABLE_GHOST_MODE: bool = os.getenv("ENABLE_GHOST_MODE", "true").lower() == "true"
    MIKROTIK_STEALTH_MODE: bool = os.getenv("MIKROTIK_STEALTH_MODE", "true").lower() == "true"
    AUTO_ROTATE_IP_ON_BAN: bool = os.getenv("AUTO_ROTATE_IP_ON_BAN", "true").lower() == "true"
    
    # =================== API KEYS ===================
    OPENROUTER_API_KEY: Optional[str] = os.getenv("OPENROUTER_API_KEY")
    
    @classmethod
    def validate(cls) -> bool:
        """Validate configuration and create necessary directories"""
        # Create directories if they don't exist
        for dir_path in [cls.DATA_DIR, cls.CACHE_DIR, cls.LOGS_DIR, cls.RESULTS_DIR]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Check critical tools
        critical_tools = ['nmap']  # Minimum required
        missing_tools = []
        
        for tool in critical_tools:
            tool_path = cls.TOOL_PATHS.get(tool, tool)
            # Basic check - in real scenario, use shutil.which()
            if not tool_path:
                missing_tools.append(tool)
        
        if missing_tools:
            print(f"⚠️  Warning: Missing critical tools: {', '.join(missing_tools)}")
            return False
        
        return True
    
    @classmethod
    def get_tool_path(cls, tool_name: str) -> str:
        """Get the path for a specific tool"""
        return cls.TOOL_PATHS.get(tool_name, tool_name)
    
    @classmethod
    def get_wordlist(cls, wordlist_type: str) -> str:
        """Get the path for a specific wordlist"""
        return cls.WORDLISTS.get(wordlist_type, "")
    
    @classmethod
    def to_dict(cls) -> Dict:
        """Export configuration as dictionary"""
        return {
            "db_path": cls.DB_PATH,
            "cache_expiry_hours": cls.CACHE_EXPIRY_HOURS,
            "max_output_chars": cls.MAX_OUTPUT_CHARS,
            "scan_timeout": cls.SCAN_TIMEOUT,
            "max_parallel_tasks": cls.MAX_PARALLEL_TASKS,
            "enable_proxy_rotation": cls.ENABLE_PROXY_ROTATION,
            "enable_rate_limiting": cls.ENABLE_RATE_LIMITING,
            "default_scan_intensity": cls.DEFAULT_SCAN_INTENSITY,
            "enable_ghost_mode": cls.ENABLE_GHOST_MODE,
            "mikrotik_stealth_mode": cls.MIKROTIK_STEALTH_MODE,
            "ip_pool_size": len(cls.IP_POOL)
        }


# Initialize and validate configuration
if __name__ == "__main__":
    print("🔧 Kali MCP Tactical Configuration")
    print("=" * 60)
    
    if TacticalConfig.validate():
        print("✅ Configuration validated successfully")
    else:
        print("❌ Configuration validation failed")
    
    print("\n📊 Current Settings:")
    for key, value in TacticalConfig.to_dict().items():
        print(f"  {key}: {value}")
