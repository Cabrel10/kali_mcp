#!/usr/bin/env python3
"""
Extraction de la structure API depuis le bundle JavaScript
skillmoney.8unb.xyz
"""

import re
import json
import asyncio
import sys
sys.path.insert(0, '/home/morningstar/Bureau/kali_mcp/MCP-Kali-Server')

async def extract_api_from_js():
    """Extraire endpoints API du bundle JS"""
    
    from kali_mcp_server import run_command_shell
    
    print("""
    ╔═══════════════════════════════════════════╗
    ║   EXTRACTION ENDPOINTS API              ║
    ║   From: index-jipedxTS.js               ║
    ╚═══════════════════════════════════════════╝
    """)
    
    # Télécharger le bundle JS
    print("\n[*] Téléchargement du bundle JavaScript...")
    
    cmd_download = """curl -s https://skillmoney.8unb.xyz/assets/index-jipedxTS.js -o /tmp/bundle.js && \\
    wc -l /tmp/bundle.js && file /tmp/bundle.js"""
    
    result = await run_command_shell(cmd_download, timeout=30)
    print(result.get('stdout', 'Download failed'))
    
    # Extraire patterns API
    print("\n[*] Extraction patterns API...")
    
    patterns = [
        # URLs
        r'["\'`]/(api|api/v\d+)/[^"\'`\s]+["\'`]',
        # Fetch/axios calls
        r'(fetch|axios|request)\(["\']([^"\']+)["\']',
        # Socket endpoints
        r'(socket\.on|socket\.emit|addEventListener)\(["\']([^"\']+)["\']',
        # Backend URLs
        r'["\'`]https?://[^"\'`\s]+["\'`]',
        # API keys patterns
        r'(api[_-]?key|authorization|bearer|token)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    
    for pattern_name, pattern in [
        ("API Routes", r'["\'`]/(api|auth|user|register|login)[^"\'`\s]*["\'`]'),
        ("SPA Hash Routes", r'["\'`]/#/[a-zA-Z0-9/_-]+["\'`]'),
        ("HTTP Requests", r'(fetch|axios|request)\(["\']([^"\']+)["\']'),
        ("Base URLs", r'["\'`]https?://[^"\'`]+?\.xyz[^"\'`\s]*["\'`]'),
        ("path/route patterns", r'["\'`](path|route)["\']?\s*[:=]\s*["\']([^"\']+)["\']'),
    ]:
        print(f"\n  Searching for: {pattern_name}")
        
        cmd_grep = f"""grep -o '{pattern}' /tmp/bundle.js 2>/dev/null | sort | uniq | head -30"""
        
        result_grep = await run_command_shell(cmd_grep, timeout=15)
        if result_grep.get('stdout'):
            matches = result_grep['stdout'].strip().split('\n')
            for match in matches:
                if match and len(match) > 2:
                    print(f"    ✓ {match}")
    
    # Recherche plus spécifique
    print("\n[*] Recherche endpoints critiques...")
    
    critical_endpoints = [
        "register", "login", "logout", "auth", "user", "profile",
        "balance", "withdraw", "deposit", "tasks", "referral",
        "verify", "otp", "2fa", "reset", "password", "dashboard",
        "settings", "wallet", "transfer", "history", "invoice"
    ]
    
    for endpoint in critical_endpoints:
        cmd_search = f"""grep -Eio '(/#/)?([a-z/]*{endpoint}[a-z/]*)' /tmp/bundle.js 2>/dev/null | sort | uniq | head -10"""
        
        result_search = await run_command_shell(cmd_search, timeout=10)
        if result_search.get('stdout'):
            matches = result_search['stdout'].strip().split('\n')
            found_matches = [m for m in matches if m and len(m) > 2 and endpoint in m.lower()]
            if found_matches:
                print(f"\n  /{endpoint}:")
                for match in found_matches[:5]:
                    print(f"    - {match}")
    
    # Extraire domaines/IPs et endpoints découverts
    print("\n[*] Domaines/IPs et sous-domaines détectés...")
    
    cmd_domains = """grep -Eio '(https?://[a-zA-Z0-9.:-]+|[a-z0-9.-]+\\.(com|xyz|io|dev|app|net)|[a-z0-9-]+\\.[a-z0-9.-]+)' /tmp/bundle.js 2>/dev/null | sort | uniq | head -50"""
    
    result_domains = await run_command_shell(cmd_domains, timeout=15)
    if result_domains.get('stdout'):
        domains = set(result_domains['stdout'].strip().split('\n'))
        print(f"  Found {len(domains)} unique domains/subdomains:")
        for domain in sorted(list(domains))[:25]:
            if domain and len(domain) > 3:
                print(f"    - {domain}")
    
    # Extraire routes/paths
    print("\n[*] Routes et paths détectés...")
    
    cmd_routes = """grep -Eio '/#/[a-zA-Z0-9/_-]+|/api[a-zA-Z0-9/_-]*|/(auth|user|dashboard|wallet|admin|settings)[a-zA-Z0-9/_-]*' /tmp/bundle.js 2>/dev/null | sort | uniq | head -50"""
    
    result_routes = await run_command_shell(cmd_routes, timeout=15)
    if result_routes.get('stdout'):
        routes = set(result_routes['stdout'].strip().split('\n'))
        print(f"  Found {len(routes)} unique routes/paths:")
        for route in sorted(list(routes))[:30]:
            if route and len(route) > 2:
                print(f"    - {route}")
    
    # Statut des clés API/secrets
    print("\n[*] Recherche credentials/keys...")
    
    cmd_keys = """grep -Eio '(api[_-]?key|secret|token|password|auth)["\']?\\s*[=:]["\']?[a-zA-Z0-9._-]{10,}' /tmp/bundle.js 2>/dev/null | head -10"""
    
    result_keys = await run_command_shell(cmd_keys, timeout=10)
    if result_keys.get('stdout'):
        print(f"  Potential credentials found:")
        keys = result_keys['stdout'].strip().split('\n')
        for key in keys[:5]:
            if key and len(key) > 5:
                # Masquer les valeurs réelles
                masked = re.sub(r'[a-zA-Z0-9._-]{8,}$', '[REDACTED]', key)
                print(f"    ! {masked}")
    else:
        print(f"  No credentials found (good sign!)")
    
    print("\n" + "="*60)
    print("✓ Extraction complétée")
    print("\n[*] Cleanup...")
    cmd_clean = "rm -f /tmp/bundle.js"
    await run_command_shell(cmd_clean, timeout=5)
    
    print("\n✓ Prêt pour tests manuels d'API")

if __name__ == "__main__":
    asyncio.run(extract_api_from_js())
