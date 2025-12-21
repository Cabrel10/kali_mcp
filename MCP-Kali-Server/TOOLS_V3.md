# Kali MCP Server v3 - Advanced Pentest Tools

## Overview
Version 3 du serveur MCP Kali avec des outils optimisés pour les tests d'intrusion avancés, une meilleure gestion des erreurs, et des payloads intégrés.

## Améliorations v3
- ✅ Meilleure gestion des timeouts et erreurs
- ✅ Payloads intégrés pour SQLi, XSS, LFI, RCE, SSTI, XXE
- ✅ Parsing avancé des résultats
- ✅ Logging structuré de toutes les opérations
- ✅ Support des sessions pour organiser les résultats
- ✅ Génération de reverse shells
- ✅ Détection automatique des vulnérabilités

## Outils Disponibles

### 🔧 Core Tools
| Outil | Description |
|-------|-------------|
| `start_session` | Démarre une session de pentest |
| `server_health` | Vérifie l'état du serveur et outils disponibles |
| `execute_command` | Exécute une commande shell arbitraire |

### 🔍 Network Reconnaissance
| Outil | Description |
|-------|-------------|
| `nmap_scan` | Scan réseau avancé (quick, basic, comprehensive, stealth, vuln, udp, aggressive) |
| `arp_scan` | Découverte d'hôtes sur le réseau local |

### 🌐 Web Application Scanning
| Outil | Description |
|-------|-------------|
| `gobuster_scan` | Enumération de répertoires/DNS/vhosts |
| `nikto_scan` | Scan de vulnérabilités web |
| `ffuf_fuzz` | Fuzzing web rapide |
| `wpscan_audit` | Audit de sécurité WordPress |
| `nuclei_scan` | Scan de vulnérabilités avec templates |
| `web_tech_detect` | Détection des technologies web |

### 💉 Injection Testing
| Outil | Description |
|-------|-------------|
| `sqlmap_scan` | Test SQLi automatisé avec SQLMap |
| `sql_injection_test` | Test SQLi manuel avec payloads personnalisés |
| `xss_scan` | Test XSS avec détection de réflexion |
| `lfi_scan` | Test LFI avec bypass d'encodage |
| `command_injection_test` | Test d'injection de commandes |

### 🔐 Brute Force & Cracking
| Outil | Description |
|-------|-------------|
| `hydra_attack` | Attaque brute force multi-protocoles |
| `john_crack` | Cracking de mots de passe |

### 🎯 Exploitation
| Outil | Description |
|-------|-------------|
| `metasploit_exploit` | Exécution de modules Metasploit |
| `reverse_shell_generator` | Génération de reverse shells (bash, python, php, etc.) |

### 🌍 DNS & Subdomain
| Outil | Description |
|-------|-------------|
| `subdomain_enum` | Enumération de sous-domaines (subfinder, amass) |
| `dns_recon` | Reconnaissance DNS et test de zone transfer |

### 🖥️ Windows/SMB
| Outil | Description |
|-------|-------------|
| `enum4linux_scan` | Enumération Windows/Samba |

### 🛠️ Utilities
| Outil | Description |
|-------|-------------|
| `get_payloads` | Récupère des payloads pré-construits |

## Payloads Intégrés

### SQL Injection
- Generic, MySQL, MSSQL, PostgreSQL
- Union-based, Error-based, Time-based, Boolean-based
- Bypass techniques inclus

### XSS
- Reflected, Stored, DOM-based
- Encodage HTML, JavaScript, Unicode
- Bypass de filtres

### LFI
- Path traversal standard
- URL encoding, Double encoding
- PHP wrappers (filter, input, data)
- Null byte injection

### Command Injection
- Séparateurs: `;`, `|`, `||`, `&&`, `&`
- Substitution: `` `cmd` ``, `$(cmd)`
- Reverse shells intégrés

### SSTI
- Jinja2, Twig, Freemarker
- Python, Java, Ruby templates

### XXE
- File disclosure
- SSRF via XXE
- Out-of-band exfiltration

## Exemples d'Utilisation

### Scan Nmap Complet
```
nmap_scan(target="192.168.1.1", scan_type="comprehensive", intensity="high")
```

### Test SQLi
```
sql_injection_test(url="http://target.com/page.php", param="id", db_type="mysql")
```

### Génération Reverse Shell
```
reverse_shell_generator(lhost="10.0.0.1", lport=4444, shell_type="python3")
```

### Enumération Sous-domaines
```
subdomain_enum(domain="example.com", tools=["subfinder", "amass"])
```

## Configuration Gemini CLI

Le serveur est configuré dans `.gemini/settings.json`:
```json
{
  "mcpServers": {
    "kali-tools": {
      "command": "/home/morningstar/miniconda3/envs/trading_env/bin/python3",
      "args": ["/path/to/kali_mcp_server_v3.py"],
      "timeout": 900000,
      "trust": true
    }
  }
}
```

## Notes de Sécurité
⚠️ Ces outils sont destinés uniquement aux tests de sécurité autorisés.
⚠️ Utilisez uniquement sur des systèmes pour lesquels vous avez une autorisation explicite.
