# Kali MCP Server v6.3 — Synthese & Guide d'Utilisation

## Synthese de l'Architecture

### Vue d'ensemble

Le Kali MCP Server v6.3 est un **moteur de pentest autonome** qui consolide 72 outils fragmentes en **27 mega-modules interconnectes**. Chaque module est parametre par profondeur (`stealth|light|deep|aggressive`), s'auto-adapte a la cible, et partage ses decouvertes avec tous les autres modules via un systeme de memoire centralisee.

### Les 4 couches

```
COUCHE 4 — STEALTH (protection de l'opérateur)
  StealthConfig | ProxyRotation | BanDetection | UniversalCommandAdapt
  Adapte automatiquement: nmap, curl, nikto, sqlmap, hydra, gobuster, ffuf, nuclei, wpscan

COUCHE 3 — INTELLIGENCE (analyse, correlation, decision)
  CVSSCalculator | VulnCorrelator | KillChainTracker | DeepOutputParser | ParallelExecutor
  ProtocolAnalyzer | SmartFuzzer | NetworkIntelligence | ExploitAdvisor

COUCHE 2 — 27 MEGA-MODULES (execution)
  recon | web | injection | creds | network | wireless | cloud | AD | api
  vuln_scanner | exploit | auth | ssrf | crypto | osint | post_exploit
  reporting | autopilot | session | payload | forensics | race_condition
  protocol_deep_scan | smart_fuzz | honeypot_detector | auto_exploit | web_interactor

COUCHE 1 — INFRASTRUCTURE (memoire, orchestration, securite)
  PentestMemory | RateLimitDetector | IntelligentOrchestrator | SessionManager | InputValidator
```

### Flux de donnees inter-modules

```
       [recon_engine] + [protocol_deep_scan]
                    |
             services detectes + OS fingerprint
                    |
   +--------+--------+--------+---------+
   |        |        |        |         |
[web]   [network] [cloud]  [api]  [honeypot_detector]
   |        |        |        |         |
   v        v        v        v         v
  findings → PentestMemory → [smart_fuzz_engine]
                    |
             VulnCorrelator + ExploitAdvisor
                    |
         exploit chains detectees
                    |
     [autopilot] + [auto_exploit]
                    |
        +----------+-----------+----------+
        |          |           |          |
  [injection]  [creds]    [ssrf]    [web_interactor]
        |          |           |          |
        v          v           v          v
   VulnFindings → CVSS → KillChain → [reporting_engine]
                                          |
                              rapport executif + technique
```

---

## Guide d'Utilisation par Scenario

### Scenario 1: Configuration Stealth (NOUVEAU v6.3)

Le systeme de furtivite protege l'operateur a chaque niveau :

```python
# Activer le niveau 2 (Enhanced)
await session_ops(action="stealth_set", session_name="2")

# Configurer un pool de proxies (IP jamais exposee)
await session_ops(action="stealth_proxy_pool",
    target='["socks5://p1:1080","socks5://p2:1080","socks5://p3:1080"]')

# Verifier le status
await session_ops(action="stealth_status")
# Retourne: level=2, adapted_tools=[nmap,curl,nikto,sqlmap,hydra,gobuster,ffuf,nuclei,wpscan]

# Rotation manuelle de proxy (après un ban)
await session_ops(action="stealth_proxy_rotate")

# Verifier si une sortie indique un ban
await session_ops(action="stealth_ban_check", target="Access Denied - Your IP blocked")

# Toutes les commandes sont maintenant auto-adaptees :
# nmap: -T1 --scan-delay 1s --randomize-hosts --proxies socks5://...
# curl: -A 'Mozilla/5.0 ...' --proxy socks5://...
# sqlmap: --random-agent --delay=2 --proxy socks5://...
# nikto: -Pause 2 -Tuning x -useproxy socks5://...
# hydra: -W 5 -c 3
```

### Scenario 2: Web Interactor — Test Browser Reel (NOUVEAU v6.3)

```python
# Test XSS en navigateur reel (pas juste reflection HTTP)
result = await web_interactor(
    url="https://target.com/search?q=test",
    actions="navigate,xss_test,session_test",
    stealth_level=2,
    screenshot=True,
)
# Retourne:
# - XSS payloads testees dans Chromium headless
# - Preuve d'execution (titre change, console alert, payload refletee)
# - Analyse securite des cookies (HttpOnly, Secure, SameSite)
# - Capture d'ecran en base64

# Remplir un formulaire + soumettre
result = await web_interactor(
    url="https://target.com/login",
    actions="navigate,fill_form,click,extract",
    form_data='{"#user": "admin", "#pass": "test"}',
    selectors='["button[type=submit]"]',
    wait_for="#dashboard",
    screenshot=True,
)
# Retourne: CSRF token extrait, formulaire rempli, page apres submit, cookies

# Extraire des donnees specifiques
result = await web_interactor(
    url="https://target.com/admin",
    actions="navigate,extract",
    extract_data="table tr, .user-email, #api-key",
)
# Retourne: tous les textes des selecteurs CSS specifies
```

**Protection anti-bot integree :**
- `navigator.webdriver = undefined`
- Rotation viewport/locale/timezone
- Canvas fingerprint noise
- Proxy automatique (jamais d'IP reelle)
- Detection de ban + rotation proxy auto

### Scenario 3: Pentest Complet Autonome

```python
result = await autopilot_commander(
    target="10.10.10.100",
    depth="deep",
    scope="full",
    aggressive=False,
    max_duration=3600
)
```

**Ce qui se passe en interne :**
1. Phase 1 — Recon sequentiel (nmap + protocol_deep_scan natif)
2. Phase 2 — Scan parallele (web + api + network + cloud + osint)
3. Phase 3 — honeypot_detector verifie la cible
4. Phase 4 — smart_fuzz_engine + vuln_scanner
5. Phase 5 — Attaques ciblees via VulnCorrelator + auto_exploit
6. Phase 6 — Post-exploitation si score >= 50
7. Phase 7 — Rapport intelligence complet (MITRE + kill chain + exploit chains)

### Scenario 4: Protocol Intelligence (NOUVEAU v6.2+)

```python
# Analyse TCP/TLS/HTTP native (sans nmap)
result = await protocol_deep_scan(target="10.0.0.1", depth="deep", timeout=30)
# Retourne: OS fingerprint (TTL), WAF detection, TLS version/cipher,
#           technologies detectees, security headers

# Fuzzing intelligent avec baseline
result = await smart_fuzz_engine(
    target="https://api.target.com/users",
    depth="deep",
    timeout=60,
)
# Retourne: parametres decouverts, payloads envoyes, anomalies detectees,
#           comparaison vs baseline (taille, temps, code erreur)
```

### Scenario 5: Detection de Honeypots + Auto-Exploitation

```python
# Verifier si la cible est un honeypot AVANT d'engager
result = await honeypot_detector(target="suspicious-host.com", depth="deep")
# Retourne: score 0-100, verdict (CLEAN/LOW_RISK/SUSPICIOUS/LIKELY_HONEYPOT)
# 7 sous-modules: banner, timing, behavioral, protocol_anomaly, signature, network, consistency

# Auto-exploitation basee sur les vulns deja trouvees
result = await auto_exploit(target="10.0.0.1", strategy="safe_check")
# Sous-modules: msf_auto, sqlmap_auto, hydra_auto, web_exploit, custom_chain, privesc_suggest
# Genere: configs Metasploit RC, commandes sqlmap, commandes hydra
# Chains: LFI→RCE, SSTI→RCE (Jinja2/Twig), SSRF→Cloud, XSS→Session
# Privesc: SUID, kernel, sudo, cron, Docker, capabilities, LinPEAS/WinPEAS
```

### Scenario 6: Audit WiFi Complet (Monitor → Crack → Pivot)

```python
result = await wireless_audit(
    interface="wlan0",
    target_bssid="AA:BB:CC:DD:EE:FF",
    depth="aggressive",
    modules="all",
    wordlist="auto"
)
```

### Scenario 7: Forensics & Detection de Malware

```python
result = await forensics_engine(
    target="192.168.1.50",
    modules="all",
    depth="deep",
    timeout=600
)
```

### Scenario 8: Crypto-Forensics Avancee

```python
# Identifier un hash inconnu
result = await crypto_forensics(target="$2b$12$LJ3m4ys3Lg...", modules="hash_id")

# Analyser et dechiffrer un fichier
result = await crypto_forensics(target="/path/to/encrypted", modules="cipher_analysis,decrypt")

# Audit TLS complet
result = await crypto_forensics(target="vulnerable-site.com", modules="tls_audit", depth="aggressive")
```

---

## Commandes Rapides

```bash
# Demarrer le serveur MCP
python kali_mcp_server.py

# Lancer tous les tests (80)
python test_all_tools.py

# Installer les dependances
pip install -r requirements.txt
playwright install chromium

# Pentest rapide stealth
await recon_engine(target="10.10.10.100", depth="stealth")

# Scan web avec stealth auto
await session_ops(action="stealth_set", session_name="2")
await web_assault(target="https://target.com", depth="deep")

# Test XSS en browser reel
await web_interactor(url="https://target.com?q=test", actions="xss_test", screenshot=True)
```

---

## Niveaux de Profondeur

| Niveau | Comportement |
|--------|-------------|
| `stealth` | Scan lent, pas de brute force, pas de deauth, logs minimaux |
| `light` | Scan standard, top 1000 ports, wordlists courtes |
| `deep` | Scan complet (all ports), brute force, deauth WiFi, NSE scripts |
| `aggressive` | Tout + exploitation active, mask attacks hashcat, attaques paralleles massives |

---

## Dependances

### Obligatoire
- Python 3.10+
- `pip install -r requirements.txt`

### Recommande (Kali Linux)
Tous ces outils sont pre-installes sur Kali Linux :
- **Recon** : nmap, whatweb, dig, whois, subfinder, amass
- **Web** : nikto, gobuster, ffuf, sqlmap, nuclei, wpscan
- **Creds** : hashcat, john, hydra
- **Network** : bettercap, responder, impacket-suite
- **Wireless** : aircrack-ng, hcxdumptool, hcxtools, wpa_supplicant
- **AD** : bloodhound-python, certipy-ad
- **Exploit** : metasploit-framework, ysoserial
- **Forensics** : volatility, chkrootkit, rkhunter, yara
- **Crypto** : testssl.sh, sslscan, openssl
- **Cloud** : aws-cli, gcloud
- **Browser** : playwright (chromium)

---

## Architecture des Fichiers

```
MCP-Kali-Server/
  kali_mcp_server.py        # 8462 lignes — serveur complet (27 modules + 20+ classes)
  protocol_intelligence.py   # 1721 lignes — 4 classes analyse protocoles
  test_all_tools.py          # ~700 lignes — 80 tests (10 sections)
  requirements.txt           # Dependances Python
  README.md                  # Documentation technique complete
  GUIDE.md                   # Ce guide (synthese + utilisation)
  kali_mcp_server_v4_backup.py  # Backup de l'ancienne v4
  .gitignore
```

---

*Kali MCP Server v6.3 — Autonomous Pentest Engine + Web Interactor*
*27 modules | 20+ classes | 80 tests | 10,183 lines*
*Compatible: fastmcp 2.x + 3.x*
*Par Cabrel10 / MorningStar*
