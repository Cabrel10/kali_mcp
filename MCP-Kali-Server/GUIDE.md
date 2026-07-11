# Kali MCP Server v6.2 — Synthese & Guide d'Utilisation

## Synthese de l'Architecture

### Vue d'ensemble

Le Kali MCP Server v6.2 est un **moteur de pentest autonome** qui consolide 72 outils fragmentes en **22 mega-modules interconnectes**. Chaque module est parametre par profondeur (`stealth|light|deep|aggressive`), s'auto-adapte a la cible, et partage ses decouvertes avec tous les autres modules via un systeme de memoire centralisee.

### Les 3 couches

```
COUCHE 3 — INTELLIGENCE (analyse, correlation, decision)
  CVSSCalculator | VulnCorrelator | KillChainTracker | DeepOutputParser | ParallelExecutor

COUCHE 2 — 22 MEGA-MODULES (execution)
  recon | web | injection | creds | network | wireless | cloud | AD | api
  vuln_scanner | exploit | auth | ssrf | crypto | osint | post_exploit
  reporting | autopilot | session | payload | forensics | race_condition

COUCHE 1 — INFRASTRUCTURE (memoire, orchestration, securite)
  PentestMemory | RateLimitDetector | IntelligentOrchestrator | SessionManager | InputValidator
```

### Flux de donnees inter-modules

```
       [recon_engine]
            |
     services detectes
            |
   +--------+--------+--------+
   |        |        |        |
[web]   [network] [cloud]  [api]
   |        |        |        |
   v        v        v        v
  findings → PentestMemory (stockage centralise)
                    |
             VulnCorrelator
                    |
         exploit chains detectees
                    |
     [autopilot] decide les prochaines attaques
                    |
        +----------+----------+
        |          |          |
  [injection]  [creds]   [ssrf]
        |          |          |
        v          v          v
   VulnFindings → CVSS scoring → KillChain tracking
                    |
             [reporting_engine]
                    |
        rapport executif + technique
```

---

## Guide d'Utilisation par Scenario

### Scenario 1: Pentest Complet Autonome

Le module `autopilot_commander` orchestre automatiquement tout le processus.

```python
# Lancer un pentest complet
result = await autopilot_commander(
    target="10.10.10.100",
    depth="deep",
    scope="full",
    aggressive=False,
    max_duration=3600
)
```

**Ce qui se passe en interne :**
1. Phase 1 — Recon sequentiel (nmap, whatweb, DNS)
2. Phase 2 — Scan parallele (web_assault + api_breaker + network_dominator + cloud_siege + osint)
3. Phase 3 — Scan vuln parallele + test auth
4. Phase 4 — Attaques ciblees basees sur la correlation (injection si SQLi potentiel, creds si services trouves, SSRF si cloud detecte, AD si LDAP/Kerberos)
5. Phase 5 — Post-exploitation si score surface d'attaque >= 50
6. Phase 6 — Rapport intelligence complet (MITRE + kill chain + exploit chains)

### Scenario 2: Audit WiFi Complet (Monitor → Crack → Pivot)

```python
# Audit WiFi de A a Z avec pivot automatique
result = await wireless_audit(
    interface="wlan0",
    target_bssid="AA:BB:CC:DD:EE:FF",
    depth="aggressive",
    modules="all",
    wordlist="auto"      # rockyou.txt par defaut
)
```

**Etapes automatisees :**
1. `monitor` — Desactive NetworkManager, active le mode monitor (airmon-ng ou fallback iw)
2. `scan` — Scan airodump-ng (CSV parsing) + bettercap WiFi en backup
3. `capture` — Capture handshake avec deauth (aireplay-ng) si deep/aggressive
4. `pmkid` — Capture PMKID (hcxdumptool) + conversion hashcat (hcxpcapngtool)
5. `crack` — Dictionnaire (aircrack-ng) → hashcat mode 22000 → mask attack (8 chiffres, 8 lettres, 8 chars)
6. **`pivot`** — Si la cle est craquee : genere wpa_supplicant.conf → connecte au reseau → obtient IP DHCP → ARP scan → scan du gateway → suggestions pour la suite
7. `restore` — Remet l'interface en mode managed, redemarre NetworkManager

**Interconnexions :**
- La cle craquee est stockee dans PentestMemory
- Un VulnFinding "WPA Key Cracked" est enregistre (CVSS 9.8)
- Le KillChain avance a "exploitation" puis "actions_on_objectives" apres pivot
- Les hotes decouverts par ARP scan sont accessibles par tous les modules

### Scenario 3: Forensics & Detection de Malware

```python
# Analyse forensique complete d'un systeme suspect
result = await forensics_engine(
    target="192.168.1.50",
    modules="all",
    depth="deep",
    timeout=600
)
```

**10 sous-modules :**

| Module | Ce qu'il fait |
|--------|--------------|
| `log_analysis` | Analyse auth.log/syslog/secure pour brute force, escalade de privileges, patterns suspects (reverse shells, commandes encodees, persistence) |
| `malware_detect` | Processus suspects (crypto miners, netcat, socat), ports C2, rootkit check (chkrootkit/rkhunter), fichiers caches, SUID inhabituels |
| `usb_forensics` | Enumeration lsusb, detection attaques HID (Rubber Ducky 0x03eb, USB Armory 0x1d6b, BadUSB), historique dmesg, stockage de masse |
| `memory_analysis` | Integration Volatility : imageinfo, pslist, netscan, malfind |
| `ransomware_analysis` | 40+ extensions connues (.encrypted, .locked, .cerber...), recherche notes de rancon, analyse d'entropie fichiers, conseils decryptage (nomoreransom.org) |
| `yara_scan` | Decouverte de regles YARA existantes, scan recursif |
| `ioc_extract` | Extraction automatique IPs, domaines, hashes, URLs, emails depuis tous les resultats |
| `timeline` | Reconstruction chronologique de tous les evenements detectes |
| `network_forensics` | Detection ARP spoofing (MACs dupliquees), regles firewall, connexions actives |
| `botnet_detect` | Ports C2 connus (6667, 4444, 5555...), ports mining (3333, 8333...), DNS tunneling, trafic suspect |

### Scenario 4: Test de Race Conditions

```python
# Test complet de race conditions sur une API
result = await race_condition_tester(
    target="https://shop.example.com",
    modules="all",
    endpoint="/api/checkout",
    method="POST",
    data='{"coupon":"SAVE50","quantity":1}',
    concurrent=50,
    timeout=60
)
```

**6 sous-modules :**

| Module | Technique |
|--------|-----------|
| `concurrent_requests` | Turbo Intruder-style : N requetes curl simultanees, analyse des anomalies (codes/tailles de reponse differents) |
| `toctou` | Scenarios TOCTOU : manipulation de prix (modifier entre verification et paiement), escalade de role, abus de quantite, switch de compte |
| `session_race` | Login concurrent pour detecter les collisions de session |
| `limit_bypass` | Reutilisation de coupon, bourrage de votes par requetes paralleles |
| `file_race` | Race condition sur fichiers (symlink attack, ecriture concurrente) |
| `timing_attack` | Enumeration d'utilisateurs par difference de temps de reponse (seuil 50ms = fuite d'info) |

### Scenario 5: Crypto-Forensics Avancee

```python
# Identifier un hash inconnu
result = await crypto_forensics(
    target="$2b$12$LJ3m4ys3Lg...",
    modules="hash_id"
)
# Retourne: type bcrypt, hashcat mode 3200, commande de crack

# Analyser et tenter de dechiffrer un fichier
result = await crypto_forensics(
    target="/path/to/suspicious.enc",
    modules="cipher_analysis,decrypt"
)
# Analyse: entropy, magic bytes, signature du format
# Decrypt: brute-force OpenSSL (10 ciphers x 10 passwords), john pour archives ZIP/RAR/PDF/Office/KeePass

# Audit TLS complet
result = await crypto_forensics(
    target="vulnerable-site.com",
    modules="tls_audit",
    depth="aggressive"
)
# Retourne: testssl.sh + sslscan + verification protocoles faibles (SSLv2/3, TLS 1.0/1.1)
#           Chaque probleme enregistre comme VulnFinding avec CVSS

# Dechiffrer un message (Caesar, Base64, hex...)
result = await crypto_forensics(
    target="Uryyb Jbeyq",    # ROT13
    modules="decrypt"
)
# Retourne: 26 rotations Caesar, decodage Base64/hex, hints Vigenere
```

**15+ patterns de hash identifies :**
MD5, SHA-1, SHA-256, SHA-512, bcrypt, MD5crypt, SHA-256crypt, SHA-512crypt, Apache MD5, phpass (WordPress/phpBB), LDAP SSHA, PBKDF2, MD5/SHA1 salted, Joomla

### Scenario 6: Persistance Avancee (Post-Exploitation)

```python
result = await post_exploit_ops(
    target="10.10.10.100",
    modules="persist",
    depth="aggressive"
)
```

**Retourne des techniques avec commandes reelles + detection + niveau de furtivite :**

**Linux (10 techniques) :**
- `crontab_reverse_shell` — crontab, stealth: medium
- `bashrc_injection` — injection .bashrc, stealth: low
- `systemd_service` — service systemd deguise, stealth: high
- `systemd_timer` — timer systemd periodique, stealth: high
- `ssh_authorized_keys` — cle SSH, stealth: high
- `ld_preload_rootkit` — rootkit via /etc/ld.so.preload, stealth: very_high
- `pam_backdoor` — backdoor PAM (magic password), stealth: very_high
- `rc_local` — script rc.local, stealth: medium
- `init_d_service` — service init.d, stealth: medium
- `motd_backdoor` — execution au login via MOTD, stealth: medium

**Windows (7 techniques) :**
- `registry_run_key`, `scheduled_task`, `wmi_event_subscription`, `dll_hijack`,
  `golden_ticket`, `startup_folder`, `com_hijack`

**Chaque technique inclut :**
- La commande complete a executer
- La commande de detection (pour blue team)
- Le niveau de furtivite (low/medium/high/very_high)

### Scenario 7: IDOR / BOLA Testing

```python
result = await auth_destroyer(
    target="https://api.example.com",
    depth="aggressive",
    modules="idor"
)
```

**Tests automatises :**
- **BOLA** : 10 noms de parametres (id, user_id, account_id, order_id, profile_id, doc_id, file_id, record_id, item_id, resource_id)
- **Method Override Bypass** : X-HTTP-Method-Override, X-HTTP-Method, X-Method-Override (PUT/DELETE/PATCH sur des endpoints interdits)
- **Edge Cases** : id=0, id=-1, id=2147483647 (INT_MAX)
- Chaque IDOR confirme est enregistre comme VulnFinding avec CVSS + MITRE T1078

---

## Commandes Rapides

```bash
# Demarrer le serveur MCP
python kali_mcp_server.py

# Lancer tous les tests (51)
python test_all_tools.py

# Pentest rapide stealth
await recon_engine(target="10.10.10.100", depth="stealth")

# Scan web agressif
await web_assault(target="https://target.com", depth="aggressive")

# Crack un hash specifique
await credential_cracker(target="10.0.0.1", hash_value="HASH", hash_type="auto")

# Generer des payloads
await payload_factory(action="generate", target="10.0.0.1", payload_type="xss")

# Rapport executif
await reporting_engine(target="10.10.10.100", report_type="executive")

# Audit Active Directory
await ad_annihilator(target="dc.domain.local", domain="DOMAIN.LOCAL", depth="deep")

# Chasse SSRF
await ssrf_hunter(target="https://target.com", param="url", depth="aggressive")
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
- `pip install fastmcp`

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

---

## Architecture des Fichiers

```
MCP-Kali-Server/
  kali_mcp_server.py        # 5692 lignes — serveur complet (22 modules + 17 classes)
  test_all_tools.py          # 827 lignes — 51 tests (6 sections)
  README.md                  # Documentation technique
  GUIDE.md                   # Ce guide (synthese + utilisation)
  kali_mcp_server_v4_backup.py  # Backup de l'ancienne v4
  .gitignore
```

---

*Kali MCP Server v6.2 — Mythos-tier Autonomous Pentest Engine*
*22 modules | 17 classes | 51 tests | 5692 lines*
*Par Cabrel10 / MorningStar*
