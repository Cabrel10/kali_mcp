# Guide d'Utilisation - Serveur MCP Kali

## 🚀 Démarrage Rapide

### 1. Lancer un Scan Nmap
```python
# Lancer un scan en arrière-plan
result = nmap_scan("example.com", scan_type="comprehensive")
# Retourne: {"task_id": "abc123", "status": "background_started"}

# Vérifier le statut
status = check_task("abc123")
# Retourne: {"status": "running", "progress": 45}

# Attendre et récupérer les résultats
status = check_task("abc123")
# Retourne: {"status": "completed", "result": {...}}
```

### 2. Lancer un Scan SQLMap
```python
# Lancer un scan SQLi en arrière-plan
result = sqlmap_scan("http://example.com/page?id=1")
# Retourne: {"task_id": "def456", "status": "background_started"}

# Vérifier le statut
status = check_task("def456")
```

### 3. Lancer un Gobuster
```python
# Lancer une énumération de répertoires
result = gobuster_scan("http://example.com")
# Retourne: {"task_id": "ghi789", "status": "background_started"}
```

## 📊 Gestion des Tâches

### Vérifier le Statut d'une Tâche
```python
status = check_task("abc123")
# Retourne:
# {
#   "task_id": "abc123",
#   "target": "example.com",
#   "tool": "nmap",
#   "status": "running",
#   "progress": 45,
#   "elapsed_time": 120.5,
#   "result": null
# }
```

### Lister Toutes les Tâches
```python
# Lister toutes les tâches
tasks = list_tasks()

# Lister les tâches en cours
tasks = list_tasks(status_filter="running")

# Lister les tâches complétées
tasks = list_tasks(status_filter="completed")

# Lister les tâches d'un outil spécifique
tasks = list_tasks(tool_filter="nmap")

# Limiter le nombre de résultats
tasks = list_tasks(limit=10)
```

### Obtenir les Statistiques
```python
stats = get_task_stats()
# Retourne:
# {
#   "total_tasks": 10,
#   "running": 2,
#   "completed": 7,
#   "failed": 1,
#   "pending": 0,
#   "cancelled": 0,
#   "by_tool": {
#     "nmap": 3,
#     "sqlmap": 2,
#     "gobuster": 5
#   }
# }
```

### Annuler une Tâche
```python
result = cancel_task("abc123")
# Retourne:
# {
#   "task_id": "abc123",
#   "cancelled": true,
#   "message": "Task cancelled successfully"
# }
```

## 🔧 Outils Disponibles

### Outils Lourds (Background Execution)
Ces outils s'exécutent en arrière-plan et retournent un task_id:

1. **nmap_scan(target, scan_type, ports, scripts, intensity, timeout)**
   - Scan réseau avancé
   - Scan types: quick, basic, comprehensive, stealth, vuln, udp, aggressive

2. **sqlmap_scan(url, data, method, technique, level, risk, timeout)**
   - Test SQLi automatisé
   - Techniques: error, union, blind, time, stacked

3. **gobuster_scan(url, mode, wordlist, extensions, threads, timeout)**
   - Énumération de répertoires/DNS/vhosts
   - Modes: dir, dns, vhost, fuzz

4. **subdomain_enum(domain, wordlist, timeout)**
   - Énumération de sous-domaines
   - Utilise subfinder et amass

5. **nuclei_scan(target, templates, severity, timeout)**
   - Scan de vulnérabilités avec templates
   - Sévérités: info, low, medium, high, critical

6. **hydra_attack(target, service, username, wordlist, timeout)**
   - Attaque brute force multi-protocoles
   - Services: ssh, ftp, http, smb, etc.

7. **john_crack(hash_file, wordlist, format, timeout)**
   - Cracking de mots de passe
   - Formats: md5, sha1, sha256, bcrypt, etc.

8. **nikto_scan(url, port, ssl, timeout)**
   - Scan de vulnérabilités web
   - Détection de serveurs web

9. **metasploit_exploit(module, target, payload, lhost, lport, timeout)**
   - Exécution de modules Metasploit
   - Exploitation de vulnérabilités

10. **ffuf_fuzz(url, wordlist, method, data, timeout)**
    - Fuzzing web rapide
    - Détection de répertoires/paramètres

### Outils Rapides (Exécution Synchrone)
Ces outils s'exécutent rapidement et retournent les résultats directement:

- **server_health()** - Vérifier l'état du serveur
- **execute_command(command)** - Exécuter une commande shell
- **web_tech_detect(url)** - Détecter les technologies web
- **xss_scan(url, param)** - Test XSS
- **lfi_scan(url, param)** - Test LFI
- **command_injection_test(url, param)** - Test injection de commandes
- Et 30+ autres outils...

## 📈 Workflow Typique

### Scénario 1: Scan Complet d'un Site
```python
# 1. Lancer un scan Nmap
nmap_result = nmap_scan("example.com", scan_type="comprehensive")
nmap_task_id = nmap_result["task_id"]

# 2. Lancer un scan Nikto
nikto_result = nikto_scan("http://example.com")
nikto_task_id = nikto_result["task_id"]

# 3. Lancer un Gobuster
gobuster_result = gobuster_scan("http://example.com")
gobuster_task_id = gobuster_result["task_id"]

# 4. Vérifier les statuts
while True:
    nmap_status = check_task(nmap_task_id)
    nikto_status = check_task(nikto_task_id)
    gobuster_status = check_task(gobuster_task_id)
    
    if all(s["status"] == "completed" for s in [nmap_status, nikto_status, gobuster_status]):
        break
    
    time.sleep(5)

# 5. Récupérer les résultats
nmap_results = check_task(nmap_task_id)["result"]
nikto_results = check_task(nikto_task_id)["result"]
gobuster_results = check_task(gobuster_task_id)["result"]
```

### Scénario 2: Test SQLi
```python
# 1. Lancer un scan SQLMap
sqlmap_result = sqlmap_scan("http://example.com/page?id=1")
task_id = sqlmap_result["task_id"]

# 2. Vérifier le statut
status = check_task(task_id)
print(f"Status: {status['status']}, Progress: {status['progress']}%")

# 3. Attendre la complétion
while check_task(task_id)["status"] != "completed":
    time.sleep(10)

# 4. Récupérer les résultats
results = check_task(task_id)["result"]
print(f"Vulnerabilities found: {results['vulnerabilities']}")
```

### Scénario 3: Brute Force
```python
# 1. Lancer une attaque Hydra
hydra_result = hydra_attack(
    target="192.168.1.100",
    service="ssh",
    username="admin",
    wordlist="/usr/share/wordlists/rockyou.txt"
)
task_id = hydra_result["task_id"]

# 2. Monitorer la progression
while True:
    status = check_task(task_id)
    if status["status"] == "completed":
        results = status["result"]
        if results["found"]:
            print(f"Credentials found: {results['credentials']}")
        break
    elif status["status"] == "failed":
        print(f"Error: {status['error']}")
        break
    
    time.sleep(5)
```

## ⚠️ Bonnes Pratiques

### 1. Toujours Vérifier le Statut
```python
# ✅ BON
task_id = nmap_scan("example.com")["task_id"]
status = check_task(task_id)
if status["status"] == "completed":
    results = status["result"]

# ❌ MAUVAIS
results = nmap_scan("example.com")  # Bloquera pendant 10 minutes
```

### 2. Utiliser des Timeouts Appropriés
```python
# ✅ BON - Timeout de 30 minutes pour un scan complet
nmap_scan("example.com", scan_type="comprehensive", timeout=1800)

# ❌ MAUVAIS - Timeout trop court
nmap_scan("example.com", scan_type="comprehensive", timeout=60)
```

### 3. Monitorer les Ressources
```python
# Vérifier les statistiques régulièrement
stats = get_task_stats()
if stats["running"] > 5:
    print("Warning: Too many concurrent tasks")
```

### 4. Nettoyer les Tâches Anciennes
```python
# Lister les tâches complétées
completed = list_tasks(status_filter="completed", limit=100)

# Vérifier l'âge des tâches
for task in completed:
    if task["elapsed_time"] > 86400:  # Plus de 24 heures
        print(f"Old task: {task['task_id']}")
```

## 🔍 Dépannage

### Le serveur ne répond pas
```bash
# Vérifier que le serveur est actif
ps aux | grep kali_mcp_server_optimized.py

# Vérifier les logs
tail -f MCP-Kali-Server/kali_mcp_server.log
```

### Une tâche est bloquée
```python
# Vérifier le statut
status = check_task("task_id")
print(status)

# Annuler la tâche
cancel_task("task_id")
```

### Trop de tâches en cours
```python
# Vérifier les statistiques
stats = get_task_stats()
print(f"Running tasks: {stats['running']}")

# Attendre que certaines se terminent
while get_task_stats()["running"] > 3:
    time.sleep(10)
```

## 📞 Support

Pour plus d'informations:
- Consulter DIAGNOSTIC_COMPLET.md
- Consulter VERIFICATION_FINALE.md
- Consulter TEST_FINAL.md

---

**Date**: 22 Décembre 2025
**Serveur**: kali_mcp_server_optimized.py
**Status**: 🟢 PRÊT POUR LA PRODUCTION
