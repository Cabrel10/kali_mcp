# MCP-KALI (kali_mcp_clean) — Guide d'utilisation & test réel

**Date test :** 12 août 2026 — **Statut : ✅ OPÉRATIONNEL (test E2E réel passé)**

## Ce qui a été vérifié réellement (pas un mock)

| Test | Commande | Résultat |
|------|----------|----------|
| Handshake MCP | `initialize` | ✅ `kali-tactical-elite` v3.4.7 |
| Liste outils | `tools/list` | ✅ **63 outils** exposés |
| Scan réel | `dns_recon example.com` | ✅ vraies commandes `dig` exécutées |

### Résultat réel du test `dns_recon example.com`
```json
{
  "A":   ["104.20.23.154", "172.66.147.243"],
  "MX":  ["0 ."],
  "NS":  ["elliott.ns.cloudflare.com.", "hera.ns.cloudflare.com."],
  "TXT": ["\"v=spf1 -all\"", "\"_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9\""]
}
```
→ Le serveur exécute de **vraies** commandes `dig A/MX/NS/TXT` (confirmé dans les logs) et retourne les vrais enregistrements DNS Cloudflare d'example.com.

## Architecture

```
Client MCP (stdio)
      │
      ▼
kali_mcp_server_optimized.py   ← serveur FastMCP, transport stdio
      │   63 outils / 27 méga-modules
      ▼
Ollama (127.0.0.1:11434)
      ├─ Phi-4-Mini-Abliterated 3.8B (2.5GB)  ← router + reasoner principal
      └─ dolphin-phi 1.6B                      ← fallback
```

## Comment l'utiliser

### 1. Démarrer le serveur MCP
```bash
cd /home/ubuntu/webapp/MORNINGSTAR/mcp/kali_mcp_clean/MCP-Kali-Server
/home/ubuntu/webapp/MORNINGSTAR/miniconda3/envs/trading_env/bin/python \
    kali_mcp_server_optimized.py
# transport stdio — le serveur lit des requêtes JSON-RPC sur stdin
```

### 2. Format des requêtes (JSON-RPC 2.0)
```json
// handshake
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"cli","version":"0.1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
// lister les outils
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
// appeler un outil
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"dns_recon","arguments":{"domain":"example.com"}}}
```

⚠️ **Important** : chaque outil a ses propres noms d'arguments.
`dns_recon` attend `domain` (PAS `target`). En cas d'erreur
`missing_argument`, lire le `tools/list` pour le schéma exact.

### 3. Intégration dans un client MCP (Gemini / Claude Desktop / etc.)
Le fichier `.gemini/settings.json` montre le pattern :
```json
{
  "mcpServers": {
    "kali-tactical-elite": {
      "command": "/chemin/vers/python3",
      "args": ["/chemin/vers/kali_mcp_server_optimized.py"],
      "cwd": "/chemin/vers/MCP-Kali-Server",
      "timeout": 900000,
      "trust": true
    }
  }
}
```
⚠️ Le `settings.json` actuel pointe vers des chemins `/home/morningstar/...`
**obsolètes** — à remplacer par les chemins réels de ce serveur.

## Outils principaux (63 au total)

- **Recon** : `tactical_recon`, `dns_recon`, `osint_harvester`, `arp_scan`
- **Web** : `web_assault`, `ffuf_fuzz`, `gobuster_scan`, `lfi_scan`, `command_injection_test`
- **Vuln** : `vuln_scanner_ultra` (nuclei), `metasploit_exploit`
- **Crack** : `hydra_attack`, `john_crack`, `crack_hashes`
- **Origin/stealth** : `find_origin_ip`, `locate_origin`, `ghost_mode_toggle`
- **Tâches longues** : `check_task`, `list_tasks`, `cancel_task`, `get_task_stats`
- **C2/post-exploit** : `deploy_persistence`, `lateral_movement`, `privilege_escalation`

## Ce qu'il faut attendre de la configuration

1. **Latence IA** : Phi-4-Mini = ~29s pour router un tool, ~23s pour analyser,
   ~7s pour le next-step. Cycle complet ≈ 60s. **C'est un LLM local, pas instantané.**
2. **Outils réels requis** : le serveur appelle de vrais binaires (`dig`, `nmap`,
   `nikto`, `hydra`, `nuclei`, `metasploit`...). Si un binaire est absent, l'outil
   retourne une erreur `command not found` — installer l'outil système correspondant.
3. **Stealth** : `STEALTH_LEVEL` env (0=OFF → 3=MAXIMUM) contrôle délais/proxy/évasion.
4. **Sécurité** : Nuclei externe exige `NUCLEI_ALLOWED_TARGETS` exact + référence
   d'autorisation. Les exploits automatiques sont **désactivés** à la gateway.
5. **Mode async** : les scans longs (hydra, metasploit, nuclei) tournent en tâches
   d'arrière-plan — récupérer avec `check_task` / `list_tasks`.

## Dépendances installées ce jour
`fastmcp 3.4.7` (était manquant → serveur ne démarrait pas), httpx, dnspython,
beautifulsoup4, lxml, pyjwt.
⚠️ Warning connu : `redis 5.3.0` veut `PyJWT~=2.9.0` mais 2.13.0 installé —
sans impact sur le serveur MCP (n'utilise pas redis).

## État des ports
- Ollama : `127.0.0.1:11434` (local uniquement)
- MCP server : **pas de port réseau** — transport stdio (processus enfant)

## À faire ensuite (non bloquant)
- [ ] Corriger `.gemini/settings.json` avec les chemins réels
- [ ] Portail client avec quota/abonnement par session + wallet (gestion frais) — **pas encore fait**
- [ ] Intégrer Nuclei (P1), bridge Metasploit (P2), Faraday reporting (P3)
