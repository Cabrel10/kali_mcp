# MCP Architecture — Control Room v2

**Date :** 2026-08-16
**Statut :** Portail v2 opérationnel (phases 1-2 validées) · boucle LLM en attente de fenêtre CPU

---

## Principe directeur

> **MCP reste MCP · le modèle reste libre de raisonner · un contrôleur mince fait
> uniquement la plomberie, la validation technique, l'historique et la sécurité.**

Aucun préprompt-routeur. Aucun pseudo-protocole JSON-RPC maison. Aucune liste
d'outils codée en dur. La source de vérité est le serveur MCP + le client MCP
officiel (SDK `mcp` / `mcp_cli.py`), avec Ollama au-dessus.

```
┌─────────────────────────────────────────────────────────────┐
│  Couche 1 : Ollama (Phi-4 / tout modèle)                     │
│  → Inférence pure, ZÉRO prison de formatage                  │
│  → Tool calling NATIF si supporté, sinon convention texte    │
├─────────────────────────────────────────────────────────────┤
│  Couche 2 : MCP Portail v2 (port 8100) — server_v2.py       │
│  → FastAPI + SSE streaming + SQLite (session history)        │
│  → loguru JSON structuré (rotation 10MB ×5) + timeline hum.  │
│  → Contrôleur mince : validation schéma, anti-boucle,        │
│    annulation, rate-limit 10 req/min, budget d'étapes        │
├─────────────────────────────────────────────────────────────┤
│  Couche 3 : MCP Client SDK officiel (stdio)                  │
│  → Découverte DYNAMIQUE des 63 outils via tools/list         │
│  → JSON-RPC natif — le parseur texte TOOL:/ARGS: n'est       │
│    qu'un FALLBACK pour les modèles sans tool_calls natifs    │
├─────────────────────────────────────────────────────────────┤
│  Couche 4 : MCP Server Kali (kali_mcp_server_optimized.py)   │
│  → 63 outils réels (nmap, gobuster, nikto, sqlmap, hydra…)   │
│  → Transport stdio, FastMCP 3.4.7                            │
└─────────────────────────────────────────────────────────────┘
```

## Philosophie : Phi-4 libre, pas en prison

Le system prompt décrit les outils et la **liberté** d'action. Il n'impose pas de
format de sortie. Le modèle peut :

- répondre directement (aucun outil) ;
- appeler 1 outil ;
- enchaîner 2-3 outils, comparer, changer d'approche ;
- récupérer après une erreur.

Le contrôleur n'intervient que pour :

```
outil inexistant · arguments invalides · timeout · appel identique sans progrès
session annulée · budget d'étapes dépassé
```

### Tool calling : natif d'abord, texte en secours

`server_v2.py` construit un schéma function-calling **dynamique** depuis la
découverte MCP réelle (`ollama_tools_schema()`, ligne 259) et le passe à Ollama
(`payload["tools"]`, ligne 277). Les modèles compatibles émettent des
`tool_calls` natifs lus par `_native_calls()`. Pour Phi-4-Mini (qui n'émet pas de
`tool_calls` natifs sur ce build), `parse_text_call()` (ligne 311) accepte la
convention `TOOL:`/`ARGS:` **ou** un bloc JSON de function-call sérialisé —
uniquement en repli, jamais comme protocole imposé.

## Session History (SQLite — `portal_history.db`)

```sql
sessions(id, created_at, updated_at, model, status, title)
messages(id, session_id, ts, role, content, tokens_in, tokens_out)
tool_calls(id, session_id, message_id, tool_name, arguments_json,
           started_at, finished_at, duration_ms, status)
tool_results(id, tool_call_id, result_text, error, size_bytes)
events(id, session_id, ts, event_type, payload_json)
```

Permet : reprise de session (12 derniers messages réinjectés), timeline complète,
replay d'un appel, export JSON / JSONL / Markdown.

## Logs structurés (`logs/`)

- `portal.jsonl` — loguru sérialisé JSON (session, tool, latence, statut, erreur,
  transport, modèle). Rotation 10 MB, 5 backups.
- `portal_human.log` — timeline lisible `HH:MM:SS | LEVEL | message`.

## API v2 (port 8100)

| Méthode | Route | Rôle |
|---|---|---|
| GET  | `/api/health` | statut + nb outils + disclaimer |
| GET  | `/api/models` | modèles Ollama disponibles |
| GET  | `/api/tools` | 63 outils + schémas (dynamique) |
| GET/POST | `/api/sessions` | lister (recherche/pagination) / créer |
| GET  | `/api/sessions/{id}` | messages + tool_calls + events |
| PATCH/DELETE | `/api/sessions/{id}` | renommer/archiver / supprimer |
| GET  | `/api/sessions/{id}/export?format=` | json / jsonl / md |
| POST | `/api/chat/stream` | boucle agent SSE (libre) |
| POST | `/api/chat/stop` | annulation réelle |
| GET  | `/api/metrics` | usage, taux de succès outils |

## État de validation (2026-08-16)

| Phase | Test | Statut |
|---|---|---|
| 1 | Health, modèles | ✅ 200 OK, 5 modèles |
| 2 | Découverte 63 outils + schémas, sessions SQLite | ✅ dynamique, persistant |
| — | Couche MCP via `mcp_cli.py` (sans Ollama) | ✅ `server_health` réel |
| 3 | Boucle agent Phi-4 (1 outil) | ⏸ bloquée par contention CPU (V30 500k) |
| 4 | Anti-boucle + timeout | ⏸ idem |
| 5 | Charge 10 req simultanées | ⏸ idem |
| 6 | Régression multi-modèle | ⏸ idem |

**Blocage P3-P6 : temporaire et prévisible.** Ollama met >6 min par génération
pendant que l'entraînement ADAN V30 500k monopolise ~420% CPU. Les phases 1-2 et
la couche protocolaire MCP ne dépendent pas d'Ollama et sont validées. Les tests
LLM seront relancés par sondes espacées dès que le CPU se libère (fin du run V30).

## Binaires Kali

`server_health` (réel, 2026-08-16) : **8 disponibles** (nmap, gobuster, nikto,
sqlmap, hydra, ffuf, curl, wget) · **14 manquants** (dirb, msfconsole, john,
hashcat, wpscan, enum4linux, amass, dnsrecon, theharvester, whatweb, wfuzz,
nuclei, subfinder, httpx). Les outils MCP appelant un binaire absent retournent
`command not found` — installer le binaire système correspondant si besoin.

## Disclaimer

> ⚠️ Usage éducatif et tests de sécurité autorisés uniquement. N'utilisez jamais
> ces outils contre des systèmes sans permission explicite. L'utilisateur est
> seul responsable.

Affiché dans l'UI (`⚠ Authorized use only`) et injecté dans le contexte système.
