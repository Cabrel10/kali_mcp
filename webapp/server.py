"""MCP-Clean Portal — console MCP (port 8100), client MCP officiel.

Architecture corrigée (Phase 2) :
- Découverte DYNAMIQUE des outils via le SDK `mcp` officiel (ClientSession /
  stdio_client) — plus de liste hardcodée de 9 outils. Le catalogue reflète
  exactement ce que le serveur FastMCP expose (63 outils).
- phi-4-mini (build abliterated) N'ÉMET PAS de tool_calls natifs Ollama
  (vérifié : HAS_TOOL_CALLS=False, il produit du texte pseudo-code). On passe
  donc le catalogue dans le prompt système et on parse une instruction
  structurée `TOOL: nom` / `ARGS: {json}` — plus fiable que l'ancien
  `_extract_text_tool_call` qui cherchait du JSON de function-call.
- Exécution réelle des outils via le même client MCP officiel.

La box est CPU-only et partagée avec l'entraînement ADAN -> génération lente,
d'où des timeouts généreux et un mode "pre_route" pour les outils nommés
explicitement (exécution immédiate sans attendre le LLM).
"""
import asyncio
import json
import os
import re
import threading
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

# SDK MCP officiel (déjà installé dans trading_env : mcp 1.28.1)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

app = FastAPI(title="MCP-Clean Console")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

OLLAMA_CHAT = "http://127.0.0.1:11434/api/chat"
MODEL = "hf.co/mradermacher/Phi-4-Mini-Abliterated-GGUF:Q4_K_M"
INDEX = Path(__file__).parent / "index.html"

# ---------------------------------------------------------------------------
# Backends LLM : "local" (Ollama, DÉFAUT sûr, non-régression) et "colab"
# (modèle GPU sur Colab via passerelle OpenAI-compatible). Le backend Colab
# émet de VRAIS tool_calls OpenAI (vérifié end-to-end sur
# unsloth/Qwen3.8-27B-GGUF) -> tooling beaucoup plus fiable que le parsing
# texte TOOL:/ARGS: imposé par phi-4 en local.
#
# Config par variables d'environnement (jamais de secret en dur dans le code) :
#   COLAB_URL   ex http://127.0.0.1:8780/v1  (passerelle Docker) ou l'URL
#               publique https://xxxx.trycloudflare.com  (le /v1 est ajouté si absent)
#   COLAB_TOKEN jeton Bearer accepté par la passerelle / llama serve --api-key
# ---------------------------------------------------------------------------
def _norm_v1(url: str) -> str:
    url = (url or "").rstrip("/")
    if not url:
        return ""
    return url if url.endswith("/v1") else url + "/v1"


COLAB_BASE = _norm_v1(os.environ.get("COLAB_URL", "http://127.0.0.1:8780/v1"))
COLAB_TOKEN = os.environ.get("COLAB_TOKEN", "")
COLAB_MODEL = os.environ.get("COLAB_MODEL", "local")  # llama serve répond sur "local"
DEFAULT_BACKEND = os.environ.get("MCP_CLEAN_BACKEND", "local")  # local par défaut

VALID_BACKENDS = ("local", "colab")


def _resolve_backend(backend: str | None) -> str:
    b = (backend or DEFAULT_BACKEND or "local").lower()
    return b if b in VALID_BACKENDS else "local"


def _backend_supports_native_tools(backend: str) -> bool:
    """Le backend Colab (Qwen3.8-27B via llama serve --jinja) émet des
    tool_calls OpenAI natifs. Le backend local (phi-4 Ollama) NON."""
    return backend == "colab"
MCP_SERVER = (
    Path(__file__).parent.parent / "MCP-Kali-Server" / "kali_mcp_server_optimized.py"
)
PYTHON = "/home/ubuntu/webapp/MORNINGSTAR/miniconda3/envs/trading_env/bin/python"

# ---------------------------------------------------------------------------
# Catalogue d'outils (pour l'UI, classés par catégorie)
# ---------------------------------------------------------------------------
TOOL_CATEGORIES = {
    "Recon": ["tactical_recon", "dns_recon", "subdomain_enum", "nmap_scan",
              "arp_scan", "web_tech_detect", "smart_scanner", "scan_wifi_networks"],
    "OSINT": ["osint_domain_reputation", "osint_certificate_analysis",
              "osint_dns_history", "osint_whois_info", "osint_wayback_machine",
              "osint_ssl_labs", "run_full_osint_analysis", "check_site_legitimacy",
              "locate_origin", "find_origin_ip"],
    "Web / Exploitation": ["sql_injection_test", "xss_scan", "lfi_scan",
              "command_injection_test", "sqlmap_scan", "ffuf_fuzz", "gobuster_scan",
              "nikto_scan", "nuclei_scan", "wpscan_audit", "metasploit_exploit",
              "test_api_endpoints", "test_register_endpoint", "run_full_endpoint_test"],
    "Phishing": ["test_phishing_csrf", "test_phishing_dom_xss", "test_phishing_idor",
              "test_phishing_otp_bypass", "test_phishing_sensitive_files",
              "test_phishing_ssrf", "run_phishing_exploit_suite"],
    "Cracking / Forensics": ["crack_hashes", "john_crack", "hydra_attack",
              "analyze_document", "reverse_engineer_binary", "extract_credentials"],
    "Post-Exploitation": ["lateral_movement", "privilege_escalation",
              "deploy_persistence", "reverse_shell_generator", "get_payloads"],
    "Contrôle": ["execute_command", "server_health", "list_tasks", "check_task",
              "cancel_task", "get_task_stats", "start_session", "ghost_mode_toggle",
              "force_tactical_mode", "distributed_assault"],
}


class ChatRequest(BaseModel):
    prompt: str
    num_predict: int = 150
    temperature: float = 0.7


class AgentRequest(BaseModel):
    message: str
    tool: str | None = None          # forcer un outil précis (clic panneau)
    tool_arg: str | None = None      # argument principal (domain/target/url...)
    reasoning: bool = False
    summarize: bool = False          # synthèse LLM (lent sous contention CPU en local)
    temperature: float = 0.2
    max_tokens: int = 300
    backend: str | None = None       # "local" (Ollama, défaut) | "colab" (GPU)


class LoopRequest(BaseModel):
    message: str
    session_id: str | None = None    # pour pouvoir interrompre la session
    max_steps: int = 8               # outils max enchaînés automatiquement
    reasoning: bool = False
    temperature: float = 0.2
    max_tokens: int = 350
    backend: str | None = None       # "local" (Ollama, défaut) | "colab" (GPU)


# ---------------------------------------------------------------------------
# Client MCP officiel (SDK `mcp`) — session stdio persistante dans un thread
# asyncio dédié. Les endpoints FastAPI (sync) appellent via
# run_coroutine_threadsafe -> thread-safe, une seule session réutilisée.
# ---------------------------------------------------------------------------
class MCPClient:
    def __init__(self):
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()
        self._session: ClientSession | None = None
        self._tools: list = []
        self._ctx_stack = []
        fut = asyncio.run_coroutine_threadsafe(self._connect(), self._loop)
        fut.result(timeout=90)

    async def _connect(self):
        params = StdioServerParameters(command=PYTHON, args=[str(MCP_SERVER)], env=None)
        cm = stdio_client(params)
        read, write = await cm.__aenter__()
        self._ctx_stack.append(cm)
        scm = ClientSession(read, write)
        self._session = await scm.__aenter__()
        self._ctx_stack.append(scm)
        await self._session.initialize()
        result = await self._session.list_tools()
        self._tools = list(result.tools)

    # -- API synchrone pour les endpoints ------------------------------------
    @property
    def tools(self) -> list:
        return self._tools

    def tool_names(self) -> list[str]:
        return [t.name for t in self._tools]

    def call_tool(self, name: str, arguments: dict, timeout: float = 120.0) -> dict:
        if self._session is None:
            return {"error": "mcp_not_connected"}
        try:
            fut = asyncio.run_coroutine_threadsafe(
                self._session.call_tool(name, arguments=arguments), self._loop
            )
            res = fut.result(timeout=timeout)
            text = ""
            if getattr(res, "content", None):
                text = "\n".join(getattr(c, "text", "") for c in res.content)
            return {"content": text, "is_error": bool(getattr(res, "isError", False))}
        except Exception as e:  # timeout, tool error, etc.
            return {"error": str(e)}


MCP = MCPClient()
_KNOWN_TOOLS = set(MCP.tool_names())


def _ollama_tools_schema() -> list[dict]:
    """Schéma function-calling DYNAMIQUE — construit depuis la découverte MCP
    réelle (63 outils), plus aucune liste hardcodée."""
    out = []
    for t in MCP.tools:
        schema = t.inputSchema or {}
        props = schema.get("properties", {}) or {}
        out.append({
            "type": "function",
            "function": {
                "name": t.name,
                "description": (t.description or f"Outil MCP {t.name}")[:400],
                "parameters": {
                    "type": "object",
                    "properties": {
                        k: {"type": (v or {}).get("type", "string"),
                            "description": (v or {}).get("description", "")[:200]}
                        for k, v in props.items()
                    },
                    "required": schema.get("required", []) or [],
                },
            },
        })
    return out


def _tools_prompt(max_tools: int = 63) -> str:
    """Catalogue compact pour le prompt système (phi-4 = petit contexte)."""
    lines = []
    for t in MCP.tools[:max_tools]:
        schema = t.inputSchema or {}
        req = schema.get("required", []) or []
        props = schema.get("properties", {}) or {}
        params = ", ".join(f"{p} ({props.get(p, {}).get('type', 'string')})" for p in req) or "aucun"
        lines.append(f"- {t.name}: params requis: {params}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers Ollama (HTTP direct — pas de dépendance au SDK ollama, timeouts
# maîtrisés sous contention CPU ADAN)
# ---------------------------------------------------------------------------
def _call_ollama_chat(messages, max_tokens=300, temperature=0.2, timeout=600):
    payload = {"model": MODEL, "messages": messages, "stream": False,
               "options": {"temperature": temperature, "num_predict": max_tokens}}
    req = urllib.request.Request(
        OLLAMA_CHAT, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


class BackendError(Exception):
    """Erreur backend enrichie (statut HTTP + message lisible pour l'UI)."""

    def __init__(self, message, status=None, retry_after=None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


def _call_colab_chat(messages, max_tokens=300, temperature=0.2, timeout=180,
                     tools=None):
    """Appel OpenAI-compatible vers la passerelle Colab. Réutilise le message
    503 amélioré de la passerelle (GPU en réveil) tel quel."""
    if not COLAB_TOKEN:
        raise BackendError("Backend Colab non configuré : COLAB_TOKEN absent "
                           "(voir .env / variables d'environnement).", status=412)
    body = {"model": COLAB_MODEL, "messages": messages, "stream": False,
            "max_tokens": max_tokens, "temperature": temperature}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    req = urllib.request.Request(
        COLAB_BASE + "/chat/completions", data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {COLAB_TOKEN}",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="ignore")
        try:
            err = json.loads(raw).get("error", {})
            msg = err.get("message", raw) if isinstance(err, dict) else str(err)
            retry = err.get("retry_after") if isinstance(err, dict) else None
        except Exception:
            msg, retry = raw, None
        raise BackendError(msg, status=e.code, retry_after=retry)
    except Exception as e:
        raise BackendError(f"passerelle Colab injoignable : {e}", status=503)


def _norm_reply(backend: str, d: dict) -> dict:
    """Normalise la réponse des deux backends vers une forme commune :
    {content, tool_calls, prompt_tokens, completion_tokens}."""
    if backend == "colab":
        msg = (d.get("choices", [{}])[0] or {}).get("message", {}) or {}
        usage = d.get("usage", {}) or {}
        return {
            "content": msg.get("content") or "",
            "tool_calls": msg.get("tool_calls") or [],
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
        }
    # ollama
    return {
        "content": (d.get("message", {}) or {}).get("content", "") or "",
        "tool_calls": [],
        "prompt_tokens": d.get("prompt_eval_count", 0),
        "completion_tokens": d.get("eval_count", 0),
    }


def _call_llm(messages, backend="local", max_tokens=300, temperature=0.2,
              timeout=None, tools=None) -> dict:
    """Dispatcher unifié. Retourne la forme normalisée _norm_reply."""
    backend = _resolve_backend(backend)
    if backend == "colab":
        d = _call_colab_chat(messages, max_tokens=max_tokens,
                             temperature=temperature,
                             timeout=timeout or 180, tools=tools)
    else:
        d = _call_ollama_chat(messages, max_tokens=max_tokens,
                             temperature=temperature, timeout=timeout or 600)
    return _norm_reply(backend, d)


def _content(d: dict) -> str:
    return (d.get("message", {}) or {}).get("content", "") or ""


def _acc(usage: dict, d: dict):
    usage["prompt_tokens"] = usage.get("prompt_tokens", 0) + d.get("prompt_eval_count", 0)
    usage["completion_tokens"] = usage.get("completion_tokens", 0) + d.get("eval_count", 0)


def _acc_norm(usage: dict, r: dict):
    """Accumule l'usage depuis une réponse normalisée (_norm_reply)."""
    usage["prompt_tokens"] = usage.get("prompt_tokens", 0) + r.get("prompt_tokens", 0)
    usage["completion_tokens"] = usage.get("completion_tokens", 0) + r.get("completion_tokens", 0)


def _tool_text(result: dict) -> str:
    if not isinstance(result, dict):
        return str(result)
    if result.get("error"):
        return f"ERREUR outil: {result['error']}"
    return result.get("content", "") or "(sortie vide)"


# ---------------------------------------------------------------------------
# Arguments par défaut quand l'utilisateur force un outil depuis le panneau
# ---------------------------------------------------------------------------
_TARGET_RE = re.compile(
    r"((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|\b\d{1,3}(?:\.\d{1,3}){3}\b|https?://\S+)")


def _arguments_for(tool_name: str, arg: str | None) -> dict:
    """Mappe l'argument libre vers le 1er param requis du schéma réel."""
    schema = next((t.inputSchema for t in MCP.tools if t.name == tool_name), {}) or {}
    required = schema.get("required", []) or []
    if not required:
        return {}
    key = required[0]
    value = (arg or "").strip()
    if not value:
        m = _TARGET_RE.search(arg or "")
        value = m.group(1) if m else ""
    return {key: value} if value else {}


def _pre_route(message: str):
    """Si le message nomme explicitement un outil connu -> exécution immédiate
    (sans attendre phi-4, qui est lent sous charge ADAN)."""
    low = message.lower()
    hits = [name for name in _KNOWN_TOOLS if name.lower() in low]
    if len(hits) != 1:
        return None
    name = hits[0]
    m = _TARGET_RE.search(message)
    arg = m.group(1) if m else None
    return name, _arguments_for(name, arg)


# ---------------------------------------------------------------------------
# Parsing des appels d'outils produits par phi-4 (PAS de tool_calls natifs —
# vérifié : HAS_TOOL_CALLS=False sur ce build). Format demandé au modèle :
#   TOOL: nom_outil
#   ARGS: {"param": "valeur"}
# + fallback sur JSON de function-call sérialisé en texte.
# ---------------------------------------------------------------------------
_TOOL_RE = re.compile(r"TOOL\s*:\s*([A-Za-z_][A-Za-z0-9_]*)", re.I)
_ARGS_RE = re.compile(r"ARGS\s*:\s*(\{.*?\})", re.I | re.S)


def _parse_tool_call(content: str):
    if not content:
        return None
    m = _TOOL_RE.search(content)
    if m:
        name = m.group(1)
        if name in _KNOWN_TOOLS:
            args = {}
            am = _ARGS_RE.search(content)
            if am:
                try:
                    args = json.loads(am.group(1))
                except json.JSONDecodeError:
                    args = {}
            if not args:
                tm = _TARGET_RE.search(content)
                args = _arguments_for(name, tm.group(1) if tm else None)
            return name, args
    # Fallback : JSON de function-call sérialisé dans le texte
    for jm in re.finditer(r"\{[^{}]*\}", content):
        try:
            obj = json.loads(jm.group(0))
        except json.JSONDecodeError:
            continue
        fn = (obj.get("function") or {})
        name = fn.get("name") or obj.get("name")
        if name in _KNOWN_TOOLS:
            args = fn.get("arguments") or obj.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            return name, args
    return None


_LOOP_SYSTEM = """Tu es un agent de cybersécurité AUTONOME qui pilote de vrais outils MCP.
RÈGLES STRICTES :
1. Pour exécuter un outil, réponds UNIQUEMENT avec ces deux lignes :
TOOL: nom_exact_de_l_outil
ARGS: {"parametre": "valeur"}
2. N'écris RIEN d'autre quand tu appelles un outil (pas de texte avant/après).
3. N'appelle JAMAIS deux fois le même outil avec les mêmes arguments.
4. Quand tu as assez de résultats, réponds normalement en français (sans TOOL:).
5. Si tu ne sais pas quel outil utiliser, réponds directement sans TOOL:.

Outils disponibles :
{tools}"""


_STOP_FLAGS: dict[str, threading.Event] = {}


def _sse(obj: dict) -> str:
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX.read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "model": MODEL,
        "default_backend": _resolve_backend(None),
        "colab_configured": bool(COLAB_TOKEN),
        "mcp_connected": MCP is not None and MCP._session is not None,
        "tools_count": len(MCP.tools),
    }


@app.get("/api/tools")
def list_tools():
    return {
        "count": len(MCP.tools),
        "tools": MCP.tool_names(),
        "categories": TOOL_CATEGORIES,
    }


def _probe_local() -> dict:
    """Ollama joignable ? (rapide, ne charge pas le modèle)."""
    try:
        req = urllib.request.Request("http://127.0.0.1:11434/api/tags")
        with urllib.request.urlopen(req, timeout=3) as r:
            data = json.loads(r.read().decode())
        names = [m.get("name", "") for m in data.get("models", [])]
        return {"available": True, "state": "ready", "model": MODEL,
                "loaded_models": names, "native_tools": False,
                "detail": "Ollama local (parsing texte TOOL:/ARGS:)"}
    except Exception as e:
        return {"available": False, "state": "unavailable", "model": MODEL,
                "native_tools": False, "detail": f"Ollama injoignable : {e}"}


def _probe_colab() -> dict:
    """Passerelle Colab : distingue configuré / GPU en réveil (503) / prêt."""
    base = {"model": COLAB_MODEL, "native_tools": True,
            "endpoint": COLAB_BASE, "configured": bool(COLAB_TOKEN)}
    if not COLAB_TOKEN:
        return {**base, "available": False, "state": "unconfigured",
                "detail": "COLAB_TOKEN absent (renseigner .env)."}
    try:
        req = urllib.request.Request(
            COLAB_BASE + "/models",
            headers={"Authorization": f"Bearer {COLAB_TOKEN}"})
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read().decode())
        models = [m.get("id") or m.get("name") for m in data.get("data", data.get("models", []))]
        return {**base, "available": True, "state": "ready",
                "served_models": models,
                "detail": "GPU Colab actif (tool_calls OpenAI natifs)."}
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="ignore")
        try:
            err = json.loads(raw).get("error", {})
            msg = err.get("message", raw) if isinstance(err, dict) else str(err)
        except Exception:
            msg = raw
        if e.code == 503:  # GPU en réveil -> message passerelle réutilisé tel quel
            return {**base, "available": False, "state": "gpu-waking",
                    "http": 503, "detail": msg}
        if e.code in (401, 403):
            return {**base, "available": False, "state": "forbidden",
                    "http": e.code, "detail": msg}
        return {**base, "available": False, "state": "error",
                "http": e.code, "detail": msg}
    except Exception as e:
        return {**base, "available": False, "state": "unreachable",
                "detail": f"passerelle injoignable : {e}"}


@app.get("/api/backends")
def backends():
    """État des deux backends pour le portail (l'utilisateur choisit, pas de
    bascule automatique silencieuse)."""
    return {
        "default": _resolve_backend(None),
        "backends": {"local": _probe_local(), "colab": _probe_colab()},
    }


@app.post("/api/agent")
def agent(req: AgentRequest):
    """Chemin rapide : l'utilisateur a forcé un outil (clic panneau) OU le
    message nomme explicitement un outil connu -> exécution directe."""
    tool = req.tool
    args: dict = {}
    if tool and tool not in _KNOWN_TOOLS:
        return {"error": f"outil inconnu: {tool}",
                "known_tools": sorted(_KNOWN_TOOLS)}
    if not tool:
        routed = _pre_route(req.message)
        if routed:
            tool, args = routed
    backend = _resolve_backend(req.backend)
    if not tool:
        # Pas d'outil identifiable -> réponse LLM simple (sans catalogue)
        try:
            r = _call_llm([{"role": "user", "content": req.message}],
                          backend=backend, max_tokens=req.max_tokens,
                          temperature=req.temperature)
        except BackendError as e:
            return {"error": e.args[0], "status": e.status,
                    "retry_after": e.retry_after, "backend": backend}
        except Exception as e:
            return {"error": f"{backend}: {e}", "backend": backend}
        usage: dict = {}
        _acc_norm(usage, r)
        return {"reply": r["content"], "executed": None, "usage": usage,
                "backend": backend}

    if not args:
        args = _arguments_for(tool, req.tool_arg or req.message)
    result = MCP.call_tool(tool, args)
    text = _tool_text(result)

    reply = text
    usage: dict = {}
    if req.summarize and not result.get("error"):
        try:
            r = _call_llm(
                [{"role": "user", "content":
                  f"Résultat de l'outil {tool}:\n{text[:3000]}\n\n"
                  "Résume ce résultat en français, de façon concise."}],
                backend=backend, max_tokens=req.max_tokens,
                temperature=req.temperature)
            _acc_norm(usage, r)
            reply = r["content"] or text
        except Exception:
            reply = text

    # Contrat frontend : executed.result.content = liste de {text: ...}
    return {
        "reply": reply,
        "executed": {
            "tool": tool,
            "arguments": args,
            "result": {"content": [{"text": text}],
                       "is_error": bool(result.get("is_error") or result.get("error"))},
        },
        "usage": usage,
        "backend": backend,
    }


@app.post("/api/agent/loop")
def agent_loop(req: LoopRequest):
    """Boucle autonome SSE : phi-4 choisit les outils (TOOL:/ARGS:), on les
    exécute via le client MCP officiel, jusqu'à réponse finale / max_steps /
    stop utilisateur."""
    session_id = req.session_id or uuid.uuid4().hex[:12]
    stop_flag = _STOP_FLAGS.setdefault(session_id, threading.Event())
    stop_flag.clear()
    backend = _resolve_backend(req.backend)
    native = _backend_supports_native_tools(backend)

    def gen():
        usage: dict = {}
        step = 0
        results_log: list[str] = []
        seen_sigs: set[str] = set()   # anti-répétition fiable (outil+args)
        yield _sse({"type": "session", "session_id": session_id,
                    "backend": backend, "native_tools": native})

        # 1) pre_route : outil explicitement nommé -> exécution immédiate
        routed = _pre_route(req.message)
        if routed:
            name, args = routed
            step += 1
            yield _sse({"type": "tool_call", "step": step, "tool": name,
                        "arguments": args, "source": "pre_route"})
            result = MCP.call_tool(name, args)
            text = _tool_text(result)
            results_log.append(f"[{name}] {text[:2000]}")
            yield _sse({"type": "tool_result", "step": step, "tool": name,
                        "result": text})

        # 2) boucle LLM — deux modes :
        #    - colab (native=True)  : tool_calls OpenAI natifs, fiables.
        #    - local (native=False) : phi-4 n'émet pas de tool_calls -> on
        #      injecte le catalogue dans le prompt système et on parse TOOL:/ARGS:.
        # NB: .replace() et non .format() — le template _LOOP_SYSTEM contient des
        # accolades littérales qui casseraient str.format.
        if native:
            messages = [{"role": "user", "content": req.message}]
            tools_payload = _ollama_tools_schema()
        else:
            messages = [
                {"role": "system",
                 "content": _LOOP_SYSTEM.replace("{tools}", _tools_prompt())},
                {"role": "user", "content": req.message},
            ]
            tools_payload = None

        while step < req.max_steps:
            if stop_flag.is_set():
                yield _sse({"type": "stopped", "step": step})
                return
            yield _sse({"type": "thinking", "step": step + 1})
            try:
                r = _call_llm(messages, backend=backend,
                              max_tokens=req.max_tokens,
                              temperature=req.temperature,
                              tools=tools_payload)
            except BackendError as e:
                yield _sse({"type": "error", "message": e.args[0],
                            "status": e.status, "retry_after": e.retry_after,
                            "backend": backend})
                return
            except Exception as e:
                yield _sse({"type": "error", "message": f"{backend}: {e}"})
                return
            _acc_norm(usage, r)
            content = r["content"]

            # --- déterminer l'appel d'outil selon le mode ---
            if native and r["tool_calls"]:
                tc = r["tool_calls"][0]
                name = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"].get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                assistant_msg = {"role": "assistant", "content": content or "",
                                 "tool_calls": [tc]}
            else:
                parsed = _parse_tool_call(content)
                if not parsed:
                    yield _sse({"type": "final", "reply": content, "usage": usage})
                    return
                name, args = parsed
                assistant_msg = {"role": "assistant", "content": content}

            if not native and not _parse_tool_call(content):
                yield _sse({"type": "final", "reply": content, "usage": usage})
                return

            # Anti-répétition : même outil + mêmes args déjà exécuté -> stop
            sig = f"{name}{json.dumps(args, sort_keys=True)}"
            if sig in seen_sigs:
                yield _sse({"type": "final",
                            "reply": "Boucle interrompue : l'agent répète le même "
                                     "appel. Résultats déjà obtenus :\n\n"
                                     + "\n\n".join(results_log)[-3000:],
                            "usage": usage})
                return
            seen_sigs.add(sig)

            step += 1
            yield _sse({"type": "tool_call", "step": step, "tool": name,
                        "arguments": args, "source": "llm"})
            result = MCP.call_tool(name, args)
            text = _tool_text(result)
            results_log.append(f"[{name} {json.dumps(args)}] {text[:2000]}")
            yield _sse({"type": "tool_result", "step": step, "tool": name,
                        "result": text})

            messages.append(assistant_msg)
            if native:
                messages.append({"role": "tool",
                                 "tool_call_id": (r["tool_calls"][0].get("id")
                                                  or f"call_{step}"),
                                 "content": text[:2500]})
            else:
                messages.append({"role": "user", "content":
                                 f"Résultat de l'outil {name} :\n{text[:2500]}\n\n"
                                 "Continue (TOOL:/ARGS:) ou réponds en français."})

        # max_steps atteint
        yield _sse({"type": "final",
                    "reply": "Nombre maximum d'étapes atteint. Résultats :\n\n"
                             + "\n\n".join(results_log)[-3000:],
                    "usage": usage})

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.post("/api/agent/stop")
def agent_stop(payload: dict):
    sid = (payload or {}).get("session_id", "")
    flag = _STOP_FLAGS.get(sid)
    if flag:
        flag.set()
    return {"stopped": True, "session_id": sid}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8100)
