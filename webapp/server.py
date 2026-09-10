"""MCP Control Room v2 — port 8100.

Architecture (cf. décision 2026-08-15) :
- MCP reste MCP : client officiel `mcp` (stdio), découverte dynamique des 63 outils.
- Phi-4 (ou tout modèle Ollama) reste LIBRE de raisonner : pas de préprompt-routeur,
  pas de prison JSON. Le contrôleur ne fait que la plomberie :
  validation de schéma, timeouts, anti-boucle, annulation, budget, audit.
- Session History SQLite : sessions / messages / tool_calls / tool_results / events.
- Logs structurés : loguru JSON (rotation 10 MB x5) + timeline humaine.
- Disclaimer d'usage autorisé affiché et injecté dans le contexte système.
"""
import asyncio
import json
import re
import sqlite3
import threading
import time
import urllib.request
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (HTMLResponse, JSONResponse, PlainTextResponse,
                               StreamingResponse)
from loguru import logger
from pydantic import BaseModel

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BASE = Path(__file__).parent
INDEX = BASE / "index.html"
LOGS_PAGE = BASE / "logs.html"
DB_PATH = BASE / "portal_history.db"
LOG_DIR = BASE / "logs"
LOG_DIR.mkdir(exist_ok=True)

MCP_SERVER = (BASE.parent / "MCP-Kali-Server" / "kali_mcp_server.py")
PYTHON = "/home/ubuntu/webapp/MORNINGSTAR/miniconda3/envs/trading_env/bin/python"
OLLAMA_CHAT = "http://127.0.0.1:11434/api/chat"
OLLAMA_TAGS = "http://127.0.0.1:11434/api/tags"
DEFAULT_MODEL = "hf.co/mradermacher/Phi-4-Mini-Abliterated-GGUF:Q4_K_M"

# ---------------------------------------------------------------------------
# Backends LLM du PORTAIL (indépendants du serveur MCP — le MCP tourne seul).
# "local"  : Ollama (défaut, non-régression).
# "colab"  : GPU Colab via passerelle OpenAI-compatible (:8780), token Bearer.
# "openrouter" / "nvidia" : providers cloud (clés via variables d'env).
# Sélection côté UI via préfixe de modèle : "colab:X", "openrouter:Y", ...
# ---------------------------------------------------------------------------
import os
COLAB_URL = os.environ.get("COLAB_URL", "http://127.0.0.1:8780/v1")
COLAB_TOKEN = os.environ.get("COLAB_TOKEN", "")
COLAB_MODEL = os.environ.get("COLAB_MODEL", "local")
OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "openai/gpt-4o-mini")
NVIDIA_KEY = os.environ.get("NVIDIA_API_KEY", "")
NVIDIA_MODEL = os.environ.get("NVIDIA_MODEL", "meta/llama-3.1-70b-instruct")

CLOUD_BACKENDS = {
    "colab":      {"url": COLAB_URL, "key": COLAB_TOKEN, "model": COLAB_MODEL},
    "openrouter": {"url": "https://openrouter.ai/api/v1", "key": OPENROUTER_KEY,
                   "model": OPENROUTER_MODEL},
    "nvidia":     {"url": "https://integrate.api.nvidia.com/v1", "key": NVIDIA_KEY,
                   "model": NVIDIA_MODEL},
}


def resolve_backend(model):
    """Préfixe de modèle -> backend. 'openrouter:gpt-4o' -> ('openrouter','gpt-4o').
    Sans préfixe connu -> ('local', model) : Ollama, comportement inchangé."""
    if model and ":" in model:
        prefix, rest = model.split(":", 1)
        if prefix in CLOUD_BACKENDS:
            return prefix, (rest or None)
    return "local", model

DISCLAIMER = (
    "⚠️ Usage éducatif et tests de sécurité autorisés uniquement. "
    "N'utilisez jamais ces outils contre des systèmes sans permission explicite. "
    "L'utilisateur est seul responsable."
)

# ---------------------------------------------------------------------------
# Logs structurés (loguru JSON, rotation 10MB, 5 backups) + timeline humaine
# ---------------------------------------------------------------------------
logger.remove()
logger.add(LOG_DIR / "portal.jsonl", serialize=True, rotation="10 MB",
           retention=5, level="DEBUG", enqueue=True)
logger.add(LOG_DIR / "portal_human.log", rotation="10 MB", retention=5,
           level="INFO", enqueue=True,
           format="{time:HH:mm:ss} | {level:7} | {message}")
log = logger.bind(component="portal")

# ---------------------------------------------------------------------------
# SQLite — Session History
# ---------------------------------------------------------------------------
_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions(
  id TEXT PRIMARY KEY, created_at TEXT, updated_at TEXT,
  model TEXT, status TEXT DEFAULT 'active', title TEXT);
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, ts TEXT,
  role TEXT, content TEXT, tokens_in INTEGER DEFAULT 0, tokens_out INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS tool_calls(
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, message_id INTEGER,
  tool_name TEXT, arguments_json TEXT, started_at TEXT, finished_at TEXT,
  duration_ms INTEGER, status TEXT);
CREATE TABLE IF NOT EXISTS tool_results(
  id INTEGER PRIMARY KEY AUTOINCREMENT, tool_call_id INTEGER,
  result_text TEXT, error TEXT, size_bytes INTEGER);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, ts TEXT,
  event_type TEXT, payload_json TEXT);
CREATE INDEX IF NOT EXISTS idx_msg_sess ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_tc_sess ON tool_calls(session_id);
CREATE INDEX IF NOT EXISTS idx_ev_sess ON events(session_id);
"""
_db_lock = threading.Lock()


def _db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def db_init():
    with _db_lock, _db() as c:
        c.executescript(_SCHEMA)


def _now():
    return datetime.now(timezone.utc).isoformat()


def db_create_session(model: str, title: str = "") -> str:
    sid = uuid.uuid4().hex[:12]
    with _db_lock, _db() as c:
        c.execute("INSERT INTO sessions(id,created_at,updated_at,model,title) "
                  "VALUES(?,?,?,?,?)", (sid, _now(), _now(), model, title))
    return sid


def db_touch(sid, status=None, title=None):
    with _db_lock, _db() as c:
        c.execute("UPDATE sessions SET updated_at=? WHERE id=?", (_now(), sid))
        if status:
            c.execute("UPDATE sessions SET status=? WHERE id=?", (status, sid))
        if title:
            c.execute("UPDATE sessions SET title=? WHERE id=?", (title, sid))


def db_message(sid, role, content, tin=0, tout=0) -> int:
    with _db_lock, _db() as c:
        cur = c.execute(
            "INSERT INTO messages(session_id,ts,role,content,tokens_in,tokens_out)"
            " VALUES(?,?,?,?,?,?)", (sid, _now(), role, content, tin, tout))
        return cur.lastrowid


def db_tool_call(sid, mid, name, args) -> int:
    with _db_lock, _db() as c:
        cur = c.execute(
            "INSERT INTO tool_calls(session_id,message_id,tool_name,arguments_json,"
            "started_at,status) VALUES(?,?,?,?,?,?)",
            (sid, mid, name, json.dumps(args, ensure_ascii=False), _now(), "running"))
        return cur.lastrowid


def db_tool_finish(tcid, status, result_text, error):
    with _db_lock, _db() as c:
        row = c.execute("SELECT started_at FROM tool_calls WHERE id=?",
                        (tcid,)).fetchone()
        dur = 0
        if row:
            try:
                dur = int((datetime.now(timezone.utc)
                           - datetime.fromisoformat(row["started_at"]))
                          .total_seconds() * 1000)
            except Exception:
                dur = 0
        c.execute("UPDATE tool_calls SET finished_at=?,duration_ms=?,status=? "
                  "WHERE id=?", (_now(), dur, status, tcid))
        c.execute("INSERT INTO tool_results(tool_call_id,result_text,error,"
                  "size_bytes) VALUES(?,?,?,?)",
                  (tcid, result_text or "", error,
                   len((result_text or "").encode())))


def db_event(sid, etype, payload):
    with _db_lock, _db() as c:
        c.execute("INSERT INTO events(session_id,ts,event_type,payload_json)"
                  " VALUES(?,?,?,?)",
                  (sid, _now(), etype, json.dumps(payload, ensure_ascii=False)))


# ---------------------------------------------------------------------------
# Client MCP officiel — session stdio persistante (thread asyncio dédié)
# ---------------------------------------------------------------------------
class MCPClient:
    def __init__(self):
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()
        self._session = None
        self._tools = []
        self._ctx = []
        fut = asyncio.run_coroutine_threadsafe(self._connect(), self._loop)
        fut.result(timeout=120)

    async def _connect(self):
        params = StdioServerParameters(command=PYTHON, args=[str(MCP_SERVER)])
        cm = stdio_client(params)
        read, write = await cm.__aenter__()
        self._ctx.append(cm)
        scm = ClientSession(read, write)
        self._session = await scm.__aenter__()
        self._ctx.append(scm)
        await self._session.initialize()
        self._tools = list((await self._session.list_tools()).tools)
        log.info("mcp_connected", tools=len(self._tools))

    @property
    def tools(self):
        return self._tools

    def tool_names(self):
        return [t.name for t in self._tools]

    def schema_of(self, name):
        return next((t.inputSchema for t in self._tools if t.name == name), {}) or {}

    def call_tool(self, name, arguments, timeout=180.0):
        if self._session is None:
            return {"error": "mcp_not_connected"}
        try:
            fut = asyncio.run_coroutine_threadsafe(
                self._session.call_tool(name, arguments=arguments), self._loop)
            res = fut.result(timeout=timeout)
            text = "\n".join(getattr(c, "text", "") for c in
                             (getattr(res, "content", None) or []))
            return {"content": text,
                    "is_error": bool(getattr(res, "isError", False))}
        except Exception as e:
            return {"error": str(e)}


db_init()
MCP = MCPClient()
KNOWN = set(MCP.tool_names())

# ---------------------------------------------------------------------------
# Validation technique d'arguments (le contrôleur valide, le modèle décide)
# ---------------------------------------------------------------------------
def validate_args(name, args):
    schema = MCP.schema_of(name)
    props = schema.get("properties", {}) or {}
    required = schema.get("required", []) or []
    if not isinstance(args, dict):
        return None, "arguments must be an object"
    missing = [k for k in required if k not in args or args[k] in (None, "")]
    if missing:
        return None, f"missing required: {', '.join(missing)}"
    clean = {}
    for k, v in args.items():
        spec = props.get(k)
        if spec is None:
            continue  # argument inconnu -> ignoré (tolérance), le serveur tranchera
        t = spec.get("type", "string")
        try:
            if t == "integer":
                v = int(v)
            elif t == "number":
                v = float(v)
            elif t == "boolean" and isinstance(v, str):
                v = v.lower() in ("1", "true", "yes")
            elif t == "string":
                v = str(v)
        except (ValueError, TypeError):
            return None, f"wrong type for '{k}' (expected {t})"
        clean[k] = v
    return clean, None


# ---------------------------------------------------------------------------
# Ollama — tool calling NATIF si le modèle le supporte, sinon convention texte.
# Phi-4 reste libre : le system prompt décrit les outils et la liberté
# d'action ; la convention TOOL:/ARGS: n'est qu'un canal technique proposé.
# ---------------------------------------------------------------------------
def ollama_tools_schema():
    out = []
    for t in MCP.tools:
        s = t.inputSchema or {}
        out.append({"type": "function", "function": {
            "name": t.name,
            "description": (t.description or f"Outil MCP {t.name}")[:400],
            "parameters": {"type": "object",
                           "properties": s.get("properties", {}) or {},
                           "required": s.get("required", []) or []}}})
    return out


# Cache des capacites par modele (decouvert a la 1ere erreur Ollama).
# Confirme par diagnostic 2026-08-19 :
# - gemma3-4b-it-abliterated : HTTP 400 "does not support tools" -> on
#   bascule sur use_tools=False (convention texte TOOL:/ARGS: du prompt).
# - qwen3 : modele "thinking" -> sans think:false, tout le budget
#   num_predict est consomme en raisonnement interne et content="".
_MODEL_CAPS = {}  # model -> {"tools": bool}


def _post_ollama(payload, timeout):
    req = urllib.request.Request(
        OLLAMA_CHAT, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def ollama_chat(messages, model, max_tokens=400, temperature=0.0,
                timeout=900, use_tools=True):
    caps = _MODEL_CAPS.setdefault(model, {"tools": True})
    payload = {"model": model, "messages": messages, "stream": False,
               "options": {"temperature": temperature, "num_predict": max_tokens}}
    # qwen3 et autres modeles a raisonnement : coupe le thinking interne
    # pour que num_predict serve la reponse, pas la reflexion cachee.
    if "qwen3" in model or "deepseek-r1" in model or "qwq" in model:
        payload["think"] = False
    if use_tools and caps["tools"]:
        payload["tools"] = ollama_tools_schema()
    try:
        d = _post_ollama(payload, timeout)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode()
        except Exception:
            pass
        # Le modele ne supporte pas les tools -> desactivation permanente
        # pour ce modele et retry immediat sans tools (canal texte).
        if e.code == 400 and "does not support tools" in body and "tools" in payload:
            caps["tools"] = False
            log.info("model_no_native_tools", model=model)
            payload.pop("tools")
            d = _post_ollama(payload, timeout)
        else:
            raise
    # done_reason=length + contenu vide : le budget a ete mange (souvent
    # par le thinking residuel). Un seul retry a budget x3.
    if (d.get("done_reason") == "length" and not _content(d)
            and not (d.get("message", {}) or {}).get("tool_calls")):
        payload["options"]["num_predict"] = max_tokens * 3
        log.info("ollama_retry_extended_budget", model=model,
                 num_predict=max_tokens * 3)
        d = _post_ollama(payload, timeout)
    return d


def cloud_chat(messages, model, max_tokens=400, temperature=0.0,
               timeout=180, use_tools=True, backend="openrouter"):
    """Appel OpenAI-compatible pour les backends cloud du portail
    (openrouter / nvidia / colab). Zéro impact sur le serveur MCP :
    c'est juste le cerveau du portail qui change d'endpoint.
    Retourne le même dict interne que ollama_chat (normalisé)."""
    cfg = CLOUD_BACKENDS.get(backend)
    if not cfg:
        raise ValueError(f"backend inconnu: {backend}")
    if not cfg["key"]:
        raise RuntimeError(f"clé API manquante pour {backend} "
                           f"(variable d'env requise)")
    model_id = model or cfg["model"]
    payload = {"model": model_id, "messages": messages,
               "temperature": temperature, "max_tokens": max_tokens,
               "stream": False}
    if use_tools:
        tools = [{"type": "function",
                  "function": {"name": n, "description": d,
                               "parameters": s}}
                 for n, d, s in ((t.name, t.description or "",
                                  t.inputSchema or {}) for t in MCP.tools)]
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
    import httpx
    headers = {"Authorization": f"Bearer {cfg['key']}",
               "Content-Type": "application/json"}
    if backend == "openrouter":
        headers["HTTP-Referer"] = "http://localhost:8100"
        headers["X-OpenRouter-Title"] = "MCP-Kali Portal"
    r = httpx.post(f"{cfg['url']}/chat/completions", json=payload,
                   headers=headers, timeout=timeout)
    r.raise_for_status()
    d = r.json()
    choice = (d.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    usage = d.get("usage") or {}
    # Normalisation vers le format interne (style Ollama) attendu par la
    # boucle agent : message.content + message.tool_calls + compteurs.
    return {
        "message": {"content": msg.get("content") or "",
                    "tool_calls": msg.get("tool_calls") or []},
        "prompt_eval_count": usage.get("prompt_tokens", 0),
        "eval_count": usage.get("completion_tokens", 0),
        "done_reason": choice.get("finish_reason", "stop"),
        "_backend": backend, "_model": model_id,
    }


def llm_chat(messages, model=None, max_tokens=400, temperature=0.0,
             timeout=180, use_tools=True):
    """Route un appel vers Ollama ou un provider OpenAI-compatible."""
    requested = model or DEFAULT_MODEL
    backend, model_id = resolve_backend(requested)
    if backend == "local":
        return ollama_chat(messages, model_id, max_tokens, temperature,
                           timeout=timeout, use_tools=use_tools)
    return cloud_chat(messages, model_id, max_tokens, temperature,
                      timeout=timeout, use_tools=use_tools, backend=backend)


def _content(d):
    return (d.get("message", {}) or {}).get("content", "") or ""


def _native_calls(d):
    """tool_calls natifs Ollama (modèles qui le supportent)."""
    tc = (d.get("message", {}) or {}).get("tool_calls") or []
    out = []
    for c in tc:
        fn = c.get("function", {})
        name = fn.get("name")
        if name in KNOWN:
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            out.append((name, args))
    return out


_TOOL_RE = re.compile(r"TOOL\s*:\s*([A-Za-z_][A-Za-z0-9_]*)", re.I)
_ARGS_MARK_RE = re.compile(r"ARGS\s*:", re.I)


def _args_json_after(content, pos):
    """Extrait le 1er objet JSON equilibre ({...}) apres la position pos.
    Gere l'imbrication (contrairement a une regex non-gourmande qui casse
    sur {"a": {"b": 1}}) et les accolades dans les chaines."""
    i = content.find("{", pos)
    if i < 0:
        return None
    for cand in _json_objects(content[i:]):
        return cand
    return None


def parse_text_call(content):
    """Convention texte pour les modèles sans tool_calls natifs (phi-4-mini).
    Accepte TOOL:/ARGS: et les blocs JSON de function-call. Aucune autre
    contrainte de format n'est imposée au modèle."""
    if not content:
        return None
    m = _TOOL_RE.search(content)
    if m and m.group(1) in KNOWN:
        name = m.group(1)
        args = {}
        am = _ARGS_MARK_RE.search(content, m.end())
        if am:
            raw = _args_json_after(content, am.end())
            if raw:
                try:
                    args = json.loads(raw)
                except json.JSONDecodeError:
                    args = {}
        return name, args
    # Fallback JSON — STRICT: extraction equilibree (gere l'imbrication) +
    # structure d'intention explicite requise ("tool", "function", ou "name"
    # accompagne de "arguments"/"args", ou "done"). Un {"name": "..."} isole
    # dans du texte narratif n'est PAS un appel d'outil.
    for cand in _json_objects(content):
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        if "done" in obj:  # signal de fin explicite, pas un appel
            continue
        name = None
        args = {}
        if "tool" in obj:  # format strict: {"tool": ..., "args"/"arguments": ...}
            name = obj.get("tool")
            args = obj.get("args") or obj.get("arguments") or {}
        elif isinstance(obj.get("function"), dict):  # style natif
            name = obj["function"].get("name")
            args = obj["function"].get("arguments") or {}
        elif "name" in obj and ("arguments" in obj or "args" in obj):
            name = obj.get("name")
            args = obj.get("arguments") or obj.get("args") or {}
        if name in KNOWN:
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            if not isinstance(args, dict):
                args = {}
            return name, args
    return None


# Détecteur de NARRATION d'outil (phi-4-mini) : le modèle décrit qu'il va
# appeler un outil au lieu d'émettre les lignes TOOL:/ARGS:. On ne le
# transforme PAS en appel (trop risqué) ; on renvoie un recentrage borné.
# Heuristique : mention d'un nom d'outil connu OU d'un vocabulaire d'appel
# ("appeler", "requête API", "utiliser l'outil"...) SANS ligne TOOL:.
_NARRATION_HINTS = re.compile(
    r"(?:appeler?|appelle|requ[êe]te\s+api|utiliser?\s+l['’]?outil|"
    r"function[_\s]?call|call\s+the\s+tool|faire\s+une\s+requ[êe]te|"
    r"invoquer|ex[ée]cuter\s+l['’]?outil|nous\s+devrions|je\s+vais\s+appeler|"
    r"recherchez?\s+l['’]?outil|acc[ée]der\s+[àa]\s+un\s+outil|"
    r"j['’]aurais\s+besoin\s+d['’]acc[ée]der|besoin\s+d['’]un\s+outil|"
    r"s['’]il\s+existe\s+un\s+outil|si\s+un\s+outil)",
    re.IGNORECASE)
# Mention générique d'un outil/du système d'outils (phi-4 ne cite pas
# toujours le nom exact ; il parle d'« un outil disponible »).
_TOOL_WORD = re.compile(r"\b(?:outil|tool|outils|tools)\b", re.IGNORECASE)


def looks_like_tool_narration(content):
    """True si le texte NARRE un appel d'outil sans le formater.
    Sert uniquement à décider d'un recentrage borné, jamais à exécuter."""
    if not content:
        return False
    if _TOOL_RE.search(content):   # déjà bien formaté -> pas de narration
        return False
    low = content.lower()
    mentions_tool = (any(k.lower() in low for k in KNOWN)
                     or bool(_TOOL_WORD.search(content)))
    return bool(_NARRATION_HINTS.search(content) and mentions_tool)


def suggest_tools(query, limit=8):
    """Suggère des noms d'outils du catalogue pertinents pour `query`,
    par recouvrement de tokens. Sert à recentrer un petit modèle (phi-4)
    qui hallucine un nom au lieu d'en choisir un du catalogue."""
    import re as _re
    qtokens = set(_re.findall(r"[a-zàâçéèêëîïôûùüÿ0-9]+", (query or "").lower()))
    # quelques synonymes FR -> mots-clés de noms d'outils
    syn = {"tache": "task", "taches": "task", "tâche": "task",
           "tâches": "task", "liste": "list", "lister": "list",
           "statut": "status", "etat": "status", "scan": "scan",
           "reseau": "network", "réseau": "network", "port": "port"}
    for fr, en in syn.items():
        if fr in qtokens:
            qtokens.add(en)
    scored = []
    for name in KNOWN:
        ntoks = set(name.lower().replace("-", "_").split("_"))
        overlap = len(qtokens & ntoks)
        if overlap:
            scored.append((overlap, name))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [n for _, n in scored[:limit]]


def _json_objects(text):
    """Genere les sous-chaines JSON equilibrees ({...}) en gerant
    l'imbrication et les chaines (accolades dans les strings ignorees)."""
    depth = 0
    start = -1
    in_str = False
    esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    yield text[start:i + 1]
                    start = -1


def system_prompt():
    """Contexte système 'liberté' — pas de routeur, pas de prison JSON."""
    lines = []
    for t in MCP.tools:
        s = t.inputSchema or {}
        req = s.get("required", []) or []
        props = s.get("properties", {}) or {}
        params = ", ".join(f"{p}({props.get(p, {}).get('type', 'string')})"
                           for p in req) or "aucun"
        lines.append(f"- {t.name}: requis: {params}")
    catalog = "\n".join(lines)
    return f"""Tu es l'agent de raisonnement de cette session.

Tu peux analyser librement la demande, réfléchir, utiliser les outils
disponibles, enchaîner plusieurs outils lorsque cela est pertinent, comparer
leurs résultats, changer d'approche si nécessaire et produire une conclusion.
Tu n'es JAMAIS obligé d'utiliser un outil : réponds directement quand ce n'est
pas nécessaire.

Quand un outil est utile, appelle-le sur deux lignes exactement ainsi :
TOOL: nom_exact
ARGS: {{"parametre": "valeur"}}

EXEMPLE — pour « liste les taches », ecris exactement :
TOOL: list_tasks
ARGS: {{}}

CRUCIAL : pour appeler un outil, ECRIS les deux lignes TOOL:/ARGS: — ne
raconte JAMAIS ce que tu ferais (« je vais appeler… », « nous devrions… »,
« pour utiliser l'outil… »). Soit tu ecris TOOL:/ARGS:, soit tu reponds
directement a la question. Toute narration d'un appel sans les lignes
TOOL:/ARGS: est un echec.

Ne suppose jamais qu'un outil a réussi : vérifie son résultat. N'utilise pas
un outil uniquement parce qu'il existe. Choisis librement la méthode la plus
pertinente.

RÈGLE D'HONNÊTETÉ (absolue) :
- Ne PRÉTENDS JAMAIS avoir exécuté un outil que tu n'as pas réellement appelé
  via TOOL:/ARGS:. Un outil n'est « exécuté » que si tu vois un bloc
  « Résultat de l'outil … » dans la conversation.
- N'INVENTE JAMAIS de résultat, de sortie, de score, de statut ni de valeur.
  Ne rapporte QUE ce qui apparaît littéralement dans un « Résultat de l'outil ».
- Une tâche démarrée en arrière-plan (status=background_started) N'EST PAS
  terminée : tu dois appeler check_task(task_id) pour obtenir le vrai résultat.
  Tant que check_task n'a pas renvoyé les données, dis « en cours », jamais
  « terminé » ni « réussi ».
- Si l'utilisateur te demande « quels résultats as-tu obtenus ? », liste
  UNIQUEMENT les outils réellement appelés dans cette session et leur sortie
  réelle. S'il n'y en a aucun, dis-le clairement. Ne fabrique pas une liste.

Outils MCP disponibles (découverte dynamique) :
{catalog}

{DISCLAIMER}"""


# ---------------------------------------------------------------------------
# Rate limiting (10 req/min/IP sur les endpoints de chat)
# ---------------------------------------------------------------------------
_hits = defaultdict(deque)


def rate_ok(ip, limit=10, window=60):
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        return False
    q.append(now)
    return True


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------
app = FastAPI(title="MCP Control Room v2")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"])
_STOP = {}
_usage = {"requests": 0, "tool_calls": 0, "tokens_in": 0, "tokens_out": 0}


def _sse(obj):
    return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"


# Un-escape les sequences \uXXXX (et \n litteraux) laissees par un outil MCP
# qui a serialise sa sortie avec ensure_ascii=True. Sans ca, l'UI affiche
# litteralement "\u26a0\ufe0f", "lanc\u00e9e", "arri\u00e8re" au lieu des
# accents/emoji. Robuste : si le decodage echoue, on renvoie le texte brut.
_UNICODE_ESCAPE_RE = re.compile(r'\\u[0-9a-fA-F]{4}')


def deescape_unicode(text: str) -> str:
    if not isinstance(text, str) or '\\u' not in text:
        return text
    try:
        # Ne touche QUE les sequences \uXXXX pour ne pas casser des backslashes
        # legitimes (chemins Windows, regex) presents dans une sortie d'outil.
        return _UNICODE_ESCAPE_RE.sub(
            lambda m: m.group(0).encode('ascii').decode('unicode_escape'), text)
    except (UnicodeDecodeError, ValueError):
        return text


class ChatIn(BaseModel):
    message: str
    session_id: str | None = None
    model: str | None = None
    backend: str | None = None
    max_steps: int = 10
    temperature: float = 0.0
    max_tokens: int = 500


@app.get("/", response_class=HTMLResponse)
def index():
    return INDEX.read_text(encoding="utf-8")


@app.get("/api/disclaimer")
def disclaimer():
    return {"disclaimer": DISCLAIMER}


@app.get("/api/health")
def health():
    return {"status": "ok", "version": "2.1",
            "model_default": DEFAULT_MODEL,
            "backends": {name: bool(cfg["key"])
                         for name, cfg in CLOUD_BACKENDS.items()},
            "mcp_connected": MCP._session is not None,
            "tools_count": len(MCP.tools),
            "disclaimer": DISCLAIMER}


@app.get("/api/backends")
def backends():
    """Liste les backends LLM du portail (local Ollama + cloud).
    Le serveur MCP reste indépendant : il tourne seul de son côté."""
    out = {"local": {"available": True, "type": "ollama",
                     "url": OLLAMA_TAGS.rsplit("/api/", 1)[0]}}
    for name, cfg in CLOUD_BACKENDS.items():
        out[name] = {"available": bool(cfg["key"]),
                     "type": "openai-compatible",
                     "url": cfg["url"], "model_default": cfg["model"]}
    return {"backends": out}


@app.get("/api/models")
def models():
    warning = None
    try:
        with urllib.request.urlopen(OLLAMA_TAGS, timeout=10) as r:
            data = json.loads(r.read().decode())
        local_models = [m["name"] for m in data.get("models", [])]
    except Exception as e:
        local_models = [DEFAULT_MODEL]
        warning = str(e)
    # Entrées cloud (préfixe backend:modele). Listées seulement si la clé
    # d'env est configurée — sinon le provider reste invisible dans l'UI.
    cloud = [f"{name}:{cfg['model']}" for name, cfg in CLOUD_BACKENDS.items()
             if cfg["key"]]
    resp = {"models": local_models + cloud,
            "cloud_configured": sorted(n for n, c in CLOUD_BACKENDS.items()
                                       if c["key"])}
    if warning:
        resp["warning"] = warning
    return resp


@app.get("/api/tools")
def tools():
    out = []
    for t in MCP.tools:
        s = t.inputSchema or {}
        out.append({"name": t.name,
                    "description": (t.description or "")[:500],
                    "schema": {"properties": s.get("properties", {}) or {},
                               "required": s.get("required", []) or []}})
    return {"count": len(out), "tools": out}


@app.get("/logs", response_class=HTMLResponse)
def logs_page():
    """Page d'observabilité : commandes réellement exécutées + logs bruts."""
    return LOGS_PAGE.read_text(encoding="utf-8")


@app.get("/api/tools/log")
def tools_log(session: str = "", limit: int = 100):
    """Journal d'exécution des outils MCP : commande réelle + sortie brute.

    Le modèle ne sert que d'orchestrateur ; CETTE vue montre ce qui a
    réellement tourné côté MCP (nom, arguments, durée, statut, sortie).
    """
    limit = max(1, min(int(limit), 500))
    with _db() as c:
        q = ("SELECT tc.id, tc.session_id, tc.tool_name, tc.arguments_json, "
             "tc.started_at, tc.finished_at, tc.duration_ms, tc.status, "
             "tr.result_text, tr.error, tr.size_bytes "
             "FROM tool_calls tc "
             "LEFT JOIN tool_results tr ON tr.tool_call_id = tc.id ")
        params = []
        if session:
            q += "WHERE tc.session_id=? "
            params.append(session)
        q += "ORDER BY tc.id DESC LIMIT ?"
        params.append(limit)
        rows = [dict(r) for r in c.execute(q, params).fetchall()]
    for r in rows:
        try:
            r["arguments"] = json.loads(r.pop("arguments_json") or "{}")
        except (json.JSONDecodeError, TypeError):
            r["arguments"] = {}
        txt = r.get("result_text") or ""
        r["result_text"] = deescape_unicode(txt)[:20000]
    return {"count": len(rows), "calls": rows}


# -- Sessions ---------------------------------------------------------------
@app.get("/api/sessions")
def sessions_list(q: str = "", limit: int = 50, offset: int = 0):
    with _db_lock, _db() as c:
        if q:
            rows = c.execute(
                "SELECT DISTINCT s.* FROM sessions s LEFT JOIN messages m "
                "ON m.session_id=s.id WHERE s.title LIKE ? OR m.content LIKE ? "
                "ORDER BY s.updated_at DESC LIMIT ? OFFSET ?",
                (f"%{q}%", f"%{q}%", limit, offset)).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM sessions ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (limit, offset)).fetchall()
    return {"sessions": [dict(r) for r in rows]}


@app.post("/api/sessions")
def session_create(payload: dict):
    model = (payload or {}).get("model", DEFAULT_MODEL)
    title = (payload or {}).get("title", "")
    sid = db_create_session(model, title)
    db_event(sid, "session_created", {"model": model})
    return {"session_id": sid}


@app.get("/api/sessions/{sid}")
def session_get(sid: str):
    with _db_lock, _db() as c:
        s = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not s:
            return JSONResponse({"error": "not_found"}, status_code=404)
        msgs = [dict(r) for r in c.execute(
            "SELECT * FROM messages WHERE session_id=? ORDER BY id", (sid,))]
        tcs = [dict(r) for r in c.execute(
            "SELECT * FROM tool_calls WHERE session_id=? ORDER BY id", (sid,))]
        evs = [dict(r) for r in c.execute(
            "SELECT * FROM events WHERE session_id=? ORDER BY id", (sid,))]
    return {"session": dict(s), "messages": msgs, "tool_calls": tcs,
            "events": evs}


@app.patch("/api/sessions/{sid}")
def session_rename(sid: str, payload: dict):
    db_touch(sid, title=(payload or {}).get("title", ""),
             status=(payload or {}).get("status"))
    return {"ok": True}


@app.delete("/api/sessions/{sid}")
def session_delete(sid: str):
    with _db_lock, _db() as c:
        for table, col in (("messages", "session_id"), ("events", "session_id"),
                           ("tool_calls", "session_id"),
                           ("sessions", "id")):
            c.execute(f"DELETE FROM {table} WHERE {col}=?", (sid,))
    return {"ok": True}


@app.get("/api/sessions/{sid}/export")
def session_export(sid: str, format: str = "json"):
    data = session_get(sid)
    if isinstance(data, JSONResponse):
        return data
    if format == "jsonl":
        lines = [json.dumps({"type": "session", **data["session"]},
                            ensure_ascii=False)]
        for m in data["messages"]:
            lines.append(json.dumps({"type": "message", **m},
                                    ensure_ascii=False))
        for tc in data["tool_calls"]:
            lines.append(json.dumps({"type": "tool_call", **tc},
                                    ensure_ascii=False))
        return PlainTextResponse("\n".join(lines),
                                 media_type="application/x-ndjson")
    if format == "md":
        out = [f"# Session {sid}", f"_{data['session']['created_at']} — "
               f"modèle {data['session']['model']}_", "",
               f"> {DISCLAIMER}", ""]
        tcs = {t["id"]: t for t in data["tool_calls"]}
        for m in data["messages"]:
            out.append(f"## {m['role'].upper()} — {m['ts']}")
            out.append(m["content"] or "")
            out.append("")
        for t in data["tool_calls"]:
            out.append(f"### TOOL {t['tool_name']} ({t['status']}, "
                       f"{t['duration_ms']}ms)")
            out.append(f"```json\n{t['arguments_json']}\n```")
        return PlainTextResponse("\n".join(out), media_type="text/markdown")
    return data


# -- Agent loop (SSE) ---------------------------------------------------------
@app.post("/api/chat/stream")
def chat_stream(req: ChatIn, request: Request):
    ip = request.client.host if request.client else "?"
    if not rate_ok(ip):
        return JSONResponse({"error": "rate_limit", "detail":
                             "10 req/min max"}, status_code=429)
    model = req.model or DEFAULT_MODEL
    # The selected backend is authoritative; Colab uses its gateway model when
    # the client did not explicitly provide a model prefixed with colab:.
    if req.backend in CLOUD_BACKENDS and req.backend != "local":
        model = req.model if req.model and req.model.startswith(req.backend + ":") else f"{req.backend}:"
    backend, model_id = resolve_backend(model)
    sid = req.session_id or db_create_session(model,
                                              title=req.message[:60])
    db_touch(sid)
    stop = _STOP.setdefault(sid, threading.Event())
    stop.clear()
    _usage["requests"] += 1

    def gen():
        usage = {"prompt_tokens": 0, "completion_tokens": 0}
        executed = set()
        results_log = []
        step = 0
        val_errs = 0  # erreurs de validation consecutives (anti-boucle)
        narration_nudges = 0  # recentrages "narration d'outil" (borné, phi-4)
        yield _sse({"type": "session", "session_id": sid, "model": model})
        log.bind(session=sid).info("user_message", text=req.message[:200])
        db_message(sid, "user", req.message)
        db_event(sid, "user_message", {"text": req.message[:500]})

        # Historique de session (reprise) : 12 derniers messages
        with _db_lock, _db() as c:
            hist = c.execute(
                "SELECT role,content FROM messages WHERE session_id=? "
                "ORDER BY id DESC LIMIT 12", (sid,)).fetchall()
        messages = [{"role": "system", "content": system_prompt()}]
        for h in reversed(hist):
            if h["role"] in ("user", "assistant"):
                messages.append({"role": h["role"], "content": h["content"]})
            elif h["role"] == "tool":
                # Resultats d'outils persistes (fix reprise de session) :
                # re-injectes en role 'user' pour rester compatibles avec
                # les modeles sans support natif du role 'tool'.
                messages.append({"role": "user",
                                 "content": f"[historique outil] "
                                            f"{h['content'][:1500]}"})
            # role 'tool_call' : ligne technique de trace, non rechargee
            # (le resultat persiste via le message 'tool' ci-dessus).

        while step < req.max_steps:
            if stop.is_set():
                db_event(sid, "stopped", {"step": step})
                yield _sse({"type": "stopped", "step": step})
                return
            yield _sse({"type": "thinking", "step": step + 1})
            t0 = time.time()
            try:
                if backend == "local":
                    d = ollama_chat(messages, model, req.max_tokens,
                                    req.temperature, use_tools=True)
                else:
                    d = cloud_chat(messages, model_id, req.max_tokens,
                                   req.temperature, use_tools=True,
                                   backend=backend)
            except Exception as e:
                log.bind(session=sid).error("llm_error", backend=backend,
                                            error=str(e))
                db_event(sid, "error", {"stage": backend, "error": str(e)})
                yield _sse({"type": "error", "message": f"{backend}: {e}"})
                return
            latency_ms = int((time.time() - t0) * 1000)
            usage["prompt_tokens"] += d.get("prompt_eval_count", 0)
            usage["completion_tokens"] += d.get("eval_count", 0)
            _usage["tokens_in"] += d.get("prompt_eval_count", 0)
            _usage["tokens_out"] += d.get("eval_count", 0)
            content = _content(d)
            log.bind(session=sid).info("llm_step", step=step + 1,
                                       latency_ms=latency_ms,
                                       out_chars=len(content))

            calls = _native_calls(d)
            if not calls:
                parsed = parse_text_call(content)
                calls = [parsed] if parsed else []

            if not calls:
                # Recentrage borné : le modèle NARRE un appel d'outil (phi-4)
                # sans émettre TOOL:/ARGS:. On lui rappelle le format une fois
                # (max 2) au lieu de traiter la narration comme réponse finale.
                if (looks_like_tool_narration(content)
                        and narration_nudges < 2):
                    narration_nudges += 1
                    sugg = suggest_tools(req.message)
                    sugg_txt = (("Outils pertinents du catalogue : "
                                 + ", ".join(sugg) + ".\n") if sugg else "")
                    db_event(sid, "tool_narration_nudge",
                             {"attempt": narration_nudges, "suggested": sugg})
                    messages.append({"role": "assistant", "content": content})
                    messages.append({"role": "user", "content":
                        "Tu as DÉCRIT un appel d'outil sans l'émettre, ou tu as "
                        "inventé un nom d'outil. Choisis un nom EXACT du "
                        "catalogue système (ne l'invente pas).\n"
                        + sugg_txt +
                        "Réponds MAINTENANT avec exactement ces deux lignes "
                        "(rien d'autre) :\n"
                        "TOOL: nom_exact_du_catalogue\n"
                        "ARGS: {}\n"
                        "Sinon, réponds directement à la question sans "
                        "mentionner d'outil."})
                    continue
                # Réponse finale en langage naturel — Phi reste libre
                db_message(sid, "assistant", content,
                           d.get("prompt_eval_count", 0), d.get("eval_count", 0))
                db_event(sid, "final", {"usage": usage})
                db_touch(sid, status="done")
                yield _sse({"type": "final", "reply": content,
                            "usage": usage})
                return

            name, args = calls[0]
            db_message(sid, "assistant", content,
                       d.get("prompt_eval_count", 0), d.get("eval_count", 0))

            # Contrôleur technique : validation schéma + anti-boucle
            clean, verr = validate_args(name, args)
            if verr:
                val_errs += 1
                db_event(sid, "validation_error",
                         {"tool": name, "args": args, "error": verr,
                          "consecutive": val_errs})
                if val_errs >= 3:
                    # Sans ce garde-fou, `continue` ne consomme aucun step :
                    # un modele qui repete des arguments invalides boucle a
                    # l'infini (ni budget d'etapes ni timeout ne bornent la
                    # boucle). 3 echecs consecutifs -> arret propre.
                    reply = (f"Validation impossible apres {val_errs} "
                             f"tentatives consecutives ({name}: {verr}). "
                             "Boucle interrompue par le controleur. "
                             "Resultats obtenus :\n\n"
                             + "\n\n".join(results_log)[-3000:])
                    db_touch(sid, status="validation_abort")
                    yield _sse({"type": "final", "reply": reply,
                                "usage": usage})
                    return
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content":
                                 f"Erreur technique de validation pour "
                                 f"{name}: {verr}. Corrige les arguments ou "
                                 f"choisis une autre approche."})
                continue
            val_errs = 0  # validation reussie -> reset du compteur
            sig = f"{name}{json.dumps(clean, sort_keys=True)}"
            if sig in executed:
                # check_task / list_tasks sont des outils de POLLING : un appel
                # identique répété est légitime (le statut évolue). On n'ajoute
                # pas ces signatures à l'anti-boucle, sinon impossible de poller
                # une tâche background plus d'une fois par session.
                if name in ("check_task", "list_tasks", "get_task_stats"):
                    pass  # polling autorisé, pas de blocage
                else:
                    reply = ("Appel identique déjà exécuté — boucle interrompue "
                             "par le contrôleur. Résultats obtenus :\n\n"
                             + "\n\n".join(results_log)[-3000:])
                    db_event(sid, "duplicate_call_blocked", {"tool": name})
                    yield _sse({"type": "final", "reply": reply, "usage": usage})
                    return
            else:
                executed.add(sig)
            step += 1
            _usage["tool_calls"] += 1
            yield _sse({"type": "tool_call", "step": step, "tool": name,
                        "arguments": clean})
            mid = db_message(sid, "tool_call",
                             f"{name} {json.dumps(clean, ensure_ascii=False)}")
            tcid = db_tool_call(sid, mid, name, clean)
            t1 = time.time()
            result = MCP.call_tool(name, clean)
            dur_ms = int((time.time() - t1) * 1000)
            if result.get("error"):
                text, status, err = "", "error", result["error"]
            else:
                text = result.get("content", "") or "(sortie vide)"
                text = deescape_unicode(text)  # \u26a0 -> emoji lisible
                status = "error" if result.get("is_error") else "ok"
                err = None
            db_tool_finish(tcid, status, text[:20000], err)
            db_event(sid, "tool_result", {"tool": name, "status": status,
                                          "duration_ms": dur_ms})
            log.bind(session=sid).info("tool_call", tool=name, status=status,
                                       duration_ms=dur_ms)
            results_log.append(f"[{name} {json.dumps(clean)}] {text[:2000]}")
            yield _sse({"type": "tool_result", "step": step, "tool": name,
                        "status": status, "duration_ms": dur_ms,
                        "result": text[:8000]})
            # Détection tâche background : si l'outil renvoie
            # {"status": "background_started", "task_id": ...}, on injecte
            # une consigne de polling explicite vers check_task (sinon le
            # modèle ne sait pas que le résultat arrive plus tard).
            poll_hint = ""
            if '"background_started"' in text and '"task_id"' in text:
                try:
                    tid = json.loads(text).get("task_id", "")
                except (json.JSONDecodeError, AttributeError):
                    tid = ""
                if tid:
                    poll_hint = (f"\n\n[TACHE EN ARRIERE-PLAN] L'outil a démarré "
                                 f"en tâche de fond (task_id={tid}). Pour suivre "
                                 f"sa progression, appelle check_task avec "
                                 f"task_id=\"{tid}\". Le scan peut prendre "
                                 f"plusieurs minutes — tu peux continuer d'autres "
                                 f"actions entre deux vérifications.")
            # Persiste le resultat dans l'historique (role 'tool') : sans
            # cela, une reprise de session rechargeait les echanges user/
            # assistant mais perdait TOUT le contexte des resultats d'outils.
            db_message(sid, "tool", f"[{name}] {text[:2500]}")
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user", "content":
                             f"Résultat de l'outil {name} :\n{text[:2500]}\n\n"
                             "Analyse ce résultat et décide librement de la "
                             "suite (autre outil ou conclusion)." + poll_hint})
        db_touch(sid, status="max_steps")
        yield _sse({"type": "final",
                    "reply": "Budget d'étapes atteint. Résultats :\n\n"
                             + "\n\n".join(results_log)[-3000:],
                    "usage": usage})

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.post("/api/chat/stop")
def chat_stop(payload: dict):
    sid = (payload or {}).get("session_id", "")
    flag = _STOP.get(sid)
    if flag:
        flag.set()
        db_event(sid, "stop_requested", {})
    return {"stopped": bool(flag), "session_id": sid}


# ---------------------------------------------------------------------------
# ALIAS DE COMPATIBILITE V1 (2026-08-17)
# L'UI (index.html) appelle /api/agent, /api/agent/loop, /api/agent/stop.
# server_v2 n'exposait que /api/chat/* -> UI cassee. On re-expose le contrat
# v1 en deleguant a la logique v2 (memes SSE events: session/thinking/
# tool_call/tool_result/final/stopped/error).
# ---------------------------------------------------------------------------
_TARGET_RE = re.compile(
    r"((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|\b\d{1,3}(?:\.\d{1,3}){3}\b|https?://\S+)")


def _arguments_for(tool_name: str, arg):
    """Mappe l'argument libre vers le 1er param requis du schema reel."""
    schema = MCP.schema_of(tool_name)
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
    """Si le message nomme explicitement UN SEUL outil connu -> execution
    immediate (sans attendre le LLM)."""
    low = (message or "").lower()
    hits = [name for name in KNOWN if name.lower() in low]
    if len(hits) != 1:
        return None
    name = hits[0]
    m = _TARGET_RE.search(message or "")
    arg = m.group(1) if m else None
    return name, _arguments_for(name, arg)


class AgentRequest(BaseModel):
    message: str
    tool: str | None = None
    tool_arg: str | None = None
    reasoning: bool = False
    summarize: bool = False
    temperature: float = 0.0
    max_tokens: int = 300
    model: str | None = None
    backend: str | None = None
class LoopRequest(BaseModel):
    message: str
    session_id: str | None = None
    max_steps: int = 8
    reasoning: bool = False
    temperature: float = 0.0
    max_tokens: int = 350
    model: str | None = None
    backend: str | None = None


@app.post("/api/agent")
def agent_direct(req: AgentRequest, request: Request):
    """Chemin rapide v1 : outil epingle/nomme -> execution directe."""
    ip = request.client.host if request.client else "?"
    if not rate_ok(ip):
        return JSONResponse({"error": "rate_limit", "detail":
                             "10 req/min max"}, status_code=429)
    tool = req.tool
    args: dict = {}
    if tool and tool not in KNOWN:
        return {"error": f"outil inconnu: {tool}",
                "known_tools": sorted(KNOWN)}
    if not tool:
        routed = _pre_route(req.message)
        if routed:
            tool, args = routed
    if not tool:
        try:
            requested_model = req.model or DEFAULT_MODEL
            if req.backend in CLOUD_BACKENDS and req.backend != "local":
                requested_model = req.model if req.model and req.model.startswith(req.backend + ":") else f"{req.backend}:"
            d = llm_chat([{"role": "user", "content": req.message}],
                         requested_model, req.max_tokens, req.temperature,
                         use_tools=False)
        except Exception as e:
            return {"error": f"llm: {e}"}
        usage = {"prompt_tokens": d.get("prompt_eval_count", 0),
                 "completion_tokens": d.get("eval_count", 0)}
        _usage["tokens_in"] += d.get("prompt_eval_count", 0)
        _usage["tokens_out"] += d.get("eval_count", 0)
        return {"reply": _content(d), "executed": None, "usage": usage}
    if not args:
        args = _arguments_for(tool, req.tool_arg or req.message)
    clean, verr = validate_args(tool, args)
    if verr:
        return {"error": f"validation: {verr}", "tool": tool}
    result = MCP.call_tool(tool, clean)
    if result.get("error"):
        text = f"ERREUR outil: {result['error']}"
    else:
        text = result.get("content", "") or "(sortie vide)"
    reply = text
    usage: dict = {"prompt_tokens": 0, "completion_tokens": 0}
    if req.summarize and not result.get("error"):
        try:
            requested_model = req.model or DEFAULT_MODEL
            if req.backend in CLOUD_BACKENDS and req.backend != "local":
                requested_model = req.model if req.model and req.model.startswith(req.backend + ":") else f"{req.backend}:"
            d = llm_chat(
                [{"role": "user", "content":
                  f"Resultat de l'outil {tool}:\n{text[:3000]}\n\n"
                  "Resume ce resultat en francais, de facon concise."}],
                requested_model, req.max_tokens, req.temperature,
                use_tools=False)
            usage = {"prompt_tokens": d.get("prompt_eval_count", 0),
                     "completion_tokens": d.get("eval_count", 0)}
            reply = _content(d) or text
        except Exception:
            reply = text
    return {
        "reply": reply,
        "executed": {
            "tool": tool,
            "arguments": clean,
            "result": {"content": [{"text": text}],
                       "is_error": bool(result.get("is_error") or
                                        result.get("error"))},
        },
        "usage": usage,
    }


@app.post("/api/agent/loop")
def agent_loop_alias(req: LoopRequest, request: Request):
    """Alias v1 -> boucle autonome v2 (/api/chat/stream). Meme contrat SSE."""
    return chat_stream(
        ChatIn(message=req.message, session_id=req.session_id,
               max_steps=req.max_steps, temperature=req.temperature,
               max_tokens=req.max_tokens, model=req.model, backend=req.backend),
        request)


@app.post("/api/agent/stop")
def agent_stop_alias(payload: dict):
    """Alias v1 -> /api/chat/stop."""
    return chat_stop(payload)


@app.get("/api/metrics")
def metrics():
    with _db_lock, _db() as c:
        n_sess = c.execute("SELECT COUNT(*) n FROM sessions").fetchone()["n"]
        n_tc = c.execute("SELECT COUNT(*) n FROM tool_calls").fetchone()["n"]
        ok = c.execute("SELECT COUNT(*) n FROM tool_calls WHERE status='ok'"
                       ).fetchone()["n"]
    return {"usage": _usage, "sessions_total": n_sess,
            "tool_calls_total": n_tc,
            "tool_success_rate": round(ok / n_tc, 3) if n_tc else None,
            "tools_discovered": len(MCP.tools)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8100)
