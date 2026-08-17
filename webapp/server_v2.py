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
INDEX = BASE / "index_v2.html"
DB_PATH = BASE / "portal_history.db"
LOG_DIR = BASE / "logs"
LOG_DIR.mkdir(exist_ok=True)

MCP_SERVER = (BASE.parent / "MCP-Kali-Server" / "kali_mcp_server_optimized.py")
PYTHON = "/home/ubuntu/webapp/MORNINGSTAR/miniconda3/envs/trading_env/bin/python"
OLLAMA_CHAT = "http://127.0.0.1:11434/api/chat"
OLLAMA_TAGS = "http://127.0.0.1:11434/api/tags"
DEFAULT_MODEL = "hf.co/mradermacher/Phi-4-Mini-Abliterated-GGUF:Q4_K_M"

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


def ollama_chat(messages, model, max_tokens=400, temperature=0.0,
                timeout=900, use_tools=True):
    payload = {"model": model, "messages": messages, "stream": False,
               "options": {"temperature": temperature, "num_predict": max_tokens}}
    if use_tools:
        payload["tools"] = ollama_tools_schema()
    req = urllib.request.Request(
        OLLAMA_CHAT, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


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
_ARGS_RE = re.compile(r"ARGS\s*:\s*(\{.*?\})\s*(?:\n|$)", re.I | re.S)


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
        am = _ARGS_RE.search(content)
        if am:
            try:
                args = json.loads(am.group(1))
            except json.JSONDecodeError:
                args = {}
        return name, args
    for jm in re.finditer(r"\{[^{}]*\}", content):
        try:
            obj = json.loads(jm.group(0))
        except json.JSONDecodeError:
            continue
        name = (obj.get("function") or {}).get("name") or obj.get("name")
        if name in KNOWN:
            args = (obj.get("function") or {}).get("arguments") \
                or obj.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            return name, args
    return None


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

Ne suppose jamais qu'un outil a réussi : vérifie son résultat. N'utilise pas
un outil uniquement parce qu'il existe. Choisis librement la méthode la plus
pertinente.

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


class ChatIn(BaseModel):
    message: str
    session_id: str | None = None
    model: str | None = None
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
    return {"status": "ok", "version": "2.0",
            "model_default": DEFAULT_MODEL,
            "mcp_connected": MCP._session is not None,
            "tools_count": len(MCP.tools),
            "disclaimer": DISCLAIMER}


@app.get("/api/models")
def models():
    try:
        with urllib.request.urlopen(OLLAMA_TAGS, timeout=10) as r:
            data = json.loads(r.read().decode())
        return {"models": [m["name"] for m in data.get("models", [])]}
    except Exception as e:
        return {"models": [DEFAULT_MODEL], "warning": str(e)}


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

        while step < req.max_steps:
            if stop.is_set():
                db_event(sid, "stopped", {"step": step})
                yield _sse({"type": "stopped", "step": step})
                return
            yield _sse({"type": "thinking", "step": step + 1})
            t0 = time.time()
            try:
                d = ollama_chat(messages, model, req.max_tokens,
                                req.temperature, use_tools=True)
            except Exception as e:
                log.bind(session=sid).error("ollama_error", error=str(e))
                db_event(sid, "error", {"stage": "ollama", "error": str(e)})
                yield _sse({"type": "error", "message": f"ollama: {e}"})
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
                db_event(sid, "validation_error",
                         {"tool": name, "args": args, "error": verr})
                messages.append({"role": "assistant", "content": content})
                messages.append({"role": "user", "content":
                                 f"Erreur technique de validation pour "
                                 f"{name}: {verr}. Corrige les arguments ou "
                                 f"choisis une autre approche."})
                continue
            sig = f"{name}{json.dumps(clean, sort_keys=True)}"
            if sig in executed:
                reply = ("Appel identique déjà exécuté — boucle interrompue "
                         "par le contrôleur. Résultats obtenus :\n\n"
                         + "\n\n".join(results_log)[-3000:])
                db_event(sid, "duplicate_call_blocked", {"tool": name})
                yield _sse({"type": "final", "reply": reply, "usage": usage})
                return
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
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user", "content":
                             f"Résultat de l'outil {name} :\n{text[:2500]}\n\n"
                             "Analyse ce résultat et décide librement de la "
                             "suite (autre outil ou conclusion)."})
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


class LoopRequest(BaseModel):
    message: str
    session_id: str | None = None
    max_steps: int = 8
    reasoning: bool = False
    temperature: float = 0.0
    max_tokens: int = 350
    model: str | None = None


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
            d = ollama_chat([{"role": "user", "content": req.message}],
                            req.model or DEFAULT_MODEL, req.max_tokens,
                            req.temperature, use_tools=False)
        except Exception as e:
            return {"error": f"ollama: {e}"}
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
            d = ollama_chat(
                [{"role": "user", "content":
                  f"Resultat de l'outil {tool}:\n{text[:3000]}\n\n"
                  "Resume ce resultat en francais, de facon concise."}],
                req.model or DEFAULT_MODEL, req.max_tokens, req.temperature,
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
               max_tokens=req.max_tokens, model=req.model),
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
