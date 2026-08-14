"""MCP-Clean Portal — console MCP complète (port 8100).

Architecture :
- Frontend  : console (gauche = outils par catégorie, droite = historique
              d'échanges, haut = tokens session + toggle reasoning).
- Backend   : /api/agent utilise le function-calling Ollama (/api/chat avec
              un schéma `tools`). Si phi-4 appelle un outil, on l'exécute pour
              de vrai via le serveur FastMCP stdio (kali_mcp_server_optimized.py)
              puis on renvoie le résultat au modèle pour la réponse finale.

La box est CPU-only et partagée avec l'entraînement ADAN -> génération lente,
d'où des timeouts généreux et un fallback si le modèle n'appelle pas d'outil.
"""
import json
import re
import threading
import urllib.request
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

app = FastAPI(title="MCP-Clean Console")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

OLLAMA_CHAT = "http://127.0.0.1:11434/api/chat"
OLLAMA_GENERATE = "http://127.0.0.1:11434/api/generate"
MODEL = "hf.co/mradermacher/Phi-4-Mini-Abliterated-GGUF:Q4_K_M"
INDEX = Path(__file__).parent / "index.html"
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
    summarize: bool = False          # synthèse phi-4 (lent sous contention CPU)
    temperature: float = 0.2
    max_tokens: int = 300


# ---------------------------------------------------------------------------
# Serveur MCP stdio (un process réutilisé, thread-safe)
# ---------------------------------------------------------------------------
import subprocess


class MCPServer:
    """Client JSON-RPC vers le serveur FastMCP stdio (process persistant)."""

    def __init__(self):
        self.proc = None
        self.lock = threading.Lock()
        self._id = 0

    def _ensure(self):
        if self.proc is None or self.proc.poll() is not None:
            self.proc = subprocess.Popen(
                [PYTHON, str(MCP_SERVER)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, bufsize=1,
            )
            self._send({"jsonrpc": "2.0", "id": self._next(), "method": "initialize",
                        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                   "clientInfo": {"name": "portal", "version": "1.0"}}})
            self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _next(self):
        self._id += 1
        return self._id

    def _send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def list_tools(self):
        with self.lock:
            self._ensure()
            rid = self._next()
            self._send({"jsonrpc": "2.0", "id": rid, "method": "tools/list", "params": {}})
            return self._read_result(rid).get("tools", [])

    def call_tool(self, name, arguments, timeout=120):
        with self.lock:
            self._ensure()
            rid = self._next()
            self._send({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                        "params": {"name": name, "arguments": arguments}})
            return self._read_result(rid, timeout=timeout)

    def _read_result(self, rid, timeout=30):
        import time
        start = time.time()
        while time.time() - start < timeout:
            line = self.proc.stdout.readline()
            if not line:
                break
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("id") == rid:
                return obj.get("result", obj)
        return {}


MCP = MCPServer()


def _list_mcp_tools() -> list[str]:
    try:
        src = MCP_SERVER.read_text(encoding="utf-8", errors="replace")
        tools = re.findall(
            r"@mcp\.tool\(\)(?:[^\n]*\n){1,6}?\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)",
            src,
        )
        return sorted({t for t in tools if not t.startswith("_")})
    except Exception:
        return []


def _ollama_tools_schema():
    """Schéma function-calling (format OpenAI) pour un sous-ensemble sûr d'outils."""
    safe = ["dns_recon", "osint_whois_info", "osint_domain_reputation",
            "subdomain_enum", "web_tech_detect", "check_site_legitimacy",
            "nmap_scan", "server_health", "list_tasks"]
    params = {
        "dns_recon": {"domain": "string"},
        "osint_whois_info": {"domain": "string"},
        "osint_domain_reputation": {"domain": "string"},
        "subdomain_enum": {"domain": "string"},
        "web_tech_detect": {"url": "string"},
        "check_site_legitimacy": {"domain": "string"},
        "nmap_scan": {"target": "string"},
        "server_health": {},
        "list_tasks": {},
    }
    out = []
    for name in safe:
        props = {k: {"type": v} for k, v in params.get(name, {}).items()}
        out.append({
            "type": "function",
            "function": {
                "name": name,
                "description": f"Exécute l'outil MCP {name}",
                "parameters": {
                    "type": "object",
                    "properties": props,
                    "required": list(props.keys()),
                },
            },
        })
    return out


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def root():
    return INDEX.read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    return {"status": "ok", "model": MODEL, "mcp_server": MCP_SERVER.name}


@app.get("/api/tools")
def tools():
    live = _list_mcp_tools()
    return {"count": len(live), "tools": live, "categories": TOOL_CATEGORIES}


def _call_ollama_chat(messages, tools=None, max_tokens=300, temperature=0.2):
    payload = {"model": MODEL, "messages": messages, "stream": False,
               "options": {"temperature": temperature, "num_predict": max_tokens}}
    if tools:
        payload["tools"] = tools
    req = urllib.request.Request(
        OLLAMA_CHAT, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.loads(r.read().decode())


def _token_usage(d):
    return {
        "prompt_tokens": d.get("prompt_eval_count", 0),
        "completion_tokens": d.get("eval_count", 0),
    }


@app.post("/api/agent")
def agent(req: AgentRequest):
    """Un tour d'agent : phi-4 décide d'un outil -> on l'exécute -> réponse."""
    usage = {"prompt_tokens": 0, "completion_tokens": 0}
    executed = None

    try:
        # Mode "outil forcé" (clic sur le panneau) : on exécute directement.
        if req.tool:
            arg = req.tool_arg or req.message
            arguments = _arguments_for(req.tool, arg)
            result = MCP.call_tool(req.tool, arguments)
            executed = {"tool": req.tool, "arguments": arguments, "result": result}
            # Sans summarize : on renvoie le résultat réel immédiatement,
            # sans attendre phi-4 (lent quand le CPU est saturé par ADAN).
            if not req.summarize:
                return {"reply": _tool_text(result), "executed": executed,
                        "usage": usage, "summary": False}
            # Demande à phi-4 de résumer le résultat réel.
            summary_prompt = (
                f"Tu as exécuté l'outil {req.tool} avec {arguments}. "
                f"Voici le résultat brut :\n{_tool_text(result)[:2000]}\n\n"
                "Résume en français, de façon concise et factuelle."
            )
            d = _call_ollama_chat(
                [{"role": "user", "content": summary_prompt}],
                max_tokens=req.max_tokens, temperature=req.temperature)
            _acc(usage, d)
            return {"reply": _content(d), "executed": executed, "usage": usage,
                    "summary": True}

        # Mode conversation : on donne le schéma d'outils à phi-4.
        system = (
            "Tu es un assistant de sécurité offensif. Tu as accès à des outils MCP. "
            "Quand la demande correspond à un outil, appelle-le via un tool_call. "
            "Sinon réponds directement et clairement en français."
        )
        if req.reasoning:
            system += " Réfléchis étape par étape avant de répondre."
        messages = [{"role": "system", "content": system},
                    {"role": "user", "content": req.message}]
        d = _call_ollama_chat(messages, tools=_ollama_tools_schema(),
                              max_tokens=req.max_tokens, temperature=req.temperature)
        _acc(usage, d)
        msg = d.get("message", {})

        # phi-4 a appelé un outil ?
        tool_calls = msg.get("tool_calls") or []
        if tool_calls:
            fn = tool_calls[0].get("function", {})
            name = fn.get("name")
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            result = MCP.call_tool(name, args)
            executed = {"tool": name, "arguments": args, "result": result}
            messages.append(msg)
            messages.append({"role": "tool", "name": name,
                             "content": _tool_text(result)[:2000]})
            d2 = _call_ollama_chat(messages, max_tokens=req.max_tokens,
                                   temperature=req.temperature)
            _acc(usage, d2)
            return {"reply": _content(d2), "executed": executed, "usage": usage}

        return {"reply": _content(d) or msg.get("content", ""), "executed": None,
                "usage": usage}
    except Exception as e:
        return {"reply": "", "error": str(e), "executed": executed, "usage": usage}


def _arguments_for(tool, value):
    domain_tools = {"dns_recon", "osint_whois_info", "osint_domain_reputation",
                    "subdomain_enum", "check_site_legitimacy", "locate_origin"}
    url_tools = {"web_tech_detect", "sql_injection_test", "xss_scan", "lfi_scan"}
    target_tools = {"nmap_scan", "arp_scan", "tactical_recon", "smart_scanner"}
    if tool in domain_tools:
        return {"domain": value}
    if tool in url_tools:
        return {"url": value, "param": "id"} if tool != "web_tech_detect" else {"url": value}
    if tool in target_tools:
        return {"target": value}
    return {}


def _tool_text(result):
    content = result.get("content") or []
    if content and isinstance(content, list):
        return "\n".join(c.get("text", "") for c in content if isinstance(c, dict))
    return json.dumps(result)[:2000]


def _content(d):
    return (d.get("message", {}) or {}).get("content", "")


def _acc(usage, d):
    u = _token_usage(d)
    usage["prompt_tokens"] += u["prompt_tokens"]
    usage["completion_tokens"] += u["completion_tokens"]


# Compatibilité ascendante : ancien chat non-streaming (tests courts).
@app.post("/api/chat")
def chat(req: ChatRequest):
    payload = json.dumps({"model": MODEL, "prompt": req.prompt, "stream": False,
                          "options": {"temperature": req.temperature,
                                      "num_predict": min(req.num_predict, 1024)}}).encode()
    req2 = urllib.request.Request(OLLAMA_GENERATE, data=payload,
                                  headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req2, timeout=600) as r:
            d = json.loads(r.read().decode())
            return {"response": d.get("response", "").strip(), "model": MODEL,
                    "eval_count": d.get("eval_count")}
    except Exception as e:
        return {"error": str(e), "model": MODEL}


@app.post("/api/chat/stream")
def chat_stream(req: ChatRequest):
    payload = json.dumps({"model": MODEL, "prompt": req.prompt, "stream": True,
                          "options": {"temperature": req.temperature,
                                      "num_predict": min(req.num_predict, 1024)}}).encode()
    req2 = urllib.request.Request(OLLAMA_GENERATE, data=payload,
                                  headers={"Content-Type": "application/json"})

    def gen():
        try:
            with urllib.request.urlopen(req2, timeout=900) as r:
                for raw in r:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    yield f"data: {json.dumps({'token': chunk.get('response', ''), 'done': chunk.get('done', False)})}\n\n"
                    if chunk.get("done"):
                        break
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")
