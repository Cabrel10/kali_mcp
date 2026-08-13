"""MCP-Clean Portal — backend FastAPI (port 8100).

Sert le portail web et proxifie les requêtes chat vers Ollama (phi-4).
La box est CPU-only et partagée avec l'entraînement ADAN : la génération
phi-4 est lente (~0.25 tok/s sous charge). Le mode non-streaming dépasse
donc facilement les timeouts navigateur -> le portail utilise le STREAMING
(SSE) : les tokens arrivent au fur et à mesure et phi-4 peut s'exprimer.
"""
import json
import re
import urllib.request
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

app = FastAPI(title="MCP-Clean Portal")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "hf.co/mradermacher/Phi-4-Mini-Abliterated-GGUF:Q4_K_M"
INDEX = Path(__file__).parent / "index.html"
MCP_SERVER_SRC = (
    Path(__file__).parent.parent / "MCP-Kali-Server" / "kali_mcp_server_optimized.py"
)


class ChatRequest(BaseModel):
    prompt: str
    num_predict: int = 150
    temperature: float = 0.7


def _list_mcp_tools() -> list[str]:
    """Extrait les noms des outils déclarés via @mcp.tool() dans le serveur.

    Les handlers sont des `async def` indentés ; on capture le def qui suit
    chaque décorateur @mcp.tool() (fenêtre de quelques lignes).
    """
    try:
        src = MCP_SERVER_SRC.read_text(encoding="utf-8", errors="replace")
        tools = re.findall(
            r"@mcp\.tool\(\)(?:[^\n]*\n){1,6}?\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)",
            src,
        )
        return sorted({t for t in tools if not t.startswith("_")})
    except Exception:
        return []


@app.get("/", response_class=HTMLResponse)
def root():
    return INDEX.read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    return {"status": "ok", "model": MODEL}


@app.get("/api/tools")
def tools():
    """Liste les outils exposés par le serveur MCP Kali."""
    t = _list_mcp_tools()
    return {"count": len(t), "tools": t}


def _ollama_payload(req: ChatRequest, stream: bool) -> bytes:
    return json.dumps({
        "model": MODEL,
        "prompt": req.prompt,
        "stream": stream,
        "options": {
            "temperature": req.temperature,
            "num_predict": min(req.num_predict, 1024),
        },
    }).encode()


@app.post("/api/chat")
def chat(req: ChatRequest):
    """Mode non-streaming (pour tests courts uniquement — lent sous charge)."""
    http_req = urllib.request.Request(
        OLLAMA_URL, data=_ollama_payload(req, stream=False),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(http_req, timeout=600) as r:
            d = json.loads(r.read().decode())
            return {
                "response": d.get("response", "").strip(),
                "model": MODEL,
                "eval_count": d.get("eval_count"),
                "eval_seconds": round(d.get("eval_duration", 0) / 1e9, 1),
            }
    except Exception as e:
        return {"error": str(e), "model": MODEL}


@app.post("/api/chat/stream")
def chat_stream(req: ChatRequest):
    """Streaming SSE : relaie chaque ligne NDJSON d'Ollama dès qu'elle arrive.

    Le navigateur affiche les tokens progressivement -> plus de timeout
    perçu même si phi-4 génère lentement (box CPU-only sous charge ADAN).
    """
    http_req = urllib.request.Request(
        OLLAMA_URL, data=_ollama_payload(req, stream=True),
        headers={"Content-Type": "application/json"},
    )

    def event_generator():
        try:
            with urllib.request.urlopen(http_req, timeout=900) as r:
                for raw in r:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    # Format SSE: data: {...}\n\n
                    yield f"data: {json.dumps({'token': chunk.get('response', ''), 'done': chunk.get('done', False)})}\n\n"
                    if chunk.get("done"):
                        break
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/mcp/execute")
def mcp_execute(tool: str, domain: str = ""):
    # Stub : l'exécution réelle des 63 outils passe par le serveur
    # FastMCP stdio (MCP-Kali-Server/kali_mcp_server_optimized.py).
    return {"status": "ok", "tool": tool, "domain": domain}
