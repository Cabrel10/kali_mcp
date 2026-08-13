"""MCP-Clean Portal — backend FastAPI (port 8098).

Sert le portail web et proxifie les requêtes chat vers Ollama (phi-4).
La box est CPU-only et partagée avec l'entraînement ADAN : la génération
phi-4 est lente (~0.4 tok/s sous charge), d'où un timeout généreux.
"""
import json
import urllib.request
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
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


class ChatRequest(BaseModel):
    prompt: str
    num_predict: int = 150
    temperature: float = 0.7


@app.get("/", response_class=HTMLResponse)
def root():
    return INDEX.read_text(encoding="utf-8")


@app.get("/api/health")
def health():
    return {"status": "ok", "model": MODEL}


@app.post("/api/chat")
def chat(req: ChatRequest):
    # Laisse phi-4 s'exprimer : prompt passé tel quel, pas de censure ajoutée,
    # température configurable, jusqu'à 1024 tokens.
    payload = json.dumps({
        "model": MODEL,
        "prompt": req.prompt,
        "stream": False,
        "options": {
            "temperature": req.temperature,
            "num_predict": min(req.num_predict, 1024),
        },
    }).encode()
    http_req = urllib.request.Request(
        OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(http_req, timeout=180) as r:
            d = json.loads(r.read().decode())
            return {
                "response": d.get("response", "").strip(),
                "model": MODEL,
                "eval_count": d.get("eval_count"),
                "eval_seconds": round(d.get("eval_duration", 0) / 1e9, 1),
            }
    except Exception as e:
        return {"error": str(e), "model": MODEL}


@app.post("/api/mcp/execute")
def mcp_execute(tool: str, domain: str = ""):
    # Stub : l'exécution réelle des 63 outils passe par le serveur
    # FastMCP stdio (MCP-Kali-Server/kali_mcp_server_optimized.py).
    return {"status": "ok", "tool": tool, "domain": domain}
