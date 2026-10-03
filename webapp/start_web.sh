#!/bin/bash
# MCP-Clean Portal — démarrage reproductible (port 8098)
# Prérequis: Ollama actif sur 127.0.0.1:11434 avec le modèle phi-4.
set -e
cd "$(dirname "$0")/.."

echo "=== [1/3] venv + dépendances ==="
python3 -m venv venv 2>/dev/null || true
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet fastapi "uvicorn[standard]"

echo "=== [2/3] Vérification Ollama + modèle phi-4 ==="
MODEL="hf.co/mradermacher/Phi-4-Mini-Abliterated-GGUF:Q4_K_M"
if ! curl -s -m 5 http://127.0.0.1:11434/api/tags | grep -q "Phi-4-Mini-Abliterated"; then
  echo "Modèle phi-4 absent, pull en cours (peut prendre du temps)..."
  ollama pull "$MODEL"
fi

echo "=== [3/3] Portail sur :8100 ==="
cd webapp
exec uvicorn server:app --host 0.0.0.0 --port 8100
