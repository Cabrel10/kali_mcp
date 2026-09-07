#!/bin/bash
# MCP-Clean — redéploiement reproductible (portail :8100)
# Usage: git clone <repo> && cd kali_mcp_clean && ./redeploy.sh
set -e
cd "$(dirname "$0")"

git fetch origin
git checkout genspark_ai_developer
git pull origin genspark_ai_developer

# Stoppe l'instance courante du portail (port 8100)
PID=$(ss -tlnp 2>/dev/null | grep ':8100' | grep -oP 'pid=\K[0-9]+' | head -1 || true)
[ -n "$PID" ] && kill "$PID" 2>/dev/null || true

# Démarre le portail (start_web.sh fait venv + deps + check modèle Ollama)
nohup ./webapp/start_web.sh > /tmp/mcp_portal.log 2>&1 &
sleep 4
curl -sf http://127.0.0.1:8100/api/health && echo " -> portail OK :8100"
