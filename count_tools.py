#!/usr/bin/env python3
"""Compte et catégorise les outils déclarés dans le serveur MCP Kali."""
import re
from pathlib import Path

SRC = Path(__file__).parent / "MCP-Kali-Server" / "kali_mcp_server_optimized.py"
src = SRC.read_text(encoding="utf-8", errors="replace")

# Décorés explicitement par @mcp.tool()
decorated = set(re.findall(r"@mcp\.tool\(\)[^\n]*\n(?:[^\n]*\n){0,3}?def\s+([A-Za-z_][A-Za-z0-9_]*)", src))
# Toutes les fonctions définies
alldefs = set(re.findall(r"^def\s+([A-Za-z_][A-Za-z0-9_]*)\(", src, re.M))

HELPERS = {"generate_timestamp", "sanitize_filename", "run_command_advanced"}

print("Fichier:", SRC.name)
print("Total fonctions def:", len(alldefs))
print("Decorées @mcp.tool():", len(decorated))
public_decorated = sorted(t for t in decorated if not t.startswith("_") and t not in HELPERS)
print("Outils publics (décorés, non-helpers):", len(public_decorated))
for t in public_decorated:
    print("  -", t)
