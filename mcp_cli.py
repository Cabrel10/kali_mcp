#!/usr/bin/env python3
"""mcp_cli.py — utilise les 63 outils MCP directement en terminal.

Usage:
    python mcp_cli.py list                       # liste les outils
    python mcp_cli.py call <outil> <arg>         # exécute un outil
    python mcp_cli.py call dns_recon example.com
    python mcp_cli.py call nmap_scan 192.168.1.1
    python mcp_cli.py call server_health
"""
import json
import subprocess
import sys
import threading

PYTHON = "/home/ubuntu/webapp/MORNINGSTAR/miniconda3/envs/trading_env/bin/python"
SERVER = "/home/ubuntu/webapp/MORNINGSTAR/mcp/kali_mcp_clean/MCP-Kali-Server/kali_mcp_server_optimized.py"

# Argument principal attendu par outil (fallback "target")
ARG_KEY = {
    "dns_recon": "domain", "osint_whois_info": "domain",
    "osint_domain_reputation": "domain", "subdomain_enum": "domain",
    "check_site_legitimacy": "domain", "web_tech_detect": "url",
    "nmap_scan": "target", "execute_command": "command",
}


class MCP:
    def __init__(self):
        self.proc = subprocess.Popen(
            [PYTHON, SERVER], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.lock = threading.Lock()
        self._id = 0

    def _next(self):
        self._id += 1
        return self._id

    def _send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def _read(self, rid, timeout=120):
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
        return {"error": "timeout"}

    def init(self):
        r = self._send_and_wait("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "mcp-cli", "version": "1.0"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return r

    def _send_and_wait(self, method, params=None, timeout=120):
        with self.lock:
            rid = self._next()
            msg = {"jsonrpc": "2.0", "id": rid, "method": method}
            if params is not None:
                msg["params"] = params
            self._send(msg)
            return self._read(rid, timeout)

    def list_tools(self):
        return self._send_and_wait("tools/list", {}).get("tools", [])

    def call(self, name, args, timeout=120):
        return self._send_and_wait("tools/call",
                                   {"name": name, "arguments": args}, timeout)

    def close(self):
        try:
            self.proc.terminate()
        except Exception:
            pass


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    mcp = MCP()
    mcp.init()

    if cmd == "list":
        tools = mcp.list_tools()
        print(f"{len(tools)} outils MCP:")
        for t in tools:
            print(" -", t.get("name"))
    elif cmd == "call":
        if len(sys.argv) < 3:
            print("usage: mcp_cli.py call <outil> [arg]")
            mcp.close()
            return
        tool = sys.argv[2]
        arg = sys.argv[3] if len(sys.argv) > 3 else None
        key = ARG_KEY.get(tool, "target")
        args = {key: arg} if arg else {}
        res = mcp.call(tool, args)
        content = res.get("content", [])
        if content and isinstance(content, list):
            print(content[0].get("text", json.dumps(res, indent=2)))
        else:
            print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        print(__doc__)
    mcp.close()


if __name__ == "__main__":
    main()
