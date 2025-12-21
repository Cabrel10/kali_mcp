import os
import json
import subprocess
import re
from typing import Dict, Any, List

class ReverseExpert:
    """Expert en analyse binaire et reverse engineering statique"""
    
    def __init__(self, executor):
        self.executor = executor

    async def analyze_binary(self, file_path: str) -> Dict[str, Any]:
        """Analyse complète d'un binaire (ELF, EXE, Mach-O)"""
        if not os.path.exists(file_path):
            return {"error": "Fichier introuvable"}

        # 1. Infos de base (Architecture, OS, Langage)
        info, _ = await self.executor.run_command(f"rabin2 -I {file_path}")
        
        # 2. Extraction des strings (Filtrage des données sensibles)
        strings, _ = await self.executor.run_command(f"rabin2 -z {file_path} | grep -E 'http|ssh|key|pass|admin' | tail -n 20")
        
        # 3. Imports/Exports (Capacités réseau/système)
        imports, _ = await self.executor.run_command(f"rabin2 -i {file_path}")
        
        # 4. Détection de packers/entropie
        entropy, _ = await self.executor.run_command(f"r2 -batch -c 'it' {file_path}")

        analysis = {
            "file": os.path.basename(file_path),
            "info": self._parse_rabin_info(info),
            "suspicious_strings": [s.strip() for s in strings.split('\n') if s.strip()],
            "capabilities": self._detect_capabilities(imports),
            "is_packed": "packed" in entropy.lower() or "upx" in info.lower()
        }
        return analysis

    def _parse_rabin_info(self, text: str) -> Dict:
        res = {}
        for line in text.split('\n'):
            if 'arch' in line: res['arch'] = line.split()[-1]
            if 'os' in line: res['os'] = line.split()[-1]
            if 'lang' in line: res['lang'] = line.split()[-1]
        return res

    def _detect_capabilities(self, imports: str) -> List[str]:
        caps = []
        if "socket" in imports: caps.append("Network Communication")
        if "Crypt" in imports: caps.append("Cryptography")
        if "CreateProcess" in imports or "system" in imports: caps.append("Process Execution")
        return caps
