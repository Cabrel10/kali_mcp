from typing import Dict

class TriageEngine:
    """Analyse les résultats et génère la stratégie optimale"""
    
    @staticmethod
    def generate_plan(recon_data: Dict) -> Dict:
        plan = {"priority": "low", "steps": []}
        
        open_ports = recon_data.get("open_ports", [])
        
        # Logique décisionnelle
        if "80" in open_ports or "443" in open_ports:
            plan["steps"].append("1. Web Discovery (WhatWeb + Httpx)")
            plan["steps"].append("2. Directory Fuzzing (Ffuf)")
            plan["priority"] = "high"
            
        if "445" in open_ports:
            plan["steps"].append("1. SMB Enumeration (NetExec)")
            plan["steps"].append("2. Check for EternalBlue / MS17-010")
            plan["priority"] = "critical"
            
        if "8291" in open_ports:
            plan["steps"].append("1. MikroTik Winbox Exploit Check")
            plan["priority"] = "high"

        return plan
