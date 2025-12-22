from typing import Dict
import re

class TriageEngine:
    """Analyse les résultats et génère la stratégie optimale"""
    
    @staticmethod
    def detect_defenses(recon_data: Dict) -> Dict[str, bool]:
        """Détecte la présence de protections comme Cloudflare ou WAF"""
        defenses = {
            'cloudflare_detected': False,
            'waf_detected': False,
            'rate_limiting_detected': False
        }
        
        # Check for Cloudflare in service banners and headers
        services = recon_data.get("services", [])
        for service in services:
            product = service.get("product", "").lower()
            if "cloudflare" in product:
                defenses['cloudflare_detected'] = True
                break
        
        # Check for WAF signatures in HTTP headers
        http_headers = recon_data.get("http_headers", {})
        waf_signatures = [
            'cloudflare', 'akamai', 'imperva', 'f5', 'fortinet', 
            'barracuda', 'sucuri', 'awselb', 'incapsula'
        ]
        
        for header_value in http_headers.values():
            header_lower = str(header_value).lower()
            for signature in waf_signatures:
                if signature in header_lower:
                    if signature == 'cloudflare':
                        defenses['cloudflare_detected'] = True
                    else:
                        defenses['waf_detected'] = True
        
        return defenses
    
    @staticmethod
    def generate_plan(recon_data: Dict) -> Dict:
        plan = {"priority": "low", "steps": [], "strategy": "standard"}
        
        open_ports = recon_data.get("open_ports", [])
        
        # Détecter les défenses
        defenses = TriageEngine.detect_defenses(recon_data)
        
        # Choisir la stratégie en fonction des défenses
        if defenses['cloudflare_detected']:
            plan["strategy"] = "STEALTH + DISTRIBUTED"
            plan["steps"].append("1. Activer Ghost Mode (ghost_mode_toggle enable=true)")
            plan["steps"].append("2. Lancer une attaque distribuée (distributed_assault)")
            plan["steps"].append("3. Vérifier le statut avec check_task")
            plan["priority"] = "high"
        elif defenses['waf_detected']:
            plan["strategy"] = "STEALTH_ONLY"
            plan["steps"].append("1. Activer Ghost Mode (ghost_mode_toggle enable=true)")
            plan["steps"].append("2. Reconnaissance tactique (tactical_recon)")
            plan["priority"] = "high"
        else:
            plan["strategy"] = "STANDARD"
        
        # Logique décisionnelle basée sur les ports
        if "80" in open_ports or "443" in open_ports:
            if not defenses['cloudflare_detected'] and not defenses['waf_detected']:
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
