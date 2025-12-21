import re
import json
from typing import Dict

class OSINTHunter:
    """Module de vérification de légitimité et OSINT"""
    
    def __init__(self, executor):
        self.executor = executor

    async def check_legitimacy(self, domain: str) -> Dict:
        """Analyse multi-facteurs pour détecter un scam ou phishing"""
        
        # 1. WHOIS (Âge du domaine)
        whois_data, _ = await self.executor.run_command(f"whois {domain}")
        creation_date = re.search(r"(Creation Date|created|Registered on):?\s*(.*)", whois_data, re.I)
        
        # 2. SSL Analysis
        ssl_data, _ = await self.executor.run_command(f"timeout 5 openssl s_client -connect {domain}:443 -servername {domain} < /dev/null 2>/dev/null | openssl x509 -noout -issuer -dates")
        
        # 3. Réputation IP (via DNSBL ou similar)
        
        score = 0
        flags = []
        date_str = "Unknown"
        
        if creation_date:
            date_str = creation_date.group(2).strip()
            if "2024" in date_str or "2025" in date_str:
                score += 40
                flags.append("Domaine très récent (Risque élevé)")
        
        if "Let's Encrypt" in ssl_data:
            flags.append("Certificat gratuit (Commun chez les scams)")
            score += 10

        return {
            "domain": domain,
            "risk_score": score,
            "verdict": "SUSPECT" if score >= 50 else "CLEAN",
            "flags": flags,
            "details": {"creation": date_str}
        }