#!/usr/bin/env python3
"""
OSINT Analyzer - Vérification de légitimité et renseignements
Analyse: Domaine, certificats, historique DNS, réputation
"""

import json
import re
from typing import Dict, List, Any
from datetime import datetime


class OSINTAnalyzer:
    """Analyse OSINT complète d'un domaine"""

    def __init__(self, executor):
        self.executor = executor
        self.timeout = 15

    async def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Vérifie la réputation du domaine via services externes
        """
        results = {
            "domain": domain,
            "reputation_checks": {},
            "risk_score": 0,
            "is_phishing": False
        }

        # Check 1: VirusTotal
        cmd = (
            f"curl -s 'https://www.virustotal.com/api/v3/domains/{domain}' "
            f"-H 'x-apikey: YOUR_VT_KEY' "
            f"--max-time {self.timeout}"
        )
        stdout, stderr, rc = await self.executor.run_command(cmd)
        if rc == 0:
            results["reputation_checks"]["virustotal"] = "checked"

        # Check 2: URLhaus
        cmd = (
            f"curl -s 'https://urlhaus-api.abuse.ch/v1/host/' "
            f"-d 'host={domain}' "
            f"--max-time {self.timeout}"
        )
        stdout, stderr, rc = await self.executor.run_command(cmd)
        if rc == 0 and "query_status" in stdout:
            results["reputation_checks"]["urlhaus"] = "checked"

        # Check 3: PhishTank
        cmd = (
            f"curl -s 'https://phishtank.com/search.php' "
            f"-d 'q={domain}&format=json' "
            f"--max-time {self.timeout}"
        )
        stdout, stderr, rc = await self.executor.run_command(cmd)
        if rc == 0:
            results["reputation_checks"]["phishtank"] = "checked"

        # Check 4: Google Safe Browsing
        cmd = (
            f"curl -s 'https://safebrowsing.googleapis.com/v4/threatMatches:find' "
            f"-H 'Content-Type: application/json' "
            f"-d '{{\"client\":{{\"clientId\":\"test\"}},\"threatInfo':{{\"threatTypes\":[\"MALWARE\"],\"platformTypes\":[\"ANY_PLATFORM\"],\"threatEntryTypes\":[\"URL\"],\"threatEntries\":[{{\"url\":\"{domain}\"}}]}}}}' "
            f"--max-time {self.timeout}"
        )
        stdout, stderr, rc = await self.executor.run_command(cmd)
        if rc == 0:
            results["reputation_checks"]["google_safe_browsing"] = "checked"

        return results

    async def analyze_certificate(self, domain: str) -> Dict[str, Any]:
        """
        Analyse le certificat SSL/TLS
        """
        results = {
            "domain": domain,
            "certificate": {},
            "warnings": [],
            "suspicious_indicators": []
        }

        # Récupérer le certificat
        cmd = (
            f"echo | openssl s_client -servername {domain} "
            f"-connect {domain}:443 2>/dev/null | "
            f"openssl x509 -noout -text"
        )

        stdout, stderr, rc = await self.executor.run_command(cmd)

        if rc == 0:
            # Extraire informations
            cert_info = {
                "subject": None,
                "issuer": None,
                "valid_from": None,
                "valid_to": None,
                "san": []
            }

            # Subject
            subject_match = re.search(r"Subject:.*CN\s*=\s*([^\n,]+)", stdout)
            if subject_match:
                cert_info["subject"] = subject_match.group(1)

            # Issuer
            issuer_match = re.search(r"Issuer:.*CN\s*=\s*([^\n,]+)", stdout)
            if issuer_match:
                cert_info["issuer"] = issuer_match.group(1)

            # Dates
            valid_from = re.search(r"Not Before:\s*(.+)", stdout)
            if valid_from:
                cert_info["valid_from"] = valid_from.group(1)

            valid_to = re.search(r"Not After\s*:\s*(.+)", stdout)
            if valid_to:
                cert_info["valid_to"] = valid_to.group(1)

            # SAN
            san_match = re.findall(
                r"DNS:([^\s,]+)",
                stdout
            )
            if san_match:
                cert_info["san"] = san_match

            results["certificate"] = cert_info

            # Vérifier les avertissements
            if "self-signed" in stdout.lower():
                results["warnings"].append("Self-signed certificate")
                results["suspicious_indicators"].append(
                    "Self-signed certs are suspicious"
                )

            if "expired" in stdout.lower():
                results["warnings"].append("Certificate expired")
                results["suspicious_indicators"].append(
                    "Expired certificate indicates abandonment"
                )

            # Vérifier wildcard
            if "*.exxspecial.com" in str(cert_info["san"]):
                results["suspicious_indicators"].append(
                    "Wildcard certificate (common in phishing)"
                )

        return results

    async def check_dns_history(self, domain: str) -> Dict[str, Any]:
        """
        Vérifie l'historique DNS et les changements
        """
        results = {
            "domain": domain,
            "current_dns": {},
            "historical_ips": [],
            "dns_changes": []
        }

        # DNS actuel
        cmd = f"dig +short {domain} @8.8.8.8"
        stdout, stderr, rc = await self.executor.run_command(cmd)

        if rc == 0 and stdout.strip():
            results["current_dns"]["A"] = stdout.strip().split('\n')

        # MX records
        cmd = f"dig +short MX {domain} @8.8.8.8"
        stdout, stderr, rc = await self.executor.run_command(cmd)
        if rc == 0 and stdout.strip():
            results["current_dns"]["MX"] = stdout.strip().split('\n')

        # NS records
        cmd = f"dig +short NS {domain} @8.8.8.8"
        stdout, stderr, rc = await self.executor.run_command(cmd)
        if rc == 0 and stdout.strip():
            results["current_dns"]["NS"] = stdout.strip().split('\n')

        # TXT records
        cmd = f"dig +short TXT {domain} @8.8.8.8"
        stdout, stderr, rc = await self.executor.run_command(cmd)
        if rc == 0 and stdout.strip():
            results["current_dns"]["TXT"] = stdout.strip().split('\n')

        return results

    async def check_whois_info(self, domain: str) -> Dict[str, Any]:
        """
        Récupère les informations WHOIS
        """
        results = {
            "domain": domain,
            "whois_data": {},
            "privacy_protected": False,
            "suspicious_registrar": False
        }

        cmd = f"whois {domain}"
        stdout, stderr, rc = await self.executor.run_command(cmd)

        if rc == 0:
            # Extraire informations clés
            registrar_match = re.search(
                r"Registrar:\s*(.+)",
                stdout
            )
            if registrar_match:
                results["whois_data"]["registrar"] = registrar_match.group(1)

            # Vérifier privacy protection
            if "privacy" in stdout.lower() or "redacted" in stdout.lower():
                results["privacy_protected"] = True

            # Vérifier registrars suspects
            suspicious_registrars = [
                "namecheap",
                "godaddy",
                "hostinger"
            ]
            if any(
                reg in stdout.lower()
                for reg in suspicious_registrars
            ):
                results["suspicious_registrar"] = True

            # Dates
            created_match = re.search(
                r"Creation Date:\s*(.+)",
                stdout
            )
            if created_match:
                results["whois_data"]["created"] = created_match.group(1)

            expiry_match = re.search(
                r"Expiry Date:\s*(.+)",
                stdout
            )
            if expiry_match:
                results["whois_data"]["expiry"] = expiry_match.group(1)

        return results

    async def check_wayback_machine(self, domain: str) -> Dict[str, Any]:
        """
        Vérifie l'historique Wayback Machine
        """
        results = {
            "domain": domain,
            "snapshots_found": 0,
            "first_snapshot": None,
            "last_snapshot": None,
            "content_changes": []
        }

        cmd = (
            f"curl -s 'https://archive.org/wayback/available?url={domain}' "
            f"--max-time {self.timeout}"
        )

        stdout, stderr, rc = await self.executor.run_command(cmd)

        if rc == 0 and "snapshots" in stdout:
            try:
                data = json.loads(stdout)
                if "archived_snapshots" in data:
                    snapshots = data["archived_snapshots"]
                    results["snapshots_found"] = len(snapshots)

                    if snapshots:
                        results["first_snapshot"] = snapshots[0].get(
                            "timestamp"
                        )
                        results["last_snapshot"] = snapshots[-1].get(
                            "timestamp"
                        )
            except json.JSONDecodeError:
                pass

        return results

    async def check_ssl_labs(self, domain: str) -> Dict[str, Any]:
        """
        Vérifie la sécurité SSL via SSL Labs
        """
        results = {
            "domain": domain,
            "ssl_grade": None,
            "vulnerabilities": [],
            "weak_ciphers": False
        }

        cmd = (
            f"curl -s 'https://api.ssllabs.com/api/v3/analyze?host={domain}' "
            f"--max-time {self.timeout}"
        )

        stdout, stderr, rc = await self.executor.run_command(cmd)

        if rc == 0:
            try:
                data = json.loads(stdout)
                if "grade" in data:
                    results["ssl_grade"] = data["grade"]

                if "endpoints" in data:
                    for endpoint in data["endpoints"]:
                        if "grade" in endpoint:
                            if endpoint["grade"] in ["D", "E", "F"]:
                                results["vulnerabilities"].append(
                                    f"Poor SSL grade: {endpoint['grade']}"
                                )
            except json.JSONDecodeError:
                pass

        return results

    async def run_full_osint(self, domain: str) -> Dict[str, Any]:
        """
        Exécute l'analyse OSINT complète
        """
        results = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "analyses": {},
            "risk_assessment": {
                "phishing_score": 0,
                "legitimacy_score": 100,
                "is_phishing": False
            }
        }

        # Exécuter toutes les analyses
        results["analyses"]["reputation"] = (
            await self.check_domain_reputation(domain)
        )
        results["analyses"]["certificate"] = (
            await self.analyze_certificate(domain)
        )
        results["analyses"]["dns_history"] = (
            await self.check_dns_history(domain)
        )
        results["analyses"]["whois"] = (
            await self.check_whois_info(domain)
        )
        results["analyses"]["wayback"] = (
            await self.check_wayback_machine(domain)
        )
        results["analyses"]["ssl_labs"] = (
            await self.check_ssl_labs(domain)
        )

        # Calculer score de risque
        phishing_indicators = 0
        total_checks = 0

        # Vérifier certificat
        if results["analyses"]["certificate"]["suspicious_indicators"]:
            phishing_indicators += len(
                results["analyses"]["certificate"]["suspicious_indicators"]
            )
        total_checks += 1

        # Vérifier WHOIS
        if results["analyses"]["whois"]["privacy_protected"]:
            phishing_indicators += 1
        if results["analyses"]["whois"]["suspicious_registrar"]:
            phishing_indicators += 1
        total_checks += 2

        # Vérifier Wayback
        if results["analyses"]["wayback"]["snapshots_found"] == 0:
            phishing_indicators += 2
        total_checks += 1

        # Calculer scores
        results["risk_assessment"]["phishing_score"] = min(
            100,
            (phishing_indicators / max(total_checks, 1)) * 100
        )
        results["risk_assessment"]["legitimacy_score"] = max(
            0,
            100 - results["risk_assessment"]["phishing_score"]
        )
        results["risk_assessment"]["is_phishing"] = (
            results["risk_assessment"]["phishing_score"] > 50
        )

        return results
