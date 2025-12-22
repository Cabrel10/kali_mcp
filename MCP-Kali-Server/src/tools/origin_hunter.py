#!/usr/bin/env python3
"""
Origin Hunter - Démasquer les serveurs derrière Cloudflare
Trouve l'IP réelle en exploitant les fuites DNS et les enregistrements non protégés
"""

import re
from typing import Dict, Any


class OriginHunter:
    """Localise l'IP réelle d'un serveur derrière Cloudflare"""

    def __init__(self, executor):
        self.executor = executor
        self.cloudflare_ranges = [
            "104.", "172.64.", "172.67.", "108.162.", "162.158.",
            "141.101.", "103.21.", "103.22.", "103.31.", "131.0.72."
        ]

    async def locate_origin(self, domain: str) -> Dict[str, Any]:
        """Tente de trouver l'IP réelle derrière Cloudflare via les fuites DNS"""
        origins = []

        # 1. Test des sous-domaines non protégés (fuites DNS)
        common_leaks = [
            "dev", "staging", "mail", "direct", "vpn", "cpanel", "ftp",
            "mysql", "admin", "api", "test", "backup", "old", "www2",
            "mail2", "smtp", "pop", "imap", "ns1", "ns2", "webmail"
        ]

        for sub in common_leaks:
            subdomain = f"{sub}.{domain}"
            cmd = f"dig +short {subdomain} @8.8.8.8"
            stdout, stderr, return_code = await self.executor.run_command(
                cmd, timeout=10
            )

            if stdout.strip():
                ips = stdout.strip().split('\n')
                for ip in ips:
                    ip = ip.strip()
                    if (ip and self._is_valid_ip(ip) and
                            not self._is_cloudflare(ip)):
                        origins.append({
                            "subdomain": subdomain,
                            "ip": ip,
                            "reason": "Unprotected subdomain leak",
                            "confidence": "HIGH"
                        })

        # 2. Test des enregistrements MX
        mx_cmd = f"dig +short MX {domain} @8.8.8.8"
        mx_stdout, stderr, return_code = await self.executor.run_command(
            mx_cmd, timeout=10
        )

        if mx_stdout.strip():
            for line in mx_stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 2:
                    mx_host = parts[-1].rstrip('.')
                    ip_cmd = f"dig +short {mx_host} @8.8.8.8"
                    ip_out, stderr, return_code = (
                        await self.executor.run_command(ip_cmd, timeout=10)
                    )

                    if ip_out.strip():
                        for ip in ip_out.strip().split('\n'):
                            ip = ip.strip()
                            if (ip and self._is_valid_ip(ip) and
                                    not self._is_cloudflare(ip)):
                                origins.append({
                                    "mx_record": mx_host,
                                    "ip": ip,
                                    "reason": "Mail server leak",
                                    "confidence": "HIGH"
                                })

        # 3. Test des enregistrements TXT
        txt_cmd = f"dig +short TXT {domain} @8.8.8.8"
        txt_stdout, stderr, return_code = await self.executor.run_command(
            txt_cmd, timeout=10
        )

        if txt_stdout.strip():
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            for ip in re.findall(ip_pattern, txt_stdout):
                if not self._is_cloudflare(ip):
                    origins.append({
                        "txt_record": "SPF/DKIM",
                        "ip": ip,
                        "reason": "IP found in TXT records",
                        "confidence": "MEDIUM"
                    })

        # 4. Test des enregistrements NS
        ns_cmd = f"dig +short NS {domain} @8.8.8.8"
        ns_stdout, stderr, return_code = await self.executor.run_command(
            ns_cmd, timeout=10
        )

        if ns_stdout.strip():
            for ns_host in ns_stdout.strip().split('\n'):
                ns_host = ns_host.strip().rstrip('.')
                if ns_host:
                    ip_cmd = f"dig +short {ns_host} @8.8.8.8"
                    ip_out, stderr, return_code = (
                        await self.executor.run_command(ip_cmd, timeout=10)
                    )

                    if ip_out.strip():
                        for ip in ip_out.strip().split('\n'):
                            ip = ip.strip()
                            if (ip and self._is_valid_ip(ip) and
                                    not self._is_cloudflare(ip)):
                                origins.append({
                                    "ns_record": ns_host,
                                    "ip": ip,
                                    "reason": "Nameserver leak",
                                    "confidence": "MEDIUM"
                                })

        # 5. Test des enregistrements SOA
        soa_cmd = f"dig +short SOA {domain} @8.8.8.8"
        soa_stdout, stderr, return_code = await self.executor.run_command(
            soa_cmd, timeout=10
        )

        if soa_stdout.strip():
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            for ip in re.findall(ip_pattern, soa_stdout):
                if not self._is_cloudflare(ip):
                    origins.append({
                        "soa_record": "SOA",
                        "ip": ip,
                        "reason": "IP found in SOA record",
                        "confidence": "LOW"
                    })

        # Dédupliquer les résultats
        unique_origins = {}
        for origin in origins:
            ip = origin['ip']
            if ip not in unique_origins or origin['confidence'] == 'HIGH':
                unique_origins[ip] = origin

        return {
            "target": domain,
            "cloudflare_detected": True,
            "potential_real_ips": list(unique_origins.values()),
            "total_found": len(unique_origins),
            "recommendation": (
                "Si une IP est trouvée, lancez tactical_recon "
                "directement sur l'IP pour contourner Cloudflare."
            ),
            "next_steps": [
                "1. Identifiez l'IP réelle parmi les résultats",
                "2. Lancez tactical_recon directement sur l'IP",
                "3. Scannez les ports 8080/8443 sans passer par Cloudflare",
                "4. Exploitez les vulnérabilités trouvées"
            ]
        }

    def _is_valid_ip(self, ip: str) -> bool:
        """Vérifie si c'est une adresse IP valide"""
        pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False

        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)

    def _is_cloudflare(self, ip: str) -> bool:
        """Vérifie si l'IP appartient à Cloudflare"""
        return any(ip.startswith(r) for r in self.cloudflare_ranges)
