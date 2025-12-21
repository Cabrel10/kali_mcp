#!/usr/bin/env python3
"""
OSINT Hunter - Open Source Intelligence gathering
Domain analysis, WHOIS, scam detection, reputation checks
"""

import asyncio
import json
import re
from typing import Dict, List, Any, Optional
from datetime import datetime
from ..core.config import TacticalConfig
from ..core.async_executor import AsyncExecutor


class OSINTHunter:
    """
    OSINT and intelligence gathering operations
    """
    
    def __init__(self):
        self.config = TacticalConfig
        self.executor = AsyncExecutor()
    
    async def analyze_site_legitimacy(
        self,
        domain: str
    ) -> Dict[str, Any]:
        """
        Comprehensive site legitimacy analysis for scam detection
        
        Args:
            domain: Domain to analyze
            
        Returns:
            Dictionary with legitimacy analysis
        """
        results = {
            'domain': domain,
            'risk_score': 0,
            'risk_level': 'UNKNOWN',
            'red_flags': [],
            'analysis': {}
        }
        
        # 1. WHOIS Analysis
        whois_data = await self._whois_lookup(domain)
        results['analysis']['whois'] = whois_data
        
        if whois_data.get('age_days'):
            if whois_data['age_days'] < 180:  # Less than 6 months
                results['risk_score'] += 30
                results['red_flags'].append(f"🚩 Domain is only {whois_data['age_days']} days old")
        
        # 2. SSL Certificate Analysis
        ssl_data = await self._check_ssl(domain)
        results['analysis']['ssl'] = ssl_data
        
        if ssl_data.get('issuer') and 'Let\'s Encrypt' in ssl_data['issuer']:
            results['risk_score'] += 10
            results['red_flags'].append("⚠️ Uses free SSL (common in scams)")
        
        # 3. DNS Analysis
        dns_data = await self._dns_analysis(domain)
        results['analysis']['dns'] = dns_data
        
        # 4. Content Analysis
        content_data = await self._analyze_content(domain)
        results['analysis']['content'] = content_data
        
        if content_data.get('suspicious_keywords'):
            results['risk_score'] += 20
            results['red_flags'].append("⚠️ Suspicious keywords in content")
        
        # 5. Reputation Check
        reputation = await self._check_reputation(domain)
        results['analysis']['reputation'] = reputation
        
        # Calculate risk level
        if results['risk_score'] >= 60:
            results['risk_level'] = '🔴 HIGH RISK - Likely SCAM'
        elif results['risk_score'] >= 30:
            results['risk_level'] = '🟠 MEDIUM RISK - Suspicious'
        elif results['risk_score'] >= 10:
            results['risk_level'] = '🟡 LOW RISK - Minor concerns'
        else:
            results['risk_level'] = '🟢 LOW RISK - Appears legitimate'
        
        return results
    
    async def _whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup"""
        command = f"whois {domain}"
        stdout, stderr, returncode = await self.executor.run_command(command, timeout=30)
        
        data = {
            'raw': stdout[:500],
            'registrar': None,
            'creation_date': None,
            'age_days': None
        }
        
        # Parse creation date
        date_patterns = [
            r'Creation Date:\s*(.+)',
            r'created:\s*(.+)',
            r'Registered on:\s*(.+)'
        ]
        
        for pattern in date_patterns:
            match = re.search(pattern, stdout, re.IGNORECASE)
            if match:
                date_str = match.group(1).strip()
                data['creation_date'] = date_str
                
                # Try to calculate age
                try:
                    # Parse common date formats
                    for fmt in ['%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%d-%b-%Y']:
                        try:
                            created = datetime.strptime(date_str.split()[0], fmt)
                            age = (datetime.now() - created).days
                            data['age_days'] = age
                            break
                        except:
                            continue
                except:
                    pass
                
                break
        
        # Extract registrar
        registrar_match = re.search(r'Registrar:\s*(.+)', stdout, re.IGNORECASE)
        if registrar_match:
            data['registrar'] = registrar_match.group(1).strip()
        
        return data
    
    async def _check_ssl(self, domain: str) -> Dict[str, Any]:
        """Check SSL certificate"""
        command = f"timeout 10 openssl s_client -connect {domain}:443 -servername {domain} < /dev/null 2>/dev/null | openssl x509 -noout -issuer -dates"
        stdout, stderr, returncode = await self.executor.run_command(command, timeout=15)
        
        data = {
            'valid': returncode == 0,
            'issuer': None,
            'expiry': None
        }
        
        if returncode == 0:
            # Extract issuer
            issuer_match = re.search(r'issuer=(.+)', stdout)
            if issuer_match:
                data['issuer'] = issuer_match.group(1).strip()
            
            # Extract expiry
            expiry_match = re.search(r'notAfter=(.+)', stdout)
            if expiry_match:
                data['expiry'] = expiry_match.group(1).strip()
        
        return data
    
    async def _dns_analysis(self, domain: str) -> Dict[str, Any]:
        """DNS record analysis"""
        data = {
            'a_records': [],
            'mx_records': [],
            'ns_records': []
        }
        
        # A records
        command = f"dig +short A {domain}"
        stdout, _, returncode = await self.executor.run_command(command, timeout=10)
        if returncode == 0:
            data['a_records'] = [ip.strip() for ip in stdout.split('\n') if ip.strip()]
        
        # MX records
        command = f"dig +short MX {domain}"
        stdout, _, returncode = await self.executor.run_command(command, timeout=10)
        if returncode == 0:
            data['mx_records'] = [mx.strip() for mx in stdout.split('\n') if mx.strip()]
        
        return data
    
    async def _analyze_content(self, domain: str) -> Dict[str, Any]:
        """Analyze website content"""
        command = f"curl -s -L --max-time 10 http://{domain}"
        stdout, stderr, returncode = await self.executor.run_command(command, timeout=15)
        
        data = {
            'title': None,
            'suspicious_keywords': []
        }
        
        if returncode == 0 and stdout:
            # Extract title
            title_match = re.search(r'<title>(.+?)</title>', stdout, re.IGNORECASE)
            if title_match:
                data['title'] = title_match.group(1).strip()[:100]
            
            # Check for suspicious keywords
            suspicious = [
                'verify', 'account', 'suspended', 'urgent', 'immediately',
                'payment', 'refund', 'prize', 'winner', 'congratulations',
                'bitcoin', 'cryptocurrency', 'investment', 'guaranteed'
            ]
            
            content_lower = stdout.lower()
            found_suspicious = [kw for kw in suspicious if kw in content_lower]
            
            if len(found_suspicious) > 3:
                data['suspicious_keywords'] = found_suspicious
        
        return data
    
    async def _check_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation (basic)"""
        # This would integrate with services like VirusTotal, URLhaus, etc.
        # For now, basic implementation
        
        return {
            'checked': True,
            'method': 'local',
            'note': 'Full reputation check requires API keys'
        }
    
    async def enumerate_subdomains(
        self,
        domain: str,
        method: str = "fast"
    ) -> Dict[str, Any]:
        """
        Enumerate subdomains
        
        Args:
            domain: Target domain
            method: Enumeration method (fast/deep)
            
        Returns:
            Dictionary with subdomains
        """
        subdomains = []
        
        # Method 1: subfinder (if available)
        has_subfinder = await self.executor.check_tool_available('subfinder')
        
        if has_subfinder:
            command = f"subfinder -d {domain} -silent"
            stdout, _, returncode = await self.executor.run_command(command, timeout=60)
            
            if returncode == 0:
                subdomains.extend([s.strip() for s in stdout.split('\n') if s.strip()])
        
        # Method 2: Certificate Transparency (crt.sh)
        command = f"curl -s 'https://crt.sh/?q=%.{domain}&output=json'"
        stdout, _, returncode = await self.executor.run_command(command, timeout=30)
        
        if returncode == 0 and stdout:
            try:
                data = json.loads(stdout)
                for entry in data:
                    name = entry.get('name_value', '')
                    if name and domain in name:
                        subdomains.append(name)
            except:
                pass
        
        # Remove duplicates and wildcards
        subdomains = list(set([s for s in subdomains if not s.startswith('*')]))
        
        return {
            'domain': domain,
            'method': method,
            'subdomains': sorted(subdomains)[:100],  # Limit to 100
            'count': len(subdomains)
        }


class ReverseEngineer:
    """Basic reverse engineering capabilities"""
    
    def __init__(self):
        self.config = TacticalConfig
        self.executor = AsyncExecutor()
    
    async def analyze_binary(
        self,
        file_path: str
    ) -> Dict[str, Any]:
        """
        Basic binary analysis with radare2/strings
        
        Args:
            file_path: Path to binary file
            
        Returns:
            Analysis results
        """
        results = {
            'file': file_path,
            'properties': {},
            'strings': [],
            'functions': [],
            'imports': []
        }
        
        # File type detection
        command = f"file '{file_path}'"
        stdout, _, _ = await self.executor.run_command(command, timeout=10)
        results['properties']['file_type'] = stdout.strip()
        
        # Extract strings
        command = f"strings '{file_path}' | head -100"
        stdout, _, _ = await self.executor.run_command(command, timeout=30)
        results['strings'] = [s.strip() for s in stdout.split('\n') if len(s.strip()) > 5][:50]
        
        # Check for interesting strings
        interesting = []
        for s in results['strings']:
            s_lower = s.lower()
            if any(keyword in s_lower for keyword in ['http://', 'https://', '.dll', '.so', 'password', 'key']):
                interesting.append(s)
        
        results['interesting_strings'] = interesting[:20]
        
        return results


if __name__ == "__main__":
    async def test():
        osint = OSINTHunter()
        
        print("Testing OSINTHunter...")
        print("=" * 60)
        
        print("\n1. Testing subdomain enumeration:")
        result = await osint.enumerate_subdomains("example.com", "fast")
        print(f"  Found {result['count']} subdomains")
        
        print("\n✅ Tests completed")
    
    asyncio.run(test())
