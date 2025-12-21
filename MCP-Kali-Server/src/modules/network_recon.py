#!/usr/bin/env python3
"""
Network Reconnaissance Module
Advanced network scanning with naabu, httpx, and nmap
"""

import asyncio
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from ..core.config import TacticalConfig
from ..core.async_executor import AsyncExecutor
from ..core.output_processor import OutputProcessor
from ..core.database import DatabaseManager


class NetworkRecon:
    """
    Advanced network reconnaissance using modern tools
    Combines naabu (fast port discovery) + httpx (web probing) + nmap (service detection)
    """
    
    def __init__(self):
        """Initialize network reconnaissance module"""
        self.config = TacticalConfig
        self.executor = AsyncExecutor()
        self.processor = OutputProcessor()
        self.db = DatabaseManager()
    
    async def tactical_port_scan(
        self,
        target: str,
        strategy: str = "fast",
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """
        Tactical port scanning with different strategies
        
        Args:
            target: Target IP or domain
            strategy: Scan strategy (stealth/fast/comprehensive)
            use_cache: Use cached results if available
            
        Returns:
            Dictionary with scan results
        """
        # Check cache first
        if use_cache:
            cached = self.db.get_cached_result(target, f"portscan_{strategy}")
            if cached:
                return {
                    'source': 'cache',
                    'result': json.loads(cached['result']),
                    'cached_at': cached['timestamp']
                }
        
        # Determine tool availability
        has_naabu = await self.executor.check_tool_available('naabu')
        
        if has_naabu:
            result = await self._naabu_scan(target, strategy)
        else:
            result = await self._nmap_scan(target, strategy)
        
        # Cache result
        self.db.cache_scan_result(
            target,
            f"portscan_{strategy}",
            json.dumps(result),
            duration=result.get('scan_duration', 0)
        )
        
        return result
    
    async def _naabu_scan(
        self,
        target: str,
        strategy: str
    ) -> Dict[str, Any]:
        """
        Fast port scanning using naabu
        
        Args:
            target: Target to scan
            strategy: Scan strategy
            
        Returns:
            Dictionary with open ports and services
        """
        # Strategy configurations
        strategies = {
            'stealth': '-rate 100 -p - -silent -top-ports 1000',
            'fast': '-rate 500 -top-ports 1000 -silent',
            'comprehensive': '-rate 300 -p - -silent',
            'mikrotik': '-rate 10 -p 22,23,80,443,8291,8728,8729 -silent'  # Special for MikroTik
        }
        
        scan_params = strategies.get(strategy, strategies['fast'])
        
        # Build command
        naabu_path = self.config.get_tool_path('naabu')
        command = f"{naabu_path} -host {target} {scan_params}"
        
        # Execute scan
        import time
        start_time = time.time()
        
        stdout, stderr, returncode = await self.executor.run_command(
            command,
            timeout=180
        )
        
        scan_duration = time.time() - start_time
        
        # Parse results
        open_ports = []
        for line in stdout.strip().split('\n'):
            if line.strip() and ':' in line:
                # Format: "192.168.1.1:80"
                port = line.split(':')[-1].strip()
                if port.isdigit():
                    open_ports.append(int(port))
        
        result = {
            'target': target,
            'strategy': strategy,
            'tool': 'naabu',
            'open_ports': sorted(open_ports),
            'port_count': len(open_ports),
            'scan_duration': round(scan_duration, 2),
            'status': 'success' if returncode == 0 else 'partial'
        }
        
        # If ports found, enrich with httpx for web services
        if open_ports:
            web_services = await self._httpx_probe(target, open_ports[:20])
            result['web_services'] = web_services
        
        return result
    
    async def _nmap_scan(
        self,
        target: str,
        strategy: str
    ) -> Dict[str, Any]:
        """
        Fallback port scanning using nmap
        
        Args:
            target: Target to scan
            strategy: Scan strategy
            
        Returns:
            Dictionary with scan results
        """
        strategies = {
            'stealth': '-sS -T2 --top-ports 100',
            'fast': '-sS -T4 --top-ports 1000',
            'comprehensive': '-sS -T3 -p-',
            'mikrotik': '-sS -T2 -p 22,23,80,443,8291,8728,8729'
        }
        
        scan_params = strategies.get(strategy, strategies['fast'])
        
        command = f"nmap {scan_params} {target} -oG -"
        
        import time
        start_time = time.time()
        
        stdout, stderr, returncode = await self.executor.run_command(
            command,
            timeout=300
        )
        
        scan_duration = time.time() - start_time
        
        # Parse nmap grepable output
        open_ports = []
        for line in stdout.split('\n'):
            if 'Ports:' in line:
                # Extract ports: "Ports: 22/open/tcp//ssh///, 80/open/tcp//http///"
                ports_section = line.split('Ports:')[1].strip()
                for port_info in ports_section.split(','):
                    parts = port_info.strip().split('/')
                    if len(parts) >= 2 and parts[1] == 'open':
                        port = parts[0].strip()
                        if port.isdigit():
                            open_ports.append(int(port))
        
        return {
            'target': target,
            'strategy': strategy,
            'tool': 'nmap',
            'open_ports': sorted(open_ports),
            'port_count': len(open_ports),
            'scan_duration': round(scan_duration, 2),
            'status': 'success' if returncode == 0 else 'partial'
        }
    
    async def _httpx_probe(
        self,
        target: str,
        ports: List[int]
    ) -> List[Dict[str, Any]]:
        """
        Probe web services using httpx
        
        Args:
            target: Target to probe
            ports: List of ports to check
            
        Returns:
            List of web service information
        """
        has_httpx = await self.executor.check_tool_available('httpx')
        
        if not has_httpx:
            return []
        
        # Build URLs to probe
        urls = []
        for port in ports:
            if port in [80, 8080, 8000, 8008]:
                urls.append(f"http://{target}:{port}")
            elif port in [443, 8443]:
                urls.append(f"https://{target}:{port}")
        
        if not urls:
            return []
        
        # Create temp file with URLs
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write('\n'.join(urls))
            url_file = f.name
        
        try:
            httpx_path = self.config.get_tool_path('httpx')
            command = f"{httpx_path} -l {url_file} -silent -title -status-code -web-server -tech-detect -json"
            
            stdout, stderr, returncode = await self.executor.run_command(
                command,
                timeout=60
            )
            
            # Parse JSON output
            services = []
            for line in stdout.strip().split('\n'):
                if line.strip():
                    try:
                        data = json.loads(line)
                        services.append({
                            'url': data.get('url', ''),
                            'status_code': data.get('status_code', 0),
                            'title': data.get('title', ''),
                            'server': data.get('webserver', ''),
                            'technologies': data.get('technologies', [])
                        })
                    except json.JSONDecodeError:
                        continue
            
            return services
        
        finally:
            # Cleanup temp file
            Path(url_file).unlink(missing_ok=True)
    
    async def service_fingerprinting(
        self,
        target: str,
        port: int
    ) -> Dict[str, Any]:
        """
        Advanced service fingerprinting on specific port
        
        Args:
            target: Target IP/domain
            port: Port to fingerprint
            
        Returns:
            Dictionary with service information
        """
        results = {
            'target': target,
            'port': port,
            'service': 'unknown',
            'version': '',
            'banners': [],
            'recommendations': []
        }
        
        # Method 1: Try nmap service detection
        command = f"nmap -sV -p {port} --version-intensity 7 {target} -oG -"
        
        stdout, stderr, returncode = await self.executor.run_command(
            command,
            timeout=30
        )
        
        if returncode == 0:
            # Parse service info from grepable output
            for line in stdout.split('\n'):
                if 'Ports:' in line:
                    # Extract service and version
                    match = re.search(rf'{port}/open/[^/]+//([^/]+)//([^/]*)', line)
                    if match:
                        results['service'] = match.group(1)
                        results['version'] = match.group(2)
        
        # Method 2: Banner grabbing with netcat
        nc_command = f"timeout 5 nc -nv {target} {port} 2>&1"
        nc_stdout, _, _ = await self.executor.run_command(nc_command, timeout=10)
        
        if nc_stdout.strip():
            results['banners'].append({
                'method': 'netcat',
                'banner': nc_stdout[:500]
            })
        
        # Method 3: HTTP banner if web port
        if port in [80, 443, 8080, 8443]:
            proto = 'https' if port in [443, 8443] else 'http'
            curl_command = f"curl -s -I --max-time 5 {proto}://{target}:{port}"
            curl_stdout, _, _ = await self.executor.run_command(curl_command, timeout=10)
            
            if curl_stdout.strip():
                results['banners'].append({
                    'method': 'http_headers',
                    'banner': curl_stdout[:500]
                })
        
        # Generate recommendations
        results['recommendations'] = self._get_service_recommendations(
            results['service'],
            results['version'],
            port
        )
        
        return results
    
    def _get_service_recommendations(
        self,
        service: str,
        version: str,
        port: int
    ) -> List[str]:
        """
        Get attack recommendations based on service
        
        Args:
            service: Service name
            version: Service version
            port: Port number
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        service_lower = service.lower()
        
        # SSH recommendations
        if 'ssh' in service_lower:
            recommendations.append("🔑 SSH detected - Consider: hydra brute-force, public key enumeration")
            if version and any(v in version.lower() for v in ['7.4', '7.6']):
                recommendations.append("⚠️  Potentially vulnerable SSH version - Check for username enumeration (CVE-2018-15473)")
        
        # HTTP/HTTPS recommendations
        elif 'http' in service_lower:
            recommendations.append("🌐 Web service - Run: directory fuzzing, nuclei scan, nikto")
            if 'apache' in service_lower:
                recommendations.append("🔍 Apache detected - Check for path traversal, mod_* vulnerabilities")
            elif 'nginx' in service_lower:
                recommendations.append("🔍 Nginx detected - Check version for known CVEs")
        
        # MySQL/MariaDB recommendations
        elif 'mysql' in service_lower or 'mariadb' in service_lower:
            recommendations.append("🗄️ Database detected - Try: default credentials (root/root), mysql enumeration")
        
        # PostgreSQL recommendations
        elif 'postgresql' in service_lower:
            recommendations.append("🗄️ PostgreSQL - Check for weak credentials, version vulnerabilities")
        
        # FTP recommendations
        elif 'ftp' in service_lower:
            recommendations.append("📁 FTP detected - Test: anonymous login, brute-force credentials")
        
        # SMB recommendations
        elif 'smb' in service_lower or port in [139, 445]:
            recommendations.append("🗂️ SMB detected - Run: enum4linux, smbclient enumeration, check for EternalBlue")
        
        # RDP recommendations
        elif 'rdp' in service_lower or port == 3389:
            recommendations.append("🖥️ RDP detected - Consider: BlueKeep check, credential brute-force")
        
        # Telnet recommendations
        elif 'telnet' in service_lower:
            recommendations.append("⚠️  TELNET (insecure!) - Capture credentials, brute-force")
        
        # WinBox (MikroTik) recommendations
        elif port == 8291:
            recommendations.append("🔧 MikroTik WinBox detected - Check for CVE-2018-14847, CVE-2024-54772")
        
        # MikroTik API
        elif port in [8728, 8729]:
            recommendations.append("🔧 MikroTik API - Try default credentials, version enumeration")
        
        return recommendations
    
    async def quick_recon(
        self,
        target: str,
        intensity: str = "fast"
    ) -> Dict[str, Any]:
        """
        Quick reconnaissance combining port scan + service detection
        
        Args:
            target: Target to scan
            intensity: Scan intensity (fast/deep)
            
        Returns:
            Complete reconnaissance results
        """
        results = {
            'target': target,
            'timestamp': asyncio.get_event_loop().time(),
            'phases': {}
        }
        
        # Phase 1: Port scanning
        port_scan = await self.tactical_port_scan(
            target,
            strategy='fast' if intensity == 'fast' else 'comprehensive'
        )
        results['phases']['port_scan'] = port_scan
        
        # Phase 2: Service fingerprinting on top ports
        if port_scan.get('open_ports'):
            top_ports = port_scan['open_ports'][:5]  # Top 5 ports
            fingerprints = []
            
            for port in top_ports:
                fingerprint = await self.service_fingerprinting(target, port)
                fingerprints.append(fingerprint)
            
            results['phases']['service_fingerprinting'] = fingerprints
        
        # Phase 3: Web service enumeration
        if port_scan.get('web_services'):
            results['phases']['web_services'] = port_scan['web_services']
        
        # Generate summary
        results['summary'] = self._generate_recon_summary(results)
        
        return results
    
    def _generate_recon_summary(self, results: Dict[str, Any]) -> str:
        """Generate human-readable summary of reconnaissance"""
        lines = []
        lines.append("=" * 60)
        lines.append("🎯 NETWORK RECONNAISSANCE SUMMARY")
        lines.append("=" * 60)
        lines.append(f"Target: {results['target']}")
        
        port_scan = results['phases'].get('port_scan', {})
        if port_scan:
            lines.append(f"\n📊 Port Scan ({port_scan.get('tool', 'unknown')}):")
            lines.append(f"  Strategy: {port_scan.get('strategy', 'unknown')}")
            lines.append(f"  Open ports: {port_scan.get('port_count', 0)}")
            
            if port_scan.get('open_ports'):
                top_ports = port_scan['open_ports'][:10]
                lines.append(f"  Ports: {', '.join(map(str, top_ports))}")
                if len(port_scan['open_ports']) > 10:
                    lines.append(f"  ... and {len(port_scan['open_ports']) - 10} more")
        
        fingerprints = results['phases'].get('service_fingerprinting', [])
        if fingerprints:
            lines.append(f"\n🔍 Service Fingerprinting:")
            for fp in fingerprints:
                service = fp.get('service', 'unknown')
                version = fp.get('version', '')
                port = fp.get('port', 0)
                lines.append(f"  • Port {port}: {service} {version}")
                
                # Add top recommendation
                recs = fp.get('recommendations', [])
                if recs:
                    lines.append(f"    {recs[0]}")
        
        web_services = results['phases'].get('web_services', [])
        if web_services:
            lines.append(f"\n🌐 Web Services ({len(web_services)}):")
            for svc in web_services[:5]:
                lines.append(f"  • {svc.get('url', '')} [{svc.get('status_code', 0)}]")
                if svc.get('title'):
                    lines.append(f"    Title: {svc['title'][:60]}")
        
        lines.append("\n" + "=" * 60)
        
        return '\n'.join(lines)
    
    async def parallel_target_scan(
        self,
        targets: List[str],
        strategy: str = "fast"
    ) -> Dict[str, Any]:
        """
        Scan multiple targets in parallel
        
        Args:
            targets: List of targets to scan
            strategy: Scan strategy
            
        Returns:
            Dictionary with results for each target
        """
        tasks = []
        for target in targets:
            task = self.tactical_port_scan(target, strategy)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            'targets': targets,
            'results': results,
            'success_count': sum(1 for r in results if isinstance(r, dict))
        }


if __name__ == "__main__":
    # Test the module
    async def test():
        recon = NetworkRecon()
        
        print("Testing NetworkRecon...")
        print("=" * 60)
        
        # Test with localhost
        print("\n1. Quick scan of localhost:")
        result = await recon.tactical_port_scan("127.0.0.1", strategy="fast")
        print(json.dumps(result, indent=2))
        
        print("\n2. Service fingerprinting on port 22:")
        fingerprint = await recon.service_fingerprinting("127.0.0.1", 22)
        print(json.dumps(fingerprint, indent=2))
        
        print("\n✅ Tests completed")
    
    asyncio.run(test())
