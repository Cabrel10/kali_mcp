#!/usr/bin/env python3
"""
Web Assault Module
Advanced web application attack tools: fuzzing, XSS, directory discovery
"""

import asyncio
import json
import re
import tempfile
from typing import Dict, List, Any, Optional
from pathlib import Path
from urllib.parse import urlparse

from ..core.config import TacticalConfig
from ..core.async_executor import AsyncExecutor
from ..core.output_processor import OutputProcessor
from ..core.database import DatabaseManager


class WebAssault:
    """
    Advanced web application attack module
    Tools: FFUF (fuzzing), Dalfox (XSS), Gobuster (directories), custom checks
    """
    
    def __init__(self):
        """Initialize web assault module"""
        self.config = TacticalConfig
        self.executor = AsyncExecutor()
        self.processor = OutputProcessor()
        self.db = DatabaseManager()
    
    async def advanced_fuzzing(
        self,
        url: str,
        mode: str = "comprehensive",
        wordlist: Optional[str] = None,
        extensions: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Advanced directory/file fuzzing with FFUF or Gobuster
        
        Args:
            url: Target URL
            mode: Fuzzing mode (quick/comprehensive/api)
            wordlist: Custom wordlist path
            extensions: File extensions to check
            
        Returns:
            Dictionary with discovered paths
        """
        # Check available tools
        has_ffuf = await self.executor.check_tool_available('ffuf')
        has_gobuster = await self.executor.check_tool_available('gobuster')
        
        if has_ffuf:
            return await self._ffuf_fuzz(url, mode, wordlist, extensions)
        elif has_gobuster:
            return await self._gobuster_fuzz(url, mode, wordlist, extensions)
        else:
            return {
                'error': 'No fuzzing tool available',
                'suggestion': 'Install ffuf or gobuster'
            }
    
    async def _ffuf_fuzz(
        self,
        url: str,
        mode: str,
        wordlist: Optional[str],
        extensions: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Fuzzing with FFUF"""
        # Select wordlist
        wordlists = {
            'quick': self.config.WORDLISTS['web_common'],
            'comprehensive': self.config.WORDLISTS['web_directories'],
            'api': self.config.WORDLISTS.get('api_endpoints', self.config.WORDLISTS['web_common'])
        }
        
        wordlist = wordlist or wordlists.get(mode, wordlists['quick'])
        
        # Build FFUF command
        ffuf_path = self.config.get_tool_path('ffuf')
        
        # Ensure URL has FUZZ placeholder
        if 'FUZZ' not in url:
            url = url.rstrip('/') + '/FUZZ'
        
        command = (
            f"{ffuf_path} -u {url} -w {wordlist} "
            f"-t 50 -ac -c -mc 200,201,301,302,401,403 -of json -o /tmp/ffuf_result.json"
        )
        
        # Add extensions if specified
        if extensions:
            command += f" -e {','.join(extensions)}"
        
        # Execute
        import time
        start_time = time.time()
        
        stdout, stderr, returncode = await self.executor.run_command(
            command,
            timeout=300
        )
        
        scan_duration = time.time() - start_time
        
        # Parse JSON result
        results = []
        
        try:
            with open('/tmp/ffuf_result.json', 'r') as f:
                data = json.load(f)
                
                for result in data.get('results', [])[:100]:  # Limit to 100
                    results.append({
                        'url': result.get('url', ''),
                        'status': result.get('status', 0),
                        'length': result.get('length', 0),
                        'words': result.get('words', 0),
                        'lines': result.get('lines', 0)
                    })
            
            # Cleanup
            Path('/tmp/ffuf_result.json').unlink(missing_ok=True)
        
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        
        # Group by status code
        by_status = {}
        for r in results:
            status = str(r['status'])
            if status not in by_status:
                by_status[status] = []
            by_status[status].append(r)
        
        return {
            'target': url,
            'tool': 'ffuf',
            'mode': mode,
            'total_found': len(results),
            'by_status': {k: len(v) for k, v in by_status.items()},
            'results': results[:50],  # Top 50 for display
            'interesting': [r for r in results if r['status'] in [200, 301, 302, 401]],
            'scan_duration': round(scan_duration, 2)
        }
    
    async def _gobuster_fuzz(
        self,
        url: str,
        mode: str,
        wordlist: Optional[str],
        extensions: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Fuzzing with Gobuster"""
        wordlists = {
            'quick': self.config.WORDLISTS['web_common'],
            'comprehensive': self.config.WORDLISTS['web_directories'],
            'api': self.config.WORDLISTS.get('api_endpoints', self.config.WORDLISTS['web_common'])
        }
        
        wordlist = wordlist or wordlists.get(mode, wordlists['quick'])
        
        # Build Gobuster command
        command = f"gobuster dir -u {url} -w {wordlist} -t 50 -q -b 404"
        
        if extensions:
            command += f" -x {','.join(extensions)}"
        
        # Execute
        import time
        start_time = time.time()
        
        stdout, stderr, returncode = await self.executor.run_command(
            command,
            timeout=300
        )
        
        scan_duration = time.time() - start_time
        
        # Parse output
        results = []
        
        for line in stdout.split('\n'):
            if line.strip() and ('Status:' in line or '(Status:' in line):
                # Extract information
                url_match = re.search(r'(/[^\s]+)', line)
                status_match = re.search(r'Status:\s*(\d+)', line, re.IGNORECASE)
                size_match = re.search(r'Size:\s*(\d+)', line, re.IGNORECASE)
                
                if url_match and status_match:
                    results.append({
                        'path': url_match.group(1),
                        'status': int(status_match.group(1)),
                        'size': int(size_match.group(1)) if size_match else 0,
                        'full_url': url.rstrip('/') + url_match.group(1)
                    })
        
        return {
            'target': url,
            'tool': 'gobuster',
            'mode': mode,
            'total_found': len(results),
            'results': results[:50],
            'scan_duration': round(scan_duration, 2)
        }
    
    async def xss_scan(
        self,
        url: str,
        parameters: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        XSS vulnerability scanning with Dalfox
        
        Args:
            url: Target URL
            parameters: Specific parameters to test
            
        Returns:
            Dictionary with XSS findings
        """
        has_dalfox = await self.executor.check_tool_available('dalfox')
        
        if not has_dalfox:
            # Fallback to manual XSS testing
            return await self._manual_xss_check(url, parameters)
        
        # Build Dalfox command
        dalfox_path = self.config.get_tool_path('dalfox')
        
        command = f"{dalfox_path} url {url} --silence --format json"
        
        if parameters:
            command += f" -p {','.join(parameters)}"
        
        # Execute
        stdout, stderr, returncode = await self.executor.run_command(
            command,
            timeout=180
        )
        
        # Parse results
        xss_findings = []
        
        for line in stdout.split('\n'):
            if '[POC]' in line or '[VULN]' in line or '"type":"XSS"' in line.lower():
                xss_findings.append(line.strip())
        
        # Try JSON parsing
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                xss_findings = data
        except json.JSONDecodeError:
            pass
        
        return {
            'target': url,
            'tool': 'dalfox',
            'vulnerable': len(xss_findings) > 0,
            'findings': xss_findings[:20],  # Top 20
            'count': len(xss_findings)
        }
    
    async def _manual_xss_check(
        self,
        url: str,
        parameters: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Manual XSS checking with curl"""
        test_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>'
        ]
        
        findings = []
        
        for payload in test_payloads:
            # Test payload in URL
            test_url = f"{url}?test={payload}"
            
            command = f"curl -s --max-time 10 '{test_url}'"
            stdout, stderr, returncode = await self.executor.run_command(
                command,
                timeout=15
            )
            
            # Check if payload is reflected
            if payload in stdout:
                findings.append({
                    'payload': payload,
                    'reflected': True,
                    'test_url': test_url
                })
        
        return {
            'target': url,
            'tool': 'manual_check',
            'vulnerable': len(findings) > 0,
            'findings': findings,
            'count': len(findings)
        }
    
    async def subdomain_takeover_check(
        self,
        domain: str,
        subdomains: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Check for subdomain takeover vulnerabilities
        
        Args:
            domain: Main domain
            subdomains: List of subdomains to check
            
        Returns:
            Dictionary with potentially vulnerable subdomains
        """
        if not subdomains:
            # Enumerate subdomains first
            subdomains = await self._enumerate_subdomains(domain)
        
        vulnerable = []
        
        for subdomain in subdomains[:100]:  # Limit to 100
            # Check DNS
            dns_cmd = f"host {subdomain}"
            dns_out, _, dns_code = await self.executor.run_command(dns_cmd, timeout=10)
            
            # Check HTTP status
            http_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 http://{subdomain}"
            http_out, _, _ = await self.executor.run_command(http_cmd, timeout=10)
            
            # Look for takeover indicators
            dns_lower = dns_out.lower()
            http_status = http_out.strip()
            
            takeover_indicators = [
                'nxdomain',
                'not found',
                'no such host',
                'heroku',
                'github.io',
                'azure',
                'amazonaws'
            ]
            
            if any(indicator in dns_lower for indicator in takeover_indicators):
                if http_status in ['404', '000']:
                    vulnerable.append({
                        'subdomain': subdomain,
                        'dns_response': dns_out[:200],
                        'http_status': http_status,
                        'likelihood': 'high' if 'nxdomain' in dns_lower else 'medium'
                    })
        
        return {
            'domain': domain,
            'checked': len(subdomains),
            'potentially_vulnerable': vulnerable,
            'count': len(vulnerable)
        }
    
    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using subfinder"""
        has_subfinder = await self.executor.check_tool_available('subfinder')
        
        if not has_subfinder:
            return []
        
        subfinder_path = self.config.get_tool_path('subfinder')
        command = f"{subfinder_path} -d {domain} -silent"
        
        stdout, stderr, returncode = await self.executor.run_command(
            command,
            timeout=60
        )
        
        subdomains = [s.strip() for s in stdout.split('\n') if s.strip()]
        return subdomains[:100]  # Limit
    
    async def api_endpoint_discovery(
        self,
        base_url: str
    ) -> Dict[str, Any]:
        """
        Discover API endpoints
        
        Args:
            base_url: Base URL of the API
            
        Returns:
            Dictionary with discovered endpoints
        """
        api_wordlist = self.config.WORDLISTS.get('api_endpoints')
        
        if not api_wordlist or not Path(api_wordlist).exists():
            # Use default API paths
            api_paths = [
                '/api/v1', '/api/v2', '/api', '/v1', '/v2',
                '/swagger', '/swagger.json', '/openapi.json',
                '/graphql', '/graphiql',
                '/api-docs', '/docs', '/api/docs',
                '/health', '/status', '/ping',
                '/users', '/login', '/register', '/auth'
            ]
            
            # Create temp wordlist
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write('\n'.join(api_paths))
                api_wordlist = f.name
        
        # Use fuzzing to discover endpoints
        result = await self.advanced_fuzzing(
            base_url,
            mode='api',
            wordlist=api_wordlist
        )
        
        # Enhance with API-specific checks
        discovered_apis = []
        
        for item in result.get('results', []):
            if item['status'] == 200:
                # Try to fetch and analyze response
                url = item.get('url', item.get('full_url', ''))
                
                check_cmd = f"curl -s --max-time 5 {url}"
                response, _, _ = await self.executor.run_command(check_cmd, timeout=10)
                
                # Check if JSON API
                is_json = False
                try:
                    json.loads(response)
                    is_json = True
                except:
                    pass
                
                discovered_apis.append({
                    'endpoint': url,
                    'status': item['status'],
                    'is_json': is_json,
                    'sample_response': response[:200] if is_json else ''
                })
        
        # Cleanup temp file if created
        if api_wordlist and api_wordlist.startswith('/tmp'):
            Path(api_wordlist).unlink(missing_ok=True)
        
        return {
            'base_url': base_url,
            'total_endpoints': len(discovered_apis),
            'endpoints': discovered_apis[:30]  # Top 30
        }
    
    async def web_technology_detection(
        self,
        url: str
    ) -> Dict[str, Any]:
        """
        Detect web technologies (CMS, frameworks, libraries)
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary with detected technologies
        """
        technologies = {
            'cms': [],
            'frameworks': [],
            'server': None,
            'languages': [],
            'javascript_libraries': []
        }
        
        # Fetch homepage
        command = f"curl -s -L --max-time 10 {url}"
        html, _, returncode = await self.executor.run_command(command, timeout=15)
        
        if returncode != 0:
            return {'error': 'Could not fetch URL'}
        
        html_lower = html.lower()
        
        # Detect CMS
        cms_signatures = {
            'WordPress': ['wp-content', 'wp-includes', '/wp-json/'],
            'Joomla': ['/components/com_', 'joomla'],
            'Drupal': ['drupal', '/sites/default/'],
            'Magento': ['magento', 'mage/cookies.js'],
            'Shopify': ['cdn.shopify.com', 'shopify'],
            'Wix': ['wix.com'],
            'Squarespace': ['squarespace']
        }
        
        for cms, signatures in cms_signatures.items():
            if any(sig in html_lower for sig in signatures):
                technologies['cms'].append(cms)
        
        # Detect frameworks
        framework_signatures = {
            'React': ['react', '__react'],
            'Angular': ['ng-', 'angular'],
            'Vue.js': ['vue', '__vue__'],
            'Laravel': ['laravel', 'csrf-token'],
            'Django': ['csrfmiddlewaretoken', 'django'],
            'Flask': ['flask'],
            'Express': ['x-powered-by: express']
        }
        
        for framework, signatures in framework_signatures.items():
            if any(sig in html_lower for sig in signatures):
                technologies['frameworks'].append(framework)
        
        # Detect JavaScript libraries
        js_libs = {
            'jQuery': 'jquery',
            'Bootstrap': 'bootstrap',
            'Lodash': 'lodash',
            'Axios': 'axios',
            'Moment.js': 'moment.js'
        }
        
        for lib, signature in js_libs.items():
            if signature in html_lower:
                technologies['javascript_libraries'].append(lib)
        
        # Get server from headers
        header_cmd = f"curl -s -I --max-time 10 {url}"
        headers, _, _ = await self.executor.run_command(header_cmd, timeout=15)
        
        for line in headers.split('\n'):
            if line.lower().startswith('server:'):
                technologies['server'] = line.split(':', 1)[1].strip()
            elif line.lower().startswith('x-powered-by:'):
                powered_by = line.split(':', 1)[1].strip()
                if powered_by not in technologies['languages']:
                    technologies['languages'].append(powered_by)
        
        return {
            'url': url,
            'technologies': technologies,
            'summary': self._format_tech_summary(technologies)
        }
    
    def _format_tech_summary(self, tech: Dict) -> str:
        """Format technology detection summary"""
        lines = []
        
        if tech.get('cms'):
            lines.append(f"CMS: {', '.join(tech['cms'])}")
        
        if tech.get('server'):
            lines.append(f"Server: {tech['server']}")
        
        if tech.get('frameworks'):
            lines.append(f"Frameworks: {', '.join(tech['frameworks'])}")
        
        if tech.get('javascript_libraries'):
            lines.append(f"JS Libraries: {', '.join(tech['javascript_libraries'][:3])}")
        
        return '\n'.join(lines) if lines else 'No technologies detected'


if __name__ == "__main__":
    # Test the module
    async def test():
        web = WebAssault()
        
        print("Testing WebAssault...")
        print("=" * 60)
        
        # Test technology detection
        print("\n1. Technology detection for example.com:")
        tech = await web.web_technology_detection("http://example.com")
        print(json.dumps(tech, indent=2))
        
        print("\n✅ Tests completed")
    
    asyncio.run(test())
