#!/usr/bin/env python3
"""
Output Processor - Intelligent parsing and filtering of tool outputs
Extracts only critical information to save LLM tokens
"""

import re
import json
from typing import Dict, List, Any, Optional
from .config import TacticalConfig


class OutputProcessor:
    """
    Intelligent output processor that extracts essential information
    from security tool outputs and formats them for AI consumption
    """
    
    def __init__(self, max_chars: int = None):
        """
        Initialize output processor
        
        Args:
            max_chars: Maximum characters to return (default from config)
        """
        self.max_chars = max_chars or TacticalConfig.MAX_OUTPUT_CHARS
        self.config = TacticalConfig
    
    def process_nmap(self, output: str) -> str:
        """
        Extract only open ports and services from Nmap output
        
        Args:
            output: Raw Nmap output
            
        Returns:
            Formatted string with essential information
        """
        lines = output.split('\n')
        open_ports = []
        host_info = {}
        
        for line in lines:
            # Extract open ports
            if 'open' in line.lower() and ('tcp' in line.lower() or 'udp' in line.lower()):
                # Parse port line: "80/tcp   open  http    Apache httpd 2.4.41"
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]  # e.g., "80/tcp"
                    state = parts[1]       # e.g., "open"
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = ' '.join(parts[3:]) if len(parts) > 3 else ""
                    
                    port_info = {
                        'port': port_proto,
                        'state': state,
                        'service': service,
                        'version': version[:50]  # Limit version string
                    }
                    open_ports.append(port_info)
            
            # Extract host status
            elif 'nmap scan report for' in line.lower():
                host_info['target'] = line.split('for')[-1].strip()
            elif 'host is up' in line.lower():
                latency = re.search(r'\((.+?)\)', line)
                host_info['status'] = 'up'
                host_info['latency'] = latency.group(1) if latency else 'unknown'
        
        # Format output
        if not open_ports:
            return self._format_no_results("Nmap", "No open ports detected")
        
        result = f"🎯 NMAP SCAN RESULTS\n"
        result += f"Target: {host_info.get('target', 'unknown')}\n"
        result += f"Status: {host_info.get('status', 'unknown')} ({host_info.get('latency', 'N/A')})\n"
        result += f"\n📊 OPEN PORTS ({len(open_ports)}):\n"
        
        for port in open_ports[:20]:  # Limit to 20 ports
            result += f"  • {port['port']} - {port['service']}"
            if port['version']:
                result += f" ({port['version']})"
            result += "\n"
        
        if len(open_ports) > 20:
            result += f"  ... and {len(open_ports) - 20} more ports\n"
        
        return self._truncate(result)
    
    def process_nuclei(self, output: str) -> Dict[str, Any]:
        """
        Parse Nuclei JSON output and extract vulnerabilities
        
        Args:
            output: Raw Nuclei output (JSON lines)
            
        Returns:
            Dictionary with structured vulnerability data
        """
        vulnerabilities = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                vuln = json.loads(line)
                
                # Extract essential fields
                vuln_data = {
                    'id': vuln.get('template-id', 'unknown'),
                    'name': vuln.get('info', {}).get('name', 'Unknown'),
                    'severity': vuln.get('info', {}).get('severity', 'info'),
                    'type': vuln.get('type', 'unknown'),
                    'matched': vuln.get('matched-at', vuln.get('host', 'unknown')),
                    'description': vuln.get('info', {}).get('description', '')[:200]
                }
                
                vulnerabilities.append(vuln_data)
            
            except json.JSONDecodeError:
                # Not JSON, might be plain text output
                if any(keyword in line.lower() for keyword in ['critical', 'high', 'vulnerability', 'found']):
                    vulnerabilities.append({
                        'raw': line[:200]
                    })
        
        # Group by severity
        by_severity = {
            'critical': [v for v in vulnerabilities if v.get('severity') == 'critical'],
            'high': [v for v in vulnerabilities if v.get('severity') == 'high'],
            'medium': [v for v in vulnerabilities if v.get('severity') == 'medium'],
            'low': [v for v in vulnerabilities if v.get('severity') == 'low'],
            'info': [v for v in vulnerabilities if v.get('severity') == 'info']
        }
        
        return {
            'total': len(vulnerabilities),
            'by_severity': {k: len(v) for k, v in by_severity.items()},
            'critical': by_severity['critical'][:5],  # Top 5 critical
            'high': by_severity['high'][:5],          # Top 5 high
            'summary': self._format_nuclei_summary(by_severity)
        }
    
    def process_gobuster(self, output: str) -> str:
        """
        Extract discovered directories from Gobuster output
        
        Args:
            output: Raw Gobuster output
            
        Returns:
            Formatted string with discovered paths
        """
        found = []
        
        for line in output.split('\n'):
            # Gobuster format: "/admin (Status: 200) [Size: 1234]"
            if 'status:' in line.lower() or '(status:' in line.lower():
                # Extract URL and status
                url_match = re.search(r'(/[^\s]+)', line)
                status_match = re.search(r'status:\s*(\d+)', line, re.IGNORECASE)
                size_match = re.search(r'size:\s*(\d+)', line, re.IGNORECASE)
                
                if url_match:
                    url = url_match.group(1)
                    status = status_match.group(1) if status_match else 'unknown'
                    size = size_match.group(1) if size_match else 'unknown'
                    
                    # Only include interesting status codes
                    if status in ['200', '201', '301', '302', '401', '403']:
                        found.append({
                            'url': url,
                            'status': status,
                            'size': size
                        })
        
        if not found:
            return self._format_no_results("Gobuster", "No interesting directories found")
        
        result = f"📁 DIRECTORY SCAN RESULTS ({len(found)}):\n"
        
        for item in found[:30]:  # Limit to 30 results
            result += f"  • {item['url']} (Status: {item['status']}, Size: {item['size']})\n"
        
        if len(found) > 30:
            result += f"  ... and {len(found) - 30} more paths\n"
        
        return self._truncate(result)
    
    def process_ffuf(self, output: str) -> Dict[str, Any]:
        """
        Parse FFUF output (JSON or text)
        
        Args:
            output: Raw FFUF output
            
        Returns:
            Dictionary with discovered endpoints
        """
        discovered = []
        
        # Try JSON parsing first
        try:
            data = json.loads(output)
            results = data.get('results', [])
            
            for result in results[:50]:  # Limit to 50
                discovered.append({
                    'url': result.get('url', ''),
                    'status': result.get('status', 0),
                    'length': result.get('length', 0),
                    'words': result.get('words', 0)
                })
        
        except json.JSONDecodeError:
            # Parse text output
            for line in output.split('\n'):
                if '[Status:' in line:
                    url_match = re.search(r'https?://[^\s]+', line)
                    status_match = re.search(r'Status:\s*(\d+)', line)
                    size_match = re.search(r'Size:\s*(\d+)', line)
                    
                    if url_match and status_match:
                        discovered.append({
                            'url': url_match.group(0),
                            'status': status_match.group(1),
                            'length': size_match.group(1) if size_match else 'unknown'
                        })
        
        return {
            'total': len(discovered),
            'results': discovered[:30],  # Top 30
            'summary': f"Found {len(discovered)} endpoints"
        }
    
    def process_sqlmap(self, output: str) -> Dict[str, Any]:
        """
        Extract SQL injection findings from SQLMap output
        
        Args:
            output: Raw SQLMap output
            
        Returns:
            Dictionary with injection details
        """
        findings = {
            'vulnerable': False,
            'injection_points': [],
            'dbms': None,
            'databases': [],
            'summary': ''
        }
        
        lines = output.split('\n')
        
        for line in lines:
            # Check if vulnerable
            if 'parameter' in line.lower() and 'vulnerable' in line.lower():
                findings['vulnerable'] = True
                findings['injection_points'].append(line.strip())
            
            # Extract DBMS
            elif 'back-end dbms:' in line.lower():
                findings['dbms'] = line.split(':')[-1].strip()
            
            # Extract databases
            elif 'available databases' in line.lower():
                # Next few lines contain database names
                pass  # Would need more context to parse
        
        findings['summary'] = (
            f"{'✅ VULNERABLE' if findings['vulnerable'] else '❌ NOT VULNERABLE'} | "
            f"DBMS: {findings['dbms'] or 'Unknown'}"
        )
        
        return findings
    
    def process_generic(self, output: str, tool_name: str = "Tool") -> str:
        """
        Generic processing for unknown tools - extract important lines
        
        Args:
            output: Raw tool output
            tool_name: Name of the tool for labeling
            
        Returns:
            Filtered output with important lines
        """
        lines = output.strip().split('\n')
        important_lines = []
        
        # Keywords that indicate important information
        important_keywords = [
            'vulnerable', 'vulnerability', 'exploit', 'found', 'discovered',
            'success', 'error', 'warning', 'critical', 'high', 'medium',
            'open', 'closed', 'detected', 'exposed', 'leak', 'injection',
            'bypass', 'authentication', 'authorization', 'xss', 'sql',
            'rce', 'lfi', 'rfi', 'ssrf', 'csrf'
        ]
        
        for line in lines:
            line_lower = line.lower()
            
            # Check if line contains important keywords
            if any(keyword in line_lower for keyword in important_keywords):
                important_lines.append(line.strip())
            
            # Keep lines with brackets/severity indicators
            elif any(indicator in line for indicator in ['[+]', '[-]', '[*]', '[!]', '[CRITICAL]', '[HIGH]']):
                important_lines.append(line.strip())
        
        # If no important lines found, take last 20 lines
        if not important_lines:
            important_lines = lines[-20:]
        
        result = f"📊 {tool_name.upper()} OUTPUT:\n"
        result += '\n'.join(important_lines[:50])  # Limit to 50 lines
        
        return self._truncate(result)
    
    def process_httpx(self, output: str) -> Dict[str, Any]:
        """
        Parse HTTPX output for web service information
        
        Args:
            output: Raw HTTPX output
            
        Returns:
            Dictionary with web service details
        """
        services = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            
            # HTTPX output: "http://example.com [200] [Apache/2.4.41] [Title]"
            parts = line.split()
            if len(parts) >= 1:
                service = {'url': parts[0]}
                
                # Extract status code
                status_match = re.search(r'\[(\d{3})\]', line)
                if status_match:
                    service['status'] = status_match.group(1)
                
                # Extract server
                server_match = re.search(r'\[([^\]]+?/[\d.]+)\]', line)
                if server_match:
                    service['server'] = server_match.group(1)
                
                # Extract title
                title_match = re.search(r'\[([^\]]+)\]$', line)
                if title_match:
                    service['title'] = title_match.group(1)
                
                services.append(service)
        
        return {
            'count': len(services),
            'services': services[:20]  # Limit to 20
        }
    
    def _format_nuclei_summary(self, by_severity: Dict[str, List]) -> str:
        """Format Nuclei vulnerability summary"""
        summary = "💣 NUCLEI SCAN SUMMARY:\n"
        
        for severity in ['critical', 'high', 'medium', 'low']:
            vulns = by_severity.get(severity, [])
            if vulns:
                summary += f"  {severity.upper()}: {len(vulns)}\n"
                for v in vulns[:3]:  # Show top 3 per severity
                    summary += f"    • {v.get('id', 'unknown')}: {v.get('name', 'Unknown')[:60]}\n"
        
        return summary
    
    def _format_no_results(self, tool_name: str, message: str) -> str:
        """Format a 'no results' message"""
        return f"ℹ️  {tool_name}: {message}"
    
    def _truncate(self, text: str) -> str:
        """Truncate text to maximum allowed characters"""
        if len(text) <= self.max_chars:
            return text
        
        return text[:self.max_chars - 50] + f"\n\n... (truncated, {len(text)} total chars)"
    
    def format_json(self, data: Dict[str, Any]) -> str:
        """Format dictionary as pretty JSON string"""
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        return self._truncate(json_str)
    
    def extract_ips(self, text: str) -> List[str]:
        """Extract IP addresses from text"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return list(set(re.findall(ip_pattern, text)))
    
    def extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return list(set(re.findall(url_pattern, text)))
    
    def extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return list(set(re.findall(email_pattern, text)))


if __name__ == "__main__":
    # Test the output processor
    processor = OutputProcessor()
    
    print("Testing OutputProcessor...")
    print("=" * 60)
    
    # Test Nmap processing
    nmap_output = """
Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-01 12:00 UTC
Nmap scan report for example.com (93.184.216.34)
Host is up (0.015s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4 (protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))

Nmap done: 1 IP address (1 host up) scanned in 10.23 seconds
    """
    
    print("\n1. Nmap Output:")
    print(processor.process_nmap(nmap_output))
    
    # Test generic processing
    print("\n2. Generic Output:")
    generic_output = "[+] Found vulnerability in login.php\n[*] Testing XSS payloads\n[!] Critical: SQL injection detected"
    print(processor.process_generic(generic_output, "Custom Tool"))
    
    # Test extraction
    print("\n3. Extraction:")
    test_text = "Server at 192.168.1.1 and https://example.com contacted admin@example.com"
    print(f"IPs: {processor.extract_ips(test_text)}")
    print(f"URLs: {processor.extract_urls(test_text)}")
    print(f"Emails: {processor.extract_emails(test_text)}")
    
    print("\n✅ Tests completed")
