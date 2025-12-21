#!/usr/bin/env python3
"""
Evasion Engine - Stealth and anti-detection techniques
Rate limiting, proxy rotation, MikroTik stealth mode
"""

import asyncio
import random
import time
from typing import Dict, List, Any, Optional
from ..core.config import TacticalConfig
from ..core.async_executor import AsyncExecutor


class EvasionEngine:
    """
    Evasion and stealth techniques to avoid detection
    Features: Rate limiting, proxy rotation, IP blacklist detection, adaptive delays
    """
    
    def __init__(self):
        """Initialize evasion engine"""
        self.config = TacticalConfig
        self.executor = AsyncExecutor()
        
        # Tracking
        self.last_request_time: Dict[str, float] = {}
        self.request_count: Dict[str, int] = {}
        self.blacklisted_targets: List[str] = []
        self.current_proxy_index: int = 0
    
    async def adaptive_delay(
        self,
        target: str,
        intensity: str = "medium"
    ):
        """
        Apply adaptive delay based on scan intensity and target response
        
        Args:
            target: Target being scanned
            intensity: Intensity level (stealth/medium/aggressive)
        """
        delay_configs = {
            'stealth': (5, 10),      # 5-10 seconds between requests
            'medium': (2, 5),         # 2-5 seconds
            'aggressive': (0.5, 2),   # 0.5-2 seconds
            'mikrotik': (8, 15)       # Special slow mode for MikroTik
        }
        
        min_delay, max_delay = delay_configs.get(intensity, delay_configs['medium'])
        
        # Check last request time for this target
        last_time = self.last_request_time.get(target, 0)
        current_time = time.time()
        elapsed = current_time - last_time
        
        # Calculate required delay
        if elapsed < min_delay:
            delay = random.uniform(min_delay, max_delay)
            await asyncio.sleep(delay)
        
        # Update tracking
        self.last_request_time[target] = time.time()
        self.request_count[target] = self.request_count.get(target, 0) + 1
    
    def get_next_proxy(self) -> Optional[str]:
        """
        Get next proxy from the pool (round-robin)
        
        Returns:
            Proxy URL or None if pool is empty
        """
        if not self.config.IP_POOL:
            return None
        
        proxy = self.config.IP_POOL[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.config.IP_POOL)
        
        return proxy
    
    def get_random_proxy(self) -> Optional[str]:
        """Get a random proxy from the pool"""
        if not self.config.IP_POOL:
            return None
        
        return random.choice(self.config.IP_POOL)
    
    def get_random_user_agent(self) -> str:
        """Get a random user agent string"""
        return random.choice(self.config.USER_AGENTS)
    
    async def check_if_banned(
        self,
        target: str,
        test_port: int = 80
    ) -> bool:
        """
        Check if current IP is banned by target
        
        Args:
            target: Target to check
            test_port: Port to test connectivity
            
        Returns:
            True if banned, False if accessible
        """
        # Try a simple connection test
        command = f"timeout 5 nc -zv {target} {test_port} 2>&1"
        
        stdout, stderr, returncode = await self.executor.run_command(
            command,
            timeout=10,
            rate_limit=False
        )
        
        output = stdout + stderr
        
        # Check for ban indicators
        ban_indicators = [
            'refused',
            'filtered',
            'no route',
            'unreachable',
            'timeout'
        ]
        
        is_banned = any(indicator in output.lower() for indicator in ban_indicators)
        
        if is_banned:
            self.blacklisted_targets.append(target)
        
        return is_banned
    
    async def rotate_ip(self) -> Dict[str, Any]:
        """
        Rotate IP address (restart Tor or change VPN)
        
        Returns:
            Dictionary with rotation result
        """
        result = {
            'method': None,
            'success': False,
            'new_ip': None
        }
        
        # Method 1: Restart Tor
        has_tor = await self.executor.check_tool_available('tor')
        
        if has_tor:
            # Send NEWNYM signal to Tor
            command = "killall -HUP tor 2>/dev/null || sudo service tor restart"
            stdout, stderr, returncode = await self.executor.run_command(
                command,
                timeout=15
            )
            
            if returncode == 0:
                result['method'] = 'tor_restart'
                result['success'] = True
                
                # Wait for new circuit
                await asyncio.sleep(5)
                
                # Get new IP
                new_ip = await self._get_current_ip()
                result['new_ip'] = new_ip
                
                return result
        
        # Method 2: Change VPN (if using ProtonVPN/OpenVPN)
        # This would require specific VPN client commands
        
        result['method'] = 'manual_required'
        result['message'] = 'Please manually rotate IP or configure Tor/VPN'
        
        return result
    
    async def _get_current_ip(self) -> Optional[str]:
        """Get current external IP address"""
        # Try multiple IP check services
        services = [
            'https://api.ipify.org',
            'https://ifconfig.me/ip',
            'https://icanhazip.com'
        ]
        
        for service in services:
            command = f"curl -s --max-time 5 {service}"
            stdout, stderr, returncode = await self.executor.run_command(
                command,
                timeout=10,
                rate_limit=False
            )
            
            if returncode == 0 and stdout.strip():
                ip = stdout.strip()
                # Validate IP format
                if self._is_valid_ip(ip):
                    return ip
        
        return None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    async def stealth_scan_mikrotik(
        self,
        target: str
    ) -> Dict[str, Any]:
        """
        Special stealth scan for MikroTik devices
        Ultra-slow to avoid blacklist
        
        Args:
            target: MikroTik target
            
        Returns:
            Scan results
        """
        mikrotik_ports = [22, 23, 80, 443, 8291, 8728, 8729]
        
        results = {
            'target': target,
            'device_type': 'MikroTik RouterOS (suspected)',
            'open_ports': [],
            'scan_duration': 0
        }
        
        start_time = time.time()
        
        # Scan each port with extreme delays
        for port in mikrotik_ports:
            # Apply MikroTik-specific delay
            await self.adaptive_delay(target, intensity='mikrotik')
            
            # Use minimal nmap command
            command = f"nmap -sT -Pn -p {port} --max-rate 10 {target} -oG -"
            
            stdout, stderr, returncode = await self.executor.run_command(
                command,
                timeout=30
            )
            
            # Check if port is open
            if 'open' in stdout.lower():
                results['open_ports'].append(port)
        
        results['scan_duration'] = time.time() - start_time
        results['port_count'] = len(results['open_ports'])
        
        return results
    
    async def test_evasion_effectiveness(
        self,
        target: str
    ) -> Dict[str, Any]:
        """
        Test effectiveness of evasion techniques
        
        Args:
            target: Target to test against
            
        Returns:
            Test results
        """
        results = {
            'target': target,
            'tests': []
        }
        
        # Test 1: Normal scan (baseline)
        print("Test 1: Normal scan (baseline)")
        baseline_start = time.time()
        banned_baseline = await self.check_if_banned(target)
        baseline_duration = time.time() - baseline_start
        
        results['tests'].append({
            'name': 'Baseline',
            'banned': banned_baseline,
            'duration': baseline_duration
        })
        
        # Test 2: With delays
        print("Test 2: With adaptive delays")
        await self.adaptive_delay(target, 'stealth')
        delay_start = time.time()
        banned_delay = await self.check_if_banned(target)
        delay_duration = time.time() - delay_start
        
        results['tests'].append({
            'name': 'With delays',
            'banned': banned_delay,
            'duration': delay_duration
        })
        
        # Test 3: With proxy (if available)
        if self.config.IP_POOL:
            print("Test 3: With proxy rotation")
            proxy = self.get_random_proxy()
            proxy_start = time.time()
            
            command = f"curl -s --max-time 5 --proxy {proxy} http://{target}"
            stdout, stderr, returncode = await self.executor.run_command(
                command,
                timeout=10
            )
            
            proxy_duration = time.time() - proxy_start
            banned_proxy = returncode != 0
            
            results['tests'].append({
                'name': 'With proxy',
                'banned': banned_proxy,
                'duration': proxy_duration,
                'proxy': proxy
            })
        
        # Summary
        results['summary'] = (
            f"Baseline: {'BANNED' if banned_baseline else 'OK'}, "
            f"With delays: {'BANNED' if banned_delay else 'OK'}"
        )
        
        return results
    
    def get_evasion_stats(self) -> Dict[str, Any]:
        """Get statistics about evasion engine usage"""
        return {
            'total_targets': len(self.request_count),
            'total_requests': sum(self.request_count.values()),
            'blacklisted_targets': len(self.blacklisted_targets),
            'proxy_pool_size': len(self.config.IP_POOL),
            'current_proxy': self.get_next_proxy(),
            'tor_enabled': self.config.ENABLE_PROXY_ROTATION
        }


if __name__ == "__main__":
    # Test the module
    async def test():
        evasion = EvasionEngine()
        
        print("Testing EvasionEngine...")
        print("=" * 60)
        
        # Test adaptive delay
        print("\n1. Testing adaptive delays:")
        for intensity in ['stealth', 'medium', 'aggressive']:
            start = time.time()
            await evasion.adaptive_delay('test-target', intensity)
            duration = time.time() - start
            print(f"  {intensity}: {duration:.2f}s delay")
        
        # Test proxy rotation
        print("\n2. Testing proxy rotation:")
        for i in range(3):
            proxy = evasion.get_next_proxy()
            print(f"  Proxy {i+1}: {proxy}")
        
        # Test user agent rotation
        print("\n3. Testing user agent rotation:")
        for i in range(3):
            ua = evasion.get_random_user_agent()
            print(f"  UA {i+1}: {ua[:50]}...")
        
        # Get stats
        print("\n4. Evasion stats:")
        stats = evasion.get_evasion_stats()
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        print("\n✅ Tests completed")
    
    asyncio.run(test())
