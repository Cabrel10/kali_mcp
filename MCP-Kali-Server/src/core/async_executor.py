#!/usr/bin/env python3
"""
Asynchronous Command Executor
Handles parallel execution of shell commands with timeout management
"""

import asyncio
import subprocess
import random
import os
import signal
import psutil
from typing import Tuple, List, Dict, Optional, Any
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .config import TacticalConfig

class AsyncExecutor:
    """
    Asynchronous executor for shell commands with advanced features:
    - Parallel execution
    - Timeout management
    - Proxy support
    - Rate limiting
    - Error handling
    """
    
    def __init__(self, max_workers: int = None):
        """
        Initialize AsyncExecutor
        
        Args:
            max_workers: Maximum number of parallel workers (default from config)
        """
        self.max_workers = max_workers or TacticalConfig.MAX_PARALLEL_TASKS
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.config = TacticalConfig
        self.last_request_time: Dict[str, float] = {}
    
    async def run_command(
        self,
        command: str,
        timeout: int = None,
        shell: bool = True,
        env: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        rate_limit: bool = True
    ) -> Tuple[str, str, int]:
        """
        Execute a shell command asynchronously
        
        Args:
            command: Shell command to execute
            timeout: Timeout in seconds (default from config)
            shell: Execute in shell mode
            env: Environment variables
            proxy: Proxy to use for the command
            rate_limit: Apply rate limiting
            
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        timeout = timeout or self.config.SCAN_TIMEOUT
        
        # Apply rate limiting if enabled
        if rate_limit and self.config.ENABLE_RATE_LIMITING:
            await self._apply_rate_limit()
        
        # Prepare environment
        exec_env = env.copy() if env else {}
        if proxy:
            exec_env['ALL_PROXY'] = proxy
            exec_env['HTTP_PROXY'] = proxy
            exec_env['HTTPS_PROXY'] = proxy
        
        try:
            # Create subprocess with new process group
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                shell=shell,
                env=exec_env if exec_env else None,
                preexec_fn=os.setsid  # Create new process group
            )
            
            # Wait for completion with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                
                return (
                    stdout.decode('utf-8', errors='ignore'),
                    stderr.decode('utf-8', errors='ignore'),
                    process.returncode or 0
                )
                
            except asyncio.TimeoutError:
                # 🔴 KILL BRUTAL - Kill process group and all children
                try:
                    # Kill entire process group
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except ProcessLookupError:
                    # Process already terminated
                    pass
                except Exception:
                    # Fallback to regular kill
                    try:
                        process.kill()
                        await process.wait()
                    except:
                        pass
                
                return (
                    "",
                    f"⏱️ KILLED after {timeout}s timeout",
                    -1
                )
        
        except Exception as e:
            return (
                "",
                f"Exception during execution: {str(e)}",
                -1
            )
    
    async def run_command_with_proxy(
        self,
        command: str,
        timeout: int = None,
        auto_rotate: bool = True
    ) -> Tuple[str, str, int]:
        """
        Run command with automatic proxy selection from pool
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
            auto_rotate: Automatically select proxy from pool
            
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        proxy = None
        
        if auto_rotate and self.config.ENABLE_PROXY_ROTATION:
            proxy = self._get_random_proxy()
        
        return await self.run_command(command, timeout=timeout, proxy=proxy)
    
    async def run_parallel_commands(
        self,
        commands: List[str],
        timeout: int = None,
        use_proxies: bool = False
    ) -> List[Tuple[str, str, int]]:
        """
        Execute multiple commands in parallel
        
        Args:
            commands: List of commands to execute
            timeout: Timeout per command
            use_proxies: Use different proxy for each command
            
        Returns:
            List of tuples (stdout, stderr, return_code)
        """
        tasks = []
        
        for cmd in commands:
            if use_proxies and self.config.ENABLE_PROXY_ROTATION:
                proxy = self._get_random_proxy()
                task = self.run_command(cmd, timeout=timeout, proxy=proxy)
            else:
                task = self.run_command(cmd, timeout=timeout)
            
            tasks.append(task)
        
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    async def run_command_with_retry(
        self,
        command: str,
        max_retries: int = 3,
        timeout: int = None,
        rotate_proxy_on_fail: bool = True
    ) -> Tuple[str, str, int]:
        """
        Execute command with automatic retry on failure
        
        Args:
            command: Command to execute
            max_retries: Maximum number of retry attempts
            timeout: Timeout per attempt
            rotate_proxy_on_fail: Change proxy on each retry
            
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        last_error = ""
        
        for attempt in range(max_retries):
            proxy = None
            if rotate_proxy_on_fail and attempt > 0:
                proxy = self._get_random_proxy()
            
            stdout, stderr, returncode = await self.run_command(
                command,
                timeout=timeout,
                proxy=proxy
            )
            
            # Success
            if returncode == 0:
                return stdout, stderr, returncode
            
            last_error = stderr
            
            # Wait before retry (exponential backoff)
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)
        
        # All retries failed
        return "", f"All {max_retries} attempts failed. Last error: {last_error}", -1
    
    async def parallel_port_scan(
        self,
        target: str,
        ports: List[int],
        timeout_per_port: int = 5
    ) -> Dict[int, bool]:
        """
        Parallel port scanning using netcat
        
        Args:
            target: Target IP or hostname
            ports: List of ports to scan
            timeout_per_port: Timeout per port check
            
        Returns:
            Dictionary of {port: is_open}
        """
        commands = [
            f"timeout {timeout_per_port} nc -zv {target} {port} 2>&1"
            for port in ports
        ]
        
        results = await self.run_parallel_commands(commands, use_proxies=False)
        
        port_status = {}
        for port, (stdout, stderr, returncode) in zip(ports, results):
            # Check if port is open based on output
            output = stdout + stderr
            is_open = (
                'succeeded' in output.lower() or
                'open' in output.lower() or
                returncode == 0
            )
            port_status[port] = is_open
        
        return port_status
    
    def _get_random_proxy(self) -> str:
        """Get a random proxy from the IP pool"""
        if not self.config.IP_POOL:
            return self.config.TOR_PROXY
        
        return random.choice(self.config.IP_POOL)
    
    async def _apply_rate_limit(self, delay_range: Tuple[float, float] = (0.5, 2.0)):
        """
        Apply rate limiting with random delay
        
        Args:
            delay_range: Tuple of (min_delay, max_delay) in seconds
        """
        current_time = asyncio.get_event_loop().time()
        last_time = self.last_request_time.get('global', 0)
        
        # Calculate required delay
        time_since_last = current_time - last_time
        min_delay = delay_range[0]
        
        if time_since_last < min_delay:
            # Add random jitter
            delay = random.uniform(*delay_range)
            await asyncio.sleep(delay)
        
        # Update last request time
        self.last_request_time['global'] = asyncio.get_event_loop().time()
    
    async def check_tool_available(self, tool_name: str) -> bool:
        """
        Check if a tool is available in the system
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            True if tool is available, False otherwise
        """
        stdout, stderr, returncode = await self.run_command(
            f"which {tool_name}",
            timeout=5,
            rate_limit=False
        )
        
        return returncode == 0 and stdout.strip() != ""
    
    async def get_command_output_lines(
        self,
        command: str,
        max_lines: int = 100,
        timeout: int = None
    ) -> List[str]:
        """
        Execute command and return output as list of lines (limited)
        
        Args:
            command: Command to execute
            max_lines: Maximum number of lines to return
            timeout: Timeout in seconds
            
        Returns:
            List of output lines
        """
        stdout, stderr, returncode = await self.run_command(command, timeout=timeout)
        
        if returncode != 0:
            return [f"Error: {stderr}"]
        
        lines = stdout.strip().split('\n')
        return lines[:max_lines] if lines else []
    
    def close(self):
        """Cleanup and close executor"""
        self.executor.shutdown(wait=True)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# Singleton instance
_executor_instance: Optional[AsyncExecutor] = None


def get_executor() -> AsyncExecutor:
    """Get or create singleton AsyncExecutor instance"""
    global _executor_instance
    
    if _executor_instance is None:
        _executor_instance = AsyncExecutor()
    
    return _executor_instance


if __name__ == "__main__":
    # Test the executor
    async def test():
        executor = AsyncExecutor()
        
        print("Testing AsyncExecutor...")
        print("=" * 60)
        
        # Test simple command
        print("\n1. Simple command test:")
        stdout, stderr, code = await executor.run_command("echo 'Hello World'")
        print(f"Output: {stdout.strip()}")
        print(f"Return code: {code}")
        
        # Test with timeout
        print("\n2. Timeout test:")
        stdout, stderr, code = await executor.run_command("sleep 10", timeout=2)
        print(f"Error: {stderr}")
        
        # Test parallel execution
        print("\n3. Parallel execution test:")
        commands = ["echo 'Task 1'", "echo 'Task 2'", "echo 'Task 3'"]
        results = await executor.run_parallel_commands(commands)
        for i, (stdout, stderr, code) in enumerate(results):
            print(f"Task {i+1}: {stdout.strip()}")
        
        print("\n✅ Tests completed")
        executor.close()
    
    asyncio.run(test())
