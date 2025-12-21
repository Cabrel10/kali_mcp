import asyncio
import random
from ..core.async_executor import AsyncExecutor

class DistributedEngine:
    """Gère le pool d'IP et l'évasion des pare-feux intelligents (MikroTik)"""
    
    def __init__(self, executor: AsyncExecutor):
        self.executor = executor
        self.use_proxychains = True 

    async def rotate_ip(self) -> dict:
        """Demande une nouvelle identité à Tor pour changer d'IP."""
        # This command works for most Debian/Ubuntu based systems with Tor service.
        cmd = "sudo systemctl restart tor"
        stdout, stderr = await self.executor.run_command(cmd)
        if "failed" in stderr.lower():
            return {"success": False, "error": stderr}
        
        # It takes a few seconds for Tor to establish a new circuit
        await asyncio.sleep(5)
        
        # Verify new IP
        new_ip_stdout, _ = await self.executor.run_command("proxychains curl -s https://api.ipify.org")
        
        return {
            "success": True, 
            "message": "Tor IP rotated successfully.",
            "new_ip": new_ip_stdout.strip()
        }

    async def launch_swarm(self, target: str, task_type: str):
        """Lance une attaque distribuée via plusieurs IP simultanément"""
        
        commands = []
        if task_type == "recon":
            # Using proxychains will automatically rotate through the configured proxies.
            # The commands are now simpler.
            commands = [
                f"proxychains naabu -host {target} -p 1-65535 -silent -rate 1000",
                f"proxychains ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -silent"
            ]

        tasks = []
        for cmd in commands:
            # No need to set ALL_PROXY if using proxychains
            tasks.append(self.executor.run_command(cmd))

        results = await asyncio.gather(*tasks)
        return {"swarm_results": [r[0] for r in results]}

    async def mikrotik_bypass_scan(self, target: str):
        """Scan spécifique pour MikroTik avec fragmentation et délais aléatoires"""
        # This is already a good implementation.
        # Using proxychains can add another layer of evasion.
        cmd = f"proxychains nmap -f --mtu 24 -T2 --data-length 24 --badsum --top-ports 100 {target}"
        return await self.executor.run_command(cmd)
