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
    """Moteur d'évasion avancé : Ghost Mode"""
    
    def __init__(self, executor, distributed_engine):
        self.executor = executor
        self.distributed = distributed_engine
        self.ghost_mode = False
        self.user_agents = TacticalConfig.USER_AGENTS
        self.request_count = 0
        self.last_request_time = 0

    async def toggle_ghost_mode(self, enable: bool):
        self.ghost_mode = enable
        return f"Ghost Mode {'ENABLED' if enable else 'DISABLED'}"

    async def check_ban_and_rotate(self, target: str) -> Dict:
        """
        Vérifie si la cible nous a banni (plus de réponse).
        Si oui, rotation automatique de l'IP via le DistributedEngine.
        """
        # Test de connectivité simple (Canary request)
        cmd = f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 {target}"
        stdout, _ = await self.executor.run_command(cmd)
        
        if stdout == "000": # Pas de réponse, probable ban
            print("🚨 Ban détecté ! Rotation de l'IP en cours...")
            rotation = await self.distributed.rotate_ip()
            return {"status": "banned", "action": "ip_rotated", "new_ip": rotation.get("new_ip")}
        
        return {"status": "active", "message": "IP toujours valide"}

    async def adaptive_delay(self, target: str, intensity: str = "medium"):
        """
        Applique un délai adaptatif basé sur l'intensité souhaitée et l'historique des requêtes.
        """
        if not self.ghost_mode:
            return
            
        self.request_count += 1
        
        # Base delay values
        delays = {
            "stealth": (3, 10),      # 3-10 seconds
            "medium": (1, 5),        # 1-5 seconds
            "aggressive": (0.5, 2)   # 0.5-2 seconds
        }
        
        min_delay, max_delay = delays.get(intensity, delays["medium"])
        
        # Add jitter
        delay = random.uniform(min_delay, max_delay)
        
        # Add extra delay every 10 requests in stealth mode
        if self.ghost_mode and self.request_count % 10 == 0:
            delay += random.uniform(5, 15)
        
        await asyncio.sleep(delay)
        self.last_request_time = time.time()

    def get_random_user_agent(self) -> str:
        """
        Retourne un user-agent aléatoire pour éviter les signatures.
        """
        return random.choice(self.user_agents)

    async def fragmented_request(self, target: str, chunks: int = 4) -> Dict:
        """
        Effectue une requête fragmentée pour contourner les IDS/IPS.
        """
        if not self.ghost_mode:
            # Normal request if ghost mode disabled
            cmd = f"curl -s {target}"
            stdout, stderr = await self.executor.run_command(cmd)
            return {"stdout": stdout, "stderr": stderr}
        
        # Fragmented request in ghost mode
        cmd = f"curl -s --header \"Range: bytes=0-{chunks}\" {target}"
        stdout, stderr = await self.executor.run_command(cmd)
        return {"stdout": stdout, "stderr": stderr}

    async def polymorphic_encoding(self, payload: str) -> str:
        """
        Encode le payload de manière polymorphique pour éviter la détection.
        """
        if not self.ghost_mode:
            return payload
            
        # Simple base64 encoding as an example
        import base64
        encoded = base64.b64encode(payload.encode()).decode()
        return f"echo {encoded} | base64 -d"


if __name__ == "__main__":
    # Test the module
    async def test():
        # Mock executor and distributed engine for testing
        class MockExecutor:
            async def run_command(self, cmd, timeout=None):
                return "200", ""
        
        class MockDistributedEngine:
            async def rotate_ip(self):
                return {"new_ip": "1.2.3.4"}
        
        executor = MockExecutor()
        distributed = MockDistributedEngine()
        evasion = EvasionEngine(executor, distributed)
        
        print("Testing EvasionEngine...")
        print("=" * 60)
        
        # Test ghost mode toggle
        print("\n1. Testing ghost mode toggle:")
        result = await evasion.toggle_ghost_mode(True)
        print(f"  Result: {result}")
        
        # Test ban check
        print("\n2. Testing ban check:")
        result = await evasion.check_ban_and_rotate("http://example.com")
        print(f"  Result: {result}")
        
        # Test adaptive delay
        print("\n3. Testing adaptive delays:")
        start = time.time()
        await evasion.adaptive_delay('test-target', 'stealth')
        duration = time.time() - start
        print(f"  Stealth delay: {duration:.2f}s")
        
        # Test user agent rotation
        print("\n4. Testing user agent rotation:")
        for i in range(3):
            ua = evasion.get_random_user_agent()
            print(f"  UA {i+1}: {ua[:50]}...")
        
        print("\n✅ Tests completed")
    
    asyncio.run(test())
