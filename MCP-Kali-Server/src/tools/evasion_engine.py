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
