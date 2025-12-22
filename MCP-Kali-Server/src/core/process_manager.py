#!/usr/bin/env python3
"""
Process Manager - Gestion robuste des processus lourds
"""

import os
import signal
import psutil
from typing import Dict, List

class ProcessManager:
    """Tue les processus orphelins et surveille les ressources"""
    
    def __init__(self):
        self.active_processes: Dict[str, int] = {}  # task_id → pid
    
    def register_process(self, task_id: str, pid: int):
        """Enregistre un processus pour surveillance"""
        self.active_processes[task_id] = pid
    
    def kill_task(self, task_id: str) -> bool:
        """Tue un processus et ses enfants"""
        if task_id not in self.active_processes:
            return False
        
        pid = self.active_processes[task_id]
        
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            
            # Tuer tous les enfants
            for child in children:
                child.kill()
            
            # Tuer le parent
            parent.kill()
            
            del self.active_processes[task_id]
            return True
            
        except psutil.NoSuchProcess:
            return False
    
    def cleanup_zombies(self):
        """Tue tous les processus de scan oubliés"""
        dangerous = ['sqlmap', 'nmap', 'gobuster', 'subfinder', 'amass', 'hydra']
        
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                cmdline = ' '.join(proc.info['cmdline'] or [])
                if any(tool in cmdline.lower() for tool in dangerous):
                    # Processus de scan détecté
                    if proc.pid not in self.active_processes.values():
                        # Orphelin → kill
                        proc.kill()
                        print(f"🗑️ Killed orphan process: {proc.info['name']} (PID {proc.pid})")
            except:
                continue