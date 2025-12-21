#!/usr/bin/env python3
"""
Database Manager - SQLite database for caching scan results
Prevents redundant scans and stores historical data
"""

import sqlite3
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from .config import TacticalConfig


class DatabaseManager:
    """
    Manages SQLite database for scan result caching and storage
    """
    
    def __init__(self, db_path: str = None):
        """
        Initialize database manager
        
        Args:
            db_path: Path to SQLite database file (default from config)
        """
        self.db_path = db_path or TacticalConfig.DB_PATH
        
        # Ensure parent directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Scans table - stores scan results
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                tool TEXT NOT NULL,
                command TEXT,
                result TEXT,
                result_hash TEXT,
                status TEXT DEFAULT 'completed',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                scan_duration REAL,
                metadata TEXT
            )
        ''')
        
        # Targets table - stores target information
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT UNIQUE NOT NULL,
                target_type TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_scanned DATETIME,
                scan_count INTEGER DEFAULT 0,
                notes TEXT,
                tags TEXT
            )
        ''')
        
        # Vulnerabilities table - stores discovered vulnerabilities
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                target TEXT NOT NULL,
                vuln_type TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                cve_id TEXT,
                cvss_score REAL,
                discovered_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'open',
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        # Tasks table - stores task information
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT UNIQUE NOT NULL,
                target TEXT NOT NULL,
                tool TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                started_at DATETIME,
                completed_at DATETIME,
                result TEXT,
                error TEXT
            )
        ''')
        
        # Create indexes for faster queries
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_scans_target_tool 
            ON scans(target, tool)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_scans_timestamp 
            ON scans(timestamp)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_target 
            ON vulnerabilities(target)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity 
            ON vulnerabilities(severity)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_tasks_task_id 
            ON tasks(task_id)
        ''')
        
        conn.commit()
        conn.close()
    
    def cache_scan_result(
        self,
        target: str,
        tool: str,
        result: str,
        command: str = "",
        duration: float = 0.0,
        metadata: Dict = None
    ) -> int:
        """
        Cache a scan result
        
        Args:
            target: Target scanned
            tool: Tool used
            result: Scan result
            command: Command executed
            duration: Scan duration in seconds
            metadata: Additional metadata
            
        Returns:
            Scan ID
        """
        result_hash = hashlib.sha256(result.encode()).hexdigest()[:16]
        metadata_json = json.dumps(metadata) if metadata else None
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scans (target, tool, command, result, result_hash, scan_duration, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (target, tool, command, result, result_hash, duration, metadata_json))
        
        scan_id = cursor.lastrowid
        
        # Update target record
        self._update_target_scan_count(target, cursor)
        
        conn.commit()
        conn.close()
        
        return scan_id
    
    def get_cached_result(
        self,
        target: str,
        tool: str,
        max_age_hours: int = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get cached scan result if available and not too old
        
        Args:
            target: Target to look up
            tool: Tool to look up
            max_age_hours: Maximum age in hours (default from config)
            
        Returns:
            Dictionary with scan result or None
        """
        max_age_hours = max_age_hours or TacticalConfig.CACHE_EXPIRY_HOURS
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, result, timestamp, scan_duration, metadata
            FROM scans
            WHERE target = ? AND tool = ?
            AND timestamp > datetime('now', ?)
            ORDER BY timestamp DESC
            LIMIT 1
        ''', (target, tool, f'-{max_age_hours} hours'))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return {
            'scan_id': row[0],
            'result': row[1],
            'timestamp': row[2],
            'scan_duration': row[3],
            'metadata': json.loads(row[4]) if row[4] else None
        }
    
    def store_vulnerability(
        self,
        target: str,
        vuln_data: Dict[str, Any],
        scan_id: Optional[int] = None
    ) -> int:
        """
        Store a discovered vulnerability
        
        Args:
            target: Target where vulnerability was found
            vuln_data: Vulnerability data dictionary
            scan_id: Optional scan ID reference
            
        Returns:
            Vulnerability ID
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO vulnerabilities 
            (scan_id, target, vuln_type, severity, title, description, cve_id, cvss_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id,
            target,
            vuln_data.get('type'),
            vuln_data.get('severity'),
            vuln_data.get('title'),
            vuln_data.get('description'),
            vuln_data.get('cve_id'),
            vuln_data.get('cvss_score')
        ))
        
        vuln_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        
        return vuln_id
    
    def get_vulnerabilities(
        self,
        target: Optional[str] = None,
        severity: Optional[str] = None,
        status: str = 'open',
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities with optional filters
        
        Args:
            target: Filter by target
            severity: Filter by severity
            status: Filter by status (default 'open')
            limit: Maximum results
            
        Returns:
            List of vulnerability dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = 'SELECT * FROM vulnerabilities WHERE 1=1'
        params = []
        
        if target:
            query += ' AND target = ?'
            params.append(target)
        
        if severity:
            query += ' AND severity = ?'
            params.append(severity)
        
        if status:
            query += ' AND status = ?'
            params.append(status)
        
        query += ' ORDER BY discovered_date DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        
        columns = [desc[0] for desc in cursor.description]
        results = []
        
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        
        conn.close()
        
        return results
    
    def get_scan_history(
        self,
        target: Optional[str] = None,
        tool: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get scan history with optional filters
        
        Args:
            target: Filter by target
            tool: Filter by tool
            limit: Maximum results
            
        Returns:
            List of scan dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = 'SELECT id, target, tool, timestamp, scan_duration, status FROM scans WHERE 1=1'
        params = []
        
        if target:
            query += ' AND target = ?'
            params.append(target)
        
        if tool:
            query += ' AND tool = ?'
            params.append(tool)
        
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        
        columns = [desc[0] for desc in cursor.description]
        results = []
        
        for row in cursor.fetchall():
            results.append(dict(zip(columns, row)))
        
        conn.close()
        
        return results
    
    def get_target_info(self, target: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a target
        
        Args:
            target: Target to look up
            
        Returns:
            Dictionary with target info or None
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM targets WHERE target = ?
        ''', (target,))
        
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return None
        
        columns = [desc[0] for desc in cursor.description]
        result = dict(zip(columns, row))
        
        conn.close()
        
        return result
    
    def add_target(
        self,
        target: str,
        target_type: str = "unknown",
        notes: str = "",
        tags: List[str] = None
    ) -> int:
        """
        Add a new target to database
        
        Args:
            target: Target (IP, domain, URL)
            target_type: Type of target
            notes: Optional notes
            tags: List of tags
            
        Returns:
            Target ID
        """
        tags_json = json.dumps(tags) if tags else None
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR IGNORE INTO targets (target, target_type, notes, tags)
            VALUES (?, ?, ?, ?)
        ''', (target, target_type, notes, tags_json))
        
        target_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        
        return target_id
    
    def _update_target_scan_count(self, target: str, cursor: sqlite3.Cursor):
        """Update target scan count and last scanned time"""
        cursor.execute('''
            INSERT OR IGNORE INTO targets (target) VALUES (?)
        ''', (target,))
        
        cursor.execute('''
            UPDATE targets 
            SET scan_count = scan_count + 1,
                last_scanned = CURRENT_TIMESTAMP
            WHERE target = ?
        ''', (target,))
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get database statistics
        
        Returns:
            Dictionary with statistics
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total scans
        cursor.execute('SELECT COUNT(*) FROM scans')
        stats['total_scans'] = cursor.fetchone()[0]
        
        # Total targets
        cursor.execute('SELECT COUNT(*) FROM targets')
        stats['total_targets'] = cursor.fetchone()[0]
        
        # Total vulnerabilities
        cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
        stats['total_vulnerabilities'] = cursor.fetchone()[0]
        
        # Vulnerabilities by severity
        cursor.execute('''
            SELECT severity, COUNT(*) 
            FROM vulnerabilities 
            WHERE status = 'open'
            GROUP BY severity
        ''')
        stats['vulns_by_severity'] = dict(cursor.fetchall())
        
        # Most scanned targets
        cursor.execute('''
            SELECT target, scan_count 
            FROM targets 
            ORDER BY scan_count DESC 
            LIMIT 5
        ''')
        stats['top_targets'] = dict(cursor.fetchall())
        
        # Scans in last 24 hours
        cursor.execute('''
            SELECT COUNT(*) 
            FROM scans 
            WHERE timestamp > datetime('now', '-1 day')
        ''')
        stats['scans_last_24h'] = cursor.fetchone()[0]
        
        conn.close()
        
        return stats
    
    def cleanup_old_scans(self, days: int = 30) -> int:
        """
        Remove old scan results
        
        Args:
            days: Remove scans older than this many days
            
        Returns:
            Number of scans removed
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM scans 
            WHERE timestamp < datetime('now', ?)
        ''', (f'-{days} days',))
        
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return deleted
    
    def export_vulnerabilities_json(self, target: Optional[str] = None) -> str:
        """
        Export vulnerabilities as JSON
        
        Args:
            target: Optional target filter
            
        Returns:
            JSON string
        """
        vulns = self.get_vulnerabilities(target=target, status='open')
        return json.dumps(vulns, indent=2, default=str)
    
    def close(self):
        """Close database connections (if any open)"""
        pass


# Singleton instance
_db_instance: Optional[DatabaseManager] = None


def get_database() -> DatabaseManager:
    """Get or create singleton DatabaseManager instance"""
    global _db_instance
    
    if _db_instance is None:
        _db_instance = DatabaseManager()
    
    return _db_instance


if __name__ == "__main__":
    # Test the database manager
    print("Testing DatabaseManager...")
    print("=" * 60)
    
    # Create test database
    db = DatabaseManager("/tmp/test_kali_mcp.db")
    
    # Test adding target
    print("\n1. Adding target:")
    target_id = db.add_target("192.168.1.1", "ip", "Test target", ["internal", "test"])
    print(f"Target ID: {target_id}")
    
    # Test caching scan result
    print("\n2. Caching scan result:")
    scan_id = db.cache_scan_result(
        "192.168.1.1",
        "nmap",
        "PORT STATE SERVICE\n22/tcp open ssh\n80/tcp open http",
        "nmap -p 22,80 192.168.1.1",
        duration=5.2,
        metadata={"ports_found": 2}
    )
    print(f"Scan ID: {scan_id}")
    
    # Test getting cached result
    print("\n3. Getting cached result:")
    cached = db.get_cached_result("192.168.1.1", "nmap")
    if cached:
        print(f"Found cached result from {cached['timestamp']}")
        print(f"Duration: {cached['scan_duration']}s")
    
    # Test storing vulnerability
    print("\n4. Storing vulnerability:")
    vuln_id = db.store_vulnerability(
        "192.168.1.1",
        {
            'type': 'outdated-software',
            'severity': 'high',
            'title': 'Outdated OpenSSH version',
            'description': 'SSH service running outdated version',
            'cve_id': 'CVE-2023-12345',
            'cvss_score': 7.5
        },
        scan_id=scan_id
    )
    print(f"Vulnerability ID: {vuln_id}")
    
    # Test getting statistics
    print("\n5. Database statistics:")
    stats = db.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n✅ Tests completed")
