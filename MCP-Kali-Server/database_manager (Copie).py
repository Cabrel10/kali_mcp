#!/usr/bin/env python3

import sqlite3
import json
import datetime
import os
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

# Configure logging
logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Gestionnaire de base de données pour structurer et stocker tous les résultats des scans de sécurité.

    Cette classe implémente le principe demandé : "après que les outils de scan et de test fonctionne
    on dois avoir une DB telecharger et structurer de toute informations structurer est bonne a prendre"
    """

    def __init__(self, db_path: str = None):
        """Initialize the database manager"""
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "scan_results.db")

        self.db_path = db_path
        self.init_database()
        logger.info(f"DatabaseManager initialized with database: {self.db_path}")

    def init_database(self):
        """Initialize the database with all necessary tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Table des sessions de test
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                target_info TEXT,
                description TEXT,
                status TEXT DEFAULT 'active'
            )
        """)

        # Table principale des résultats de scans
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                command_executed TEXT,
                raw_output TEXT,
                parsed_results TEXT,
                output_file_path TEXT,
                status TEXT DEFAULT 'completed',
                execution_time REAL,
                FOREIGN KEY (session_id) REFERENCES sessions (session_id)
            )
        """)

        # Table des hôtes découverts
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS discovered_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                scan_id INTEGER,
                ip_address TEXT NOT NULL,
                hostname TEXT,
                os_info TEXT,
                mac_address TEXT,
                status TEXT DEFAULT 'up',
                discovered_by TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions (session_id),
                FOREIGN KEY (scan_id) REFERENCES scan_results (id)
            )
        """)

        # Table des ports découverts
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS discovered_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                scan_id INTEGER,
                port_number INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                service_name TEXT,
                service_version TEXT,
                service_info TEXT,
                discovered_by TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (host_id) REFERENCES discovered_hosts (id),
                FOREIGN KEY (session_id) REFERENCES sessions (session_id),
                FOREIGN KEY (scan_id) REFERENCES scan_results (id)
            )
        """)

        # Table des répertoires web découverts
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS web_directories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                scan_id INTEGER,
                base_url TEXT NOT NULL,
                directory_path TEXT NOT NULL,
                http_status INTEGER,
                content_length INTEGER,
                content_type TEXT,
                discovered_by TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions (session_id),
                FOREIGN KEY (scan_id) REFERENCES scan_results (id)
            )
        """)

        # Table des vulnérabilités découvertes
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                scan_id INTEGER,
                target TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                severity TEXT,
                title TEXT,
                description TEXT,
                cve_id TEXT,
                cvss_score REAL,
                solution TEXT,
                references TEXT,
                discovered_by TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions (session_id),
                FOREIGN KEY (scan_id) REFERENCES scan_results (id)
            )
        """)

        # Table des identifiants trouvés
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS discovered_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                scan_id INTEGER,
                target TEXT NOT NULL,
                username TEXT,
                password TEXT,
                hash_value TEXT,
                hash_type TEXT,
                service TEXT,
                port INTEGER,
                discovered_by TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions (session_id),
                FOREIGN KEY (scan_id) REFERENCES scan_results (id)
            )
        """)

        # Table des exploits possibles
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS potential_exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                scan_id INTEGER,
                target TEXT NOT NULL,
                exploit_title TEXT NOT NULL,
                exploit_path TEXT,
                exploit_type TEXT,
                platform TEXT,
                exploit_date DATE,
                verified BOOLEAN DEFAULT 0,
                discovered_by TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions (session_id),
                FOREIGN KEY (scan_id) REFERENCES scan_results (id)
            )
        """)

        # Table des informations DNS
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                scan_id INTEGER,
                domain TEXT NOT NULL,
                record_type TEXT NOT NULL,
                record_value TEXT NOT NULL,
                ttl INTEGER,
                discovered_by TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions (session_id),
                FOREIGN KEY (scan_id) REFERENCES scan_results (id)
            )
        """)

        # Index pour améliorer les performances
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_session_id ON scan_results (session_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_tool_name ON scan_results (tool_name)"
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_target ON scan_results (target)")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_results (timestamp)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_host_ip ON discovered_hosts (ip_address)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_port_number ON discovered_ports (port_number)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_vulnerability_type ON vulnerabilities (vulnerability_type)"
        )

        conn.commit()
        conn.close()
        logger.info("Database initialized with all tables")

    def create_session(
        self, session_id: str, target_info: str = None, description: str = None
    ) -> bool:
        """Create a new penetration testing session"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT OR REPLACE INTO sessions (session_id, target_info, description)
                VALUES (?, ?, ?)
            """,
                (session_id, target_info, description),
            )

            conn.commit()
            conn.close()
            logger.info(f"Session created: {session_id}")
            return True
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            return False

    def store_scan_result(
        self,
        session_id: str,
        tool_name: str,
        target: str,
        scan_type: str = None,
        command: str = None,
        raw_output: str = None,
        parsed_results: Dict = None,
        output_file: str = None,
        execution_time: float = None,
    ) -> int:
        """Store a scan result and return the scan ID"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO scan_results
                (session_id, tool_name, target, scan_type, command_executed,
                 raw_output, parsed_results, output_file_path, execution_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    session_id,
                    tool_name,
                    target,
                    scan_type,
                    command,
                    raw_output,
                    json.dumps(parsed_results) if parsed_results else None,
                    output_file,
                    execution_time,
                ),
            )

            scan_id = cursor.lastrowid
            conn.commit()
            conn.close()

            logger.info(f"Scan result stored with ID: {scan_id}")
            return scan_id
        except Exception as e:
            logger.error(f"Error storing scan result: {e}")
            return -1

    def store_discovered_host(
        self,
        session_id: str,
        scan_id: int,
        ip_address: str,
        hostname: str = None,
        os_info: str = None,
        mac_address: str = None,
        discovered_by: str = None,
    ) -> int:
        """Store information about a discovered host"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Check if host already exists in this session
            cursor.execute(
                """
                SELECT id FROM discovered_hosts
                WHERE session_id = ? AND ip_address = ?
            """,
                (session_id, ip_address),
            )

            existing = cursor.fetchone()
            if existing:
                # Update existing host
                cursor.execute(
                    """
                    UPDATE discovered_hosts
                    SET hostname = COALESCE(?, hostname),
                        os_info = COALESCE(?, os_info),
                        mac_address = COALESCE(?, mac_address),
                        last_seen = CURRENT_TIMESTAMP
                    WHERE id = ?
                """,
                    (hostname, os_info, mac_address, existing[0]),
                )
                host_id = existing[0]
            else:
                # Insert new host
                cursor.execute(
                    """
                    INSERT INTO discovered_hosts
                    (session_id, scan_id, ip_address, hostname, os_info, mac_address, discovered_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        session_id,
                        scan_id,
                        ip_address,
                        hostname,
                        os_info,
                        mac_address,
                        discovered_by,
                    ),
                )
                host_id = cursor.lastrowid

            conn.commit()
            conn.close()
            return host_id
        except Exception as e:
            logger.error(f"Error storing discovered host: {e}")
            return -1

    def store_discovered_port(
        self,
        host_id: int,
        session_id: str,
        scan_id: int,
        port_number: int,
        protocol: str,
        state: str,
        service_name: str = None,
        service_version: str = None,
        service_info: str = None,
        discovered_by: str = None,
    ) -> bool:
        """Store information about a discovered port"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT OR REPLACE INTO discovered_ports
                (host_id, session_id, scan_id, port_number, protocol, state,
                 service_name, service_version, service_info, discovered_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    host_id,
                    session_id,
                    scan_id,
                    port_number,
                    protocol,
                    state,
                    service_name,
                    service_version,
                    service_info,
                    discovered_by,
                ),
            )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error storing discovered port: {e}")
            return False

    def store_web_directory(
        self,
        session_id: str,
        scan_id: int,
        base_url: str,
        directory_path: str,
        http_status: int = None,
        content_length: int = None,
        content_type: str = None,
        discovered_by: str = None,
    ) -> bool:
        """Store information about a discovered web directory"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT OR REPLACE INTO web_directories
                (session_id, scan_id, base_url, directory_path, http_status,
                 content_length, content_type, discovered_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    session_id,
                    scan_id,
                    base_url,
                    directory_path,
                    http_status,
                    content_length,
                    content_type,
                    discovered_by,
                ),
            )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error storing web directory: {e}")
            return False

    def store_vulnerability(
        self,
        session_id: str,
        scan_id: int,
        target: str,
        vuln_type: str,
        severity: str = None,
        title: str = None,
        description: str = None,
        cve_id: str = None,
        cvss_score: float = None,
        solution: str = None,
        references: str = None,
        discovered_by: str = None,
    ) -> bool:
        """Store information about a discovered vulnerability"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO vulnerabilities
                (session_id, scan_id, target, vulnerability_type, severity, title,
                 description, cve_id, cvss_score, solution, references, discovered_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    session_id,
                    scan_id,
                    target,
                    vuln_type,
                    severity,
                    title,
                    description,
                    cve_id,
                    cvss_score,
                    solution,
                    references,
                    discovered_by,
                ),
            )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error storing vulnerability: {e}")
            return False

    def store_credentials(
        self,
        session_id: str,
        scan_id: int,
        target: str,
        username: str = None,
        password: str = None,
        hash_value: str = None,
        hash_type: str = None,
        service: str = None,
        port: int = None,
        discovered_by: str = None,
    ) -> bool:
        """Store discovered credentials"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO discovered_credentials
                (session_id, scan_id, target, username, password, hash_value,
                 hash_type, service, port, discovered_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    session_id,
                    scan_id,
                    target,
                    username,
                    password,
                    hash_value,
                    hash_type,
                    service,
                    port,
                    discovered_by,
                ),
            )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error storing credentials: {e}")
            return False

    def store_exploit(
        self,
        session_id: str,
        scan_id: int,
        target: str,
        exploit_title: str,
        exploit_path: str = None,
        exploit_type: str = None,
        platform: str = None,
        exploit_date: str = None,
        discovered_by: str = None,
    ) -> bool:
        """Store potential exploit information"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO potential_exploits
                (session_id, scan_id, target, exploit_title, exploit_path,
                 exploit_type, platform, exploit_date, discovered_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    session_id,
                    scan_id,
                    target,
                    exploit_title,
                    exploit_path,
                    exploit_type,
                    platform,
                    exploit_date,
                    discovered_by,
                ),
            )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error storing exploit: {e}")
            return False

    def store_dns_record(
        self,
        session_id: str,
        scan_id: int,
        domain: str,
        record_type: str,
        record_value: str,
        ttl: int = None,
        discovered_by: str = None,
    ) -> bool:
        """Store DNS record information"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT OR REPLACE INTO dns_records
                (session_id, scan_id, domain, record_type, record_value, ttl, discovered_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    session_id,
                    scan_id,
                    domain,
                    record_type,
                    record_value,
                    ttl,
                    discovered_by,
                ),
            )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error storing DNS record: {e}")
            return False

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """Get comprehensive summary of a session"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Session info
            cursor.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
            session_info = cursor.fetchone()

            if not session_info:
                return {"error": "Session not found"}

            # Scan counts
            cursor.execute(
                """
                SELECT tool_name, COUNT(*) as count
                FROM scan_results
                WHERE session_id = ?
                GROUP BY tool_name
            """,
                (session_id,),
            )
            scan_counts = dict(cursor.fetchall())

            # Host counts
            cursor.execute(
                """
                SELECT COUNT(DISTINCT ip_address) as host_count
                FROM discovered_hosts
                WHERE session_id = ?
            """,
                (session_id,),
            )
            host_count = cursor.fetchone()[0]

            # Port counts
            cursor.execute(
                """
                SELECT COUNT(*) as port_count
                FROM discovered_ports
                WHERE session_id = ?
            """,
                (session_id,),
            )
            port_count = cursor.fetchone()[0]

            # Vulnerability counts
            cursor.execute(
                """
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities
                WHERE session_id = ?
                GROUP BY severity
            """,
                (session_id,),
            )
            vuln_counts = dict(cursor.fetchall())

            # Web directory counts
            cursor.execute(
                """
                SELECT COUNT(*) as dir_count
                FROM web_directories
                WHERE session_id = ?
            """,
                (session_id,),
            )
            dir_count = cursor.fetchone()[0]

            conn.close()

            return {
                "session_id": session_id,
                "created_at": session_info[2],
                "updated_at": session_info[3],
                "target_info": session_info[4],
                "description": session_info[5],
                "statistics": {
                    "scans_performed": scan_counts,
                    "hosts_discovered": host_count,
                    "ports_discovered": port_count,
                    "vulnerabilities_found": vuln_counts,
                    "web_directories_found": dir_count,
                },
            }
        except Exception as e:
            logger.error(f"Error getting session summary: {e}")
            return {"error": str(e)}

    def export_session_data(self, session_id: str, output_format: str = "json") -> str:
        """Export all session data to specified format"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            cursor = conn.cursor()

            # Get all data for the session
            data = {
                "session_id": session_id,
                "export_timestamp": datetime.datetime.now().isoformat(),
                "scan_results": [],
                "discovered_hosts": [],
                "discovered_ports": [],
                "web_directories": [],
                "vulnerabilities": [],
                "credentials": [],
                "exploits": [],
                "dns_records": [],
            }

            # Fetch all data
            tables = [
                "scan_results",
                "discovered_hosts",
                "discovered_ports",
                "web_directories",
                "vulnerabilities",
                "discovered_credentials",
                "potential_exploits",
                "dns_records",
            ]

            for table in tables:
                cursor.execute(
                    f"SELECT * FROM {table} WHERE session_id = ?", (session_id,)
                )
                rows = cursor.fetchall()
                data[table.replace("discovered_", "").replace("potential_", "")] = [
                    dict(row) for row in rows
                ]

            conn.close()

            if output_format.lower() == "json":
                return json.dumps(data, indent=2, default=str)
            else:
                return str(data)

        except Exception as e:
            logger.error(f"Error exporting session data: {e}")
            return f"Export error: {e}"

    def get_all_sessions(self) -> List[Dict]:
        """Get list of all sessions"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM sessions ORDER BY created_at DESC")
            sessions = [dict(row) for row in cursor.fetchall()]

            conn.close()
            return sessions
        except Exception as e:
            logger.error(f"Error getting all sessions: {e}")
            return []

    def search_vulnerabilities(
        self, severity: str = None, cve_id: str = None, vuln_type: str = None
    ) -> List[Dict]:
        """Search vulnerabilities by criteria"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = "SELECT * FROM vulnerabilities WHERE 1=1"
            params = []

            if severity:
                query += " AND severity = ?"
                params.append(severity)
            if cve_id:
                query += " AND cve_id = ?"
                params.append(cve_id)
            if vuln_type:
                query += " AND vulnerability_type LIKE ?"
                params.append(f"%{vuln_type}%")

            cursor.execute(query, params)
            vulnerabilities = [dict(row) for row in cursor.fetchall()]

            conn.close()
            return vulnerabilities
        except Exception as e:
            logger.error(f"Error searching vulnerabilities: {e}")
            return []

    def get_database_stats(self) -> Dict[str, Any]:
        """Get overall database statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            stats = {}

            # Table counts
            tables = [
                "sessions",
                "scan_results",
                "discovered_hosts",
                "discovered_ports",
                "web_directories",
                "vulnerabilities",
                "discovered_credentials",
                "potential_exploits",
                "dns_records",
            ]

            for table in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                stats[f"{table}_count"] = cursor.fetchone()[0]

            # Database file size
            stats["database_size_mb"] = os.path.getsize(self.db_path) / (1024 * 1024)

            conn.close()
            return stats
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {"error": str(e)}

    def cleanup_old_sessions(self, days_old: int = 30) -> int:
        """Clean up sessions older than specified days"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get old sessions
            cursor.execute(
                """
                SELECT session_id FROM sessions
                WHERE created_at < datetime('now', '-' || ? || ' days')
            """,
                (days_old,),
            )

            old_sessions = [row[0] for row in cursor.fetchall()]

            if old_sessions:
                # Delete related data
                for session_id in old_sessions:
                    tables = [
                        "dns_records",
                        "potential_exploits",
                        "discovered_credentials",
                        "vulnerabilities",
                        "web_directories",
                        "discovered_ports",
                        "discovered_hosts",
                        "scan_results",
                        "sessions",
                    ]

                    for table in tables:
                        cursor.execute(
                            f"DELETE FROM {table} WHERE session_id = ?", (session_id,)
                        )

                conn.commit()

            conn.close()
            logger.info(f"Cleaned up {len(old_sessions)} old sessions")
            return len(old_sessions)

        except Exception as e:
            logger.error(f"Error cleaning up old sessions: {e}")
            return 0


# Global database instance
db_manager = None


def get_db_manager() -> DatabaseManager:
    """Get the global database manager instance"""
    global db_manager
    if db_manager is None:
        db_manager = DatabaseManager()
    return db_manager


if __name__ == "__main__":
    # Test the database manager
    print("🧪 Testing Database Manager...")

    db = DatabaseManager("test_scan_results.db")

    # Create test session
    session_id = f"test_session_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    db.create_session(
        session_id, "Test Target: 192.168.1.1", "Database testing session"
    )

    # Store test data
    scan_id = db.store_scan_result(
        session_id,
        "nmap_scan",
        "192.168.1.1",
        "basic",
        "nmap -sS 192.168.1.1",
        "Nmap output...",
        {"ports_found": 3},
        "/tmp/scan.xml",
        5.2,
    )

    host_id = db.store_discovered_host(
        session_id,
        scan_id,
        "192.168.1.1",
        "target.local",
        "Linux",
        "00:11:22:33:44:55",
        "nmap_scan",
    )

    db.store_discovered_port(
        host_id,
        session_id,
        scan_id,
        22,
        "tcp",
        "open",
        "ssh",
        "OpenSSH 7.4",
        "SSH service",
        "nmap_scan",
    )

    # Get summary
    summary = db.get_session_summary(session_id)
    print("Session Summary:", json.dumps(summary, indent=2))

    # Get stats
    stats = db.get_database_stats()
    print("Database Stats:", json.dumps(stats, indent=2))

    print("✅ Database Manager test completed!")
