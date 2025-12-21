#!/usr/bin/env python3

import argparse
import json
import sys
import os
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

# Add the current directory to the path to import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from database_manager import DatabaseManager, get_db_manager
    from database_integration import DatabaseIntegration, get_db_integration
except ImportError as e:
    print(f"❌ Error importing database modules: {e}")
    print(
        "Make sure database_manager.py and database_integration.py are in the same directory"
    )
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


class DatabaseManagerTool:
    """
    Outil de gestion et visualisation de la base de données des résultats de scan.
    Permet de consulter, analyser et exporter toutes les données structurées.
    """

    def __init__(self, db_path: str = None):
        """Initialize the database manager tool"""
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "scan_results.db")

        self.db_path = db_path
        self.db_manager = DatabaseManager(db_path)
        self.db_integration = DatabaseIntegration()

        print(f"📊 Database Manager Tool initialized")
        print(f"🗃️  Database: {self.db_path}")

    def show_stats(self):
        """Display comprehensive database statistics"""
        print("\n" + "=" * 60)
        print("📈 DATABASE STATISTICS")
        print("=" * 60)

        stats = self.db_manager.get_database_stats()

        if "error" in stats:
            print(f"❌ Error getting stats: {stats['error']}")
            return

        # Database info
        db_size_mb = stats.get("database_size_mb", 0)
        print(f"💾 Database Size: {db_size_mb:.2f} MB")
        print(f"📁 Database Path: {self.db_path}")

        # Table counts
        print(f"\n📋 TABLE COUNTS:")
        table_counts = [
            ("Sessions", stats.get("sessions_count", 0)),
            ("Scan Results", stats.get("scan_results_count", 0)),
            ("Discovered Hosts", stats.get("discovered_hosts_count", 0)),
            ("Discovered Ports", stats.get("discovered_ports_count", 0)),
            ("Web Directories", stats.get("web_directories_count", 0)),
            ("Vulnerabilities", stats.get("vulnerabilities_count", 0)),
            ("Credentials", stats.get("discovered_credentials_count", 0)),
            ("Potential Exploits", stats.get("potential_exploits_count", 0)),
            ("DNS Records", stats.get("dns_records_count", 0)),
        ]

        for table_name, count in table_counts:
            print(f"  • {table_name:<20}: {count:>8}")

        # Recent activity
        self._show_recent_activity()

    def _show_recent_activity(self):
        """Show recent scanning activity"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Recent scans (last 24 hours)
            cursor.execute("""
                SELECT tool_name, target, timestamp, status
                FROM scan_results
                WHERE datetime(timestamp) > datetime('now', '-1 day')
                ORDER BY timestamp DESC
                LIMIT 10
            """)

            recent_scans = cursor.fetchall()

            if recent_scans:
                print(f"\n🕐 RECENT ACTIVITY (Last 24h):")
                for tool, target, timestamp, status in recent_scans:
                    print(f"  • {timestamp} - {tool} on {target} ({status})")
            else:
                print(f"\n🕐 No recent activity in the last 24 hours")

            conn.close()

        except Exception as e:
            print(f"⚠️  Error getting recent activity: {e}")

    def list_sessions(self):
        """List all penetration testing sessions"""
        print("\n" + "=" * 60)
        print("📁 PENETRATION TESTING SESSIONS")
        print("=" * 60)

        sessions = self.db_manager.get_all_sessions()

        if not sessions:
            print("No sessions found in database")
            return

        for session in sessions:
            session_id = session.get("session_id", "Unknown")
            created_at = session.get("created_at", "Unknown")
            target_info = session.get("target_info", "No target info")
            description = session.get("description", "No description")

            print(f"\n🎯 Session: {session_id}")
            print(f"   📅 Created: {created_at}")
            print(f"   🎯 Target: {target_info}")
            print(f"   📝 Description: {description}")

            # Get session statistics
            summary = self.db_manager.get_session_summary(session_id)
            if "statistics" in summary:
                stats = summary["statistics"]
                scans = len(stats.get("scans_performed", {}))
                hosts = stats.get("hosts_discovered", 0)
                ports = stats.get("ports_discovered", 0)
                vulns = sum(stats.get("vulnerabilities_found", {}).values())
                dirs = stats.get("web_directories_found", 0)

                print(
                    f"   📊 Stats: {scans} scans, {hosts} hosts, {ports} ports, {vulns} vulns, {dirs} dirs"
                )

    def show_session_details(self, session_id: str):
        """Show detailed information about a specific session"""
        print(f"\n" + "=" * 60)
        print(f"🔍 SESSION DETAILS: {session_id}")
        print("=" * 60)

        summary = self.db_manager.get_session_summary(session_id)

        if "error" in summary:
            print(f"❌ {summary['error']}")
            return

        # Basic session info
        print(f"📁 Session ID: {summary.get('session_id', 'Unknown')}")
        print(f"📅 Created: {summary.get('created_at', 'Unknown')}")
        print(f"📅 Updated: {summary.get('updated_at', 'Unknown')}")
        print(f"🎯 Target: {summary.get('target_info', 'No target info')}")
        print(f"📝 Description: {summary.get('description', 'No description')}")

        # Statistics
        if "statistics" in summary:
            stats = summary["statistics"]

            print(f"\n📊 SCAN STATISTICS:")
            scans_performed = stats.get("scans_performed", {})
            for tool, count in scans_performed.items():
                print(f"  • {tool}: {count} scans")

            print(f"\n🏠 DISCOVERED ASSETS:")
            print(f"  • Hosts discovered: {stats.get('hosts_discovered', 0)}")
            print(f"  • Ports discovered: {stats.get('ports_discovered', 0)}")
            print(f"  • Web directories: {stats.get('web_directories_found', 0)}")

            print(f"\n🚨 SECURITY FINDINGS:")
            vulns = stats.get("vulnerabilities_found", {})
            total_vulns = sum(vulns.values())
            print(f"  • Total vulnerabilities: {total_vulns}")
            for severity, count in vulns.items():
                if count > 0:
                    print(f"    - {severity.capitalize()}: {count}")

        # Show detailed findings
        self._show_detailed_findings(session_id)

    def _show_detailed_findings(self, session_id: str):
        """Show detailed findings for a session"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Discovered hosts
            cursor.execute(
                """
                SELECT ip_address, hostname, os_info, status
                FROM discovered_hosts
                WHERE session_id = ?
                ORDER BY ip_address
            """,
                (session_id,),
            )

            hosts = cursor.fetchall()
            if hosts:
                print(f"\n🏠 DISCOVERED HOSTS ({len(hosts)}):")
                for ip, hostname, os_info, status in hosts[:10]:  # Limit to first 10
                    hostname_str = f" ({hostname})" if hostname else ""
                    os_str = f" - {os_info}" if os_info else ""
                    print(f"  • {ip}{hostname_str} [{status}]{os_str}")
                if len(hosts) > 10:
                    print(f"  ... and {len(hosts) - 10} more hosts")

            # Top vulnerabilities
            cursor.execute(
                """
                SELECT vulnerability_type, severity, title, COUNT(*) as count
                FROM vulnerabilities
                WHERE session_id = ?
                GROUP BY vulnerability_type, severity, title
                ORDER BY count DESC
                LIMIT 10
            """,
                (session_id,),
            )

            vulns = cursor.fetchall()
            if vulns:
                print(f"\n🚨 TOP VULNERABILITIES:")
                for vuln_type, severity, title, count in vulns:
                    severity_icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(
                        severity, "⚪"
                    )
                    print(
                        f"  • {severity_icon} {title} ({vuln_type}) - Found {count} times"
                    )

            # Discovered credentials
            cursor.execute(
                """
                SELECT username, service, port, COUNT(*) as count
                FROM discovered_credentials
                WHERE session_id = ?
                GROUP BY username, service, port
                ORDER BY count DESC
                LIMIT 5
            """,
                (session_id,),
            )

            creds = cursor.fetchall()
            if creds:
                print(f"\n🔑 DISCOVERED CREDENTIALS:")
                for username, service, port, count in creds:
                    service_str = f"{service}" + (f":{port}" if port else "")
                    print(f"  • {username} on {service_str}")

            conn.close()

        except Exception as e:
            print(f"⚠️  Error getting detailed findings: {e}")

    def search_vulnerabilities(
        self, severity: str = None, vuln_type: str = None, cve_id: str = None
    ):
        """Search for vulnerabilities by criteria"""
        print("\n" + "=" * 60)
        print("🔍 VULNERABILITY SEARCH")
        print("=" * 60)

        criteria = []
        if severity:
            criteria.append(f"severity: {severity}")
        if vuln_type:
            criteria.append(f"type: {vuln_type}")
        if cve_id:
            criteria.append(f"CVE: {cve_id}")

        if criteria:
            print(f"Search criteria: {', '.join(criteria)}")
        else:
            print("Showing all vulnerabilities")

        vulnerabilities = self.db_manager.search_vulnerabilities(
            severity=severity, vuln_type=vuln_type, cve_id=cve_id
        )

        if not vulnerabilities:
            print("No vulnerabilities found matching criteria")
            return

        print(f"\n🚨 Found {len(vulnerabilities)} vulnerabilities:\n")

        for vuln in vulnerabilities:
            severity_icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(
                vuln.get("severity"), "⚪"
            )

            print(f"{severity_icon} {vuln.get('title', 'Unnamed Vulnerability')}")
            print(f"   📍 Target: {vuln.get('target', 'Unknown')}")
            print(f"   📂 Type: {vuln.get('vulnerability_type', 'Unknown')}")
            print(f"   ⚠️  Severity: {vuln.get('severity', 'Unknown')}")
            print(f"   🕐 Found: {vuln.get('timestamp', 'Unknown')}")
            print(f"   🔧 Tool: {vuln.get('discovered_by', 'Unknown')}")

            if vuln.get("cve_id"):
                print(f"   🆔 CVE: {vuln.get('cve_id')}")

            if vuln.get("cvss_score"):
                print(f"   📊 CVSS: {vuln.get('cvss_score')}")

            if vuln.get("description"):
                desc = (
                    vuln.get("description", "")[:100] + "..."
                    if len(vuln.get("description", "")) > 100
                    else vuln.get("description", "")
                )
                print(f"   📝 Description: {desc}")

            print()

    def export_session(
        self, session_id: str, output_file: str = None, format: str = "json"
    ):
        """Export session data to file"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"session_{session_id}_{timestamp}.{format}"

        print(f"\n📤 Exporting session {session_id} to {output_file}")

        try:
            data = self.db_manager.export_session_data(session_id, format)

            with open(output_file, "w") as f:
                f.write(data)

            file_size = os.path.getsize(output_file)
            print(f"✅ Export completed successfully")
            print(f"   📁 File: {output_file}")
            print(f"   📊 Size: {file_size} bytes")

        except Exception as e:
            print(f"❌ Export failed: {e}")

    def generate_report(self, session_id: str = None, output_file: str = None):
        """Generate a comprehensive penetration testing report"""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if session_id:
                output_file = f"pentest_report_{session_id}_{timestamp}.md"
            else:
                output_file = f"pentest_report_all_{timestamp}.md"

        print(f"\n📋 Generating penetration testing report...")

        try:
            with open(output_file, "w") as f:
                self._write_markdown_report(f, session_id)

            file_size = os.path.getsize(output_file)
            print(f"✅ Report generated successfully")
            print(f"   📁 File: {output_file}")
            print(f"   📊 Size: {file_size} bytes")

        except Exception as e:
            print(f"❌ Report generation failed: {e}")

    def _write_markdown_report(self, f, session_id: str = None):
        """Write a markdown penetration testing report"""
        f.write("# Penetration Testing Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        if session_id:
            f.write(f"**Session ID:** {session_id}\n\n")
            summary = self.db_manager.get_session_summary(session_id)

            if "error" not in summary:
                f.write("## Executive Summary\n\n")
                f.write(
                    f"**Target:** {summary.get('target_info', 'Multiple targets')}\n"
                )
                f.write(
                    f"**Test Period:** {summary.get('created_at', 'Unknown')} - {summary.get('updated_at', 'Unknown')}\n"
                )
                f.write(
                    f"**Description:** {summary.get('description', 'No description provided')}\n\n"
                )

                # Statistics
                stats = summary.get("statistics", {})
                f.write("## Assessment Statistics\n\n")
                f.write(
                    f"- **Scans Performed:** {len(stats.get('scans_performed', {}))}\n"
                )
                f.write(f"- **Hosts Discovered:** {stats.get('hosts_discovered', 0)}\n")
                f.write(f"- **Ports Discovered:** {stats.get('ports_discovered', 0)}\n")
                f.write(
                    f"- **Web Directories Found:** {stats.get('web_directories_found', 0)}\n"
                )

                vulns = stats.get("vulnerabilities_found", {})
                total_vulns = sum(vulns.values())
                f.write(f"- **Total Vulnerabilities:** {total_vulns}\n")
                for severity, count in vulns.items():
                    if count > 0:
                        f.write(f"  - {severity.capitalize()}: {count}\n")
                f.write("\n")

        # Detailed findings
        self._write_detailed_findings_markdown(f, session_id)

    def _write_detailed_findings_markdown(self, f, session_id: str = None):
        """Write detailed findings to markdown report"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Build query based on session filter
            where_clause = "WHERE session_id = ?" if session_id else ""
            params = (session_id,) if session_id else ()

            # Vulnerabilities section
            f.write("## Vulnerabilities Found\n\n")
            cursor.execute(
                f"""
                SELECT vulnerability_type, severity, title, description, target, cve_id, cvss_score
                FROM vulnerabilities
                {where_clause}
                ORDER BY
                    CASE severity
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3
                        ELSE 4
                    END,
                    vulnerability_type
            """,
                params,
            )

            vulnerabilities = cursor.fetchall()
            if vulnerabilities:
                for (
                    vuln_type,
                    severity,
                    title,
                    desc,
                    target,
                    cve_id,
                    cvss_score,
                ) in vulnerabilities:
                    f.write(f"### {title}\n\n")
                    f.write(f"**Severity:** {severity.upper()}\n")
                    f.write(f"**Type:** {vuln_type}\n")
                    f.write(f"**Target:** {target}\n")
                    if cve_id:
                        f.write(f"**CVE ID:** {cve_id}\n")
                    if cvss_score:
                        f.write(f"**CVSS Score:** {cvss_score}\n")
                    f.write(f"**Description:** {desc}\n\n")
            else:
                f.write("No vulnerabilities found.\n\n")

            # Discovered hosts section
            f.write("## Discovered Hosts\n\n")
            cursor.execute(
                f"""
                SELECT DISTINCT h.ip_address, h.hostname, h.os_info,
                       COUNT(p.port_number) as port_count
                FROM discovered_hosts h
                LEFT JOIN discovered_ports p ON h.id = p.host_id
                {where_clause.replace("session_id", "h.session_id") if where_clause else ""}
                GROUP BY h.ip_address, h.hostname, h.os_info
                ORDER BY h.ip_address
            """,
                params,
            )

            hosts = cursor.fetchall()
            if hosts:
                f.write("| IP Address | Hostname | OS Info | Open Ports |\n")
                f.write("|------------|----------|---------|------------|\n")
                for ip, hostname, os_info, port_count in hosts:
                    hostname = hostname or "N/A"
                    os_info = os_info or "Unknown"
                    f.write(f"| {ip} | {hostname} | {os_info} | {port_count} |\n")
                f.write("\n")
            else:
                f.write("No hosts discovered.\n\n")

            # Credentials section
            f.write("## Discovered Credentials\n\n")
            cursor.execute(
                f"""
                SELECT target, username, service, port
                FROM discovered_credentials
                {where_clause}
                ORDER BY target, service
            """,
                params,
            )

            credentials = cursor.fetchall()
            if credentials:
                f.write("| Target | Username | Service | Port |\n")
                f.write("|--------|----------|---------|------|\n")
                for target, username, service, port in credentials:
                    port_str = str(port) if port else "N/A"
                    service = service or "Unknown"
                    f.write(f"| {target} | {username} | {service} | {port_str} |\n")
                f.write("\n")
            else:
                f.write("No credentials discovered.\n\n")

            conn.close()

        except Exception as e:
            f.write(f"Error generating detailed findings: {e}\n\n")

    def cleanup_old_data(self, days: int = 30):
        """Clean up old session data"""
        print(f"\n🧹 Cleaning up sessions older than {days} days...")

        cleaned = self.db_manager.cleanup_old_sessions(days)

        if cleaned > 0:
            print(f"✅ Cleaned up {cleaned} old sessions")
        else:
            print(f"ℹ️  No old sessions found to clean up")

    def interactive_mode(self):
        """Start interactive database exploration mode"""
        print("\n" + "=" * 60)
        print("🔄 INTERACTIVE MODE")
        print("=" * 60)
        print("Type 'help' for available commands, 'quit' to exit")

        while True:
            try:
                command = input("\n📊 db> ").strip().lower()

                if command == "quit" or command == "exit":
                    print("👋 Goodbye!")
                    break
                elif command == "help":
                    self._print_interactive_help()
                elif command == "stats":
                    self.show_stats()
                elif command == "sessions":
                    self.list_sessions()
                elif command.startswith("session "):
                    session_id = command.split(" ", 1)[1]
                    self.show_session_details(session_id)
                elif command.startswith("vulns"):
                    self.search_vulnerabilities()
                elif command == "recent":
                    self._show_recent_activity()
                else:
                    print(
                        f"Unknown command: {command}. Type 'help' for available commands."
                    )

            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
            except EOFError:
                print("\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")

    def _print_interactive_help(self):
        """Print help for interactive mode"""
        print("\n📚 AVAILABLE COMMANDS:")
        print("  stats          - Show database statistics")
        print("  sessions       - List all sessions")
        print("  session <id>   - Show session details")
        print("  vulns          - Show all vulnerabilities")
        print("  recent         - Show recent activity")
        print("  help           - Show this help message")
        print("  quit/exit      - Exit interactive mode")


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="Database Manager Tool for Kali MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python db_manager_tool.py stats                    # Show database statistics
  python db_manager_tool.py sessions                 # List all sessions
  python db_manager_tool.py session SESSION_ID       # Show session details
  python db_manager_tool.py vulns --severity high    # Show high severity vulnerabilities
  python db_manager_tool.py export SESSION_ID        # Export session data
  python db_manager_tool.py report SESSION_ID        # Generate penetration testing report
  python db_manager_tool.py cleanup --days 30        # Clean up data older than 30 days
  python db_manager_tool.py interactive              # Start interactive mode
        """,
    )

    parser.add_argument(
        "--db",
        type=str,
        help="Path to database file (default: scan_results.db in current directory)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Stats command
    subparsers.add_parser("stats", help="Show database statistics")

    # Sessions command
    subparsers.add_parser("sessions", help="List all penetration testing sessions")

    # Session details command
    session_parser = subparsers.add_parser(
        "session", help="Show detailed session information"
    )
    session_parser.add_argument("session_id", help="Session ID to show details for")

    # Vulnerability search command
    vulns_parser = subparsers.add_parser("vulns", help="Search vulnerabilities")
    vulns_parser.add_argument(
        "--severity", choices=["low", "medium", "high"], help="Filter by severity"
    )
    vulns_parser.add_argument(
        "--type", dest="vuln_type", help="Filter by vulnerability type"
    )
    vulns_parser.add_argument("--cve", dest="cve_id", help="Filter by CVE ID")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export session data")
    export_parser.add_argument("session_id", help="Session ID to export")
    export_parser.add_argument("--output", "-o", help="Output file name")
    export_parser.add_argument(
        "--format", choices=["json", "csv"], default="json", help="Export format"
    )

    # Report command
    report_parser = subparsers.add_parser(
        "report", help="Generate penetration testing report"
    )
    report_parser.add_argument(
        "session_id",
        nargs="?",
        help="Session ID (optional, generates report for all sessions if not provided)",
    )
    report_parser.add_argument("--output", "-o", help="Output file name")

    # Cleanup command
    cleanup_parser = subparsers.add_parser("cleanup", help="Clean up old session data")
    cleanup_parser.add_argument(
        "--days", type=int, default=30, help="Delete sessions older than this many days"
    )

    # Interactive command
    subparsers.add_parser(
        "interactive", help="Start interactive database exploration mode"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    try:
        # Initialize the database manager tool
        db_tool = DatabaseManagerTool(args.db)

        # Execute the requested command
        if args.command == "stats":
            db_tool.show_stats()
        elif args.command == "sessions":
            db_tool.list_sessions()
        elif args.command == "session":
            db_tool.show_session_details(args.session_id)
        elif args.command == "vulns":
            db_tool.search_vulnerabilities(
                severity=args.severity,
                vuln_type=getattr(args, "vuln_type", None),
                cve_id=getattr(args, "cve_id", None),
            )
        elif args.command == "export":
            db_tool.export_session(args.session_id, args.output, args.format)
        elif args.command == "report":
            db_tool.generate_report(args.session_id, args.output)
        elif args.command == "cleanup":
            db_tool.cleanup_old_data(args.days)
        elif args.command == "interactive":
            db_tool.interactive_mode()

    except Exception as e:
        print(f"❌ Error: {e}")
        logger.error(f"Command failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
