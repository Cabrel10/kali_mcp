#!/usr/bin/env python3

import os
import sys
import json
import time
import datetime
import subprocess
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


def run_command(command, timeout=300):
    """Execute a command and return the result"""
    try:
        logger.info(f"Executing: {' '.join(command)}")
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "command": " ".join(command),
            "success": result.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(command)}")
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "Command timed out",
            "command": " ".join(command),
            "success": False,
        }
    except Exception as e:
        logger.error(f"Command failed: {e}")
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "command": " ".join(command),
            "success": False,
        }


def create_database_session():
    """Create a database session for storing results"""
    session_id = (
        f"simefin_automated_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )

    try:
        # Try to import and use our database manager
        import sqlite3

        db_path = os.path.join(
            os.path.dirname(__file__), "MCP-Kali-Server", "scan_results.db"
        )

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create sessions table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                target_info TEXT,
                description TEXT,
                status TEXT DEFAULT 'active'
            )
        """)

        # Insert session
        cursor.execute(
            "INSERT OR REPLACE INTO sessions (session_id, target_info, description) VALUES (?, ?, ?)",
            (session_id, "simefin.top", "Automated security assessment"),
        )

        conn.commit()
        conn.close()
        print(f"✅ Database session created: {session_id}")

    except Exception as e:
        print(f"⚠️ Database session creation failed: {e}")

    return session_id


def automated_simefin_scan():
    """Comprehensive automated security scan of simefin.top"""

    target = "simefin.top"
    session_id = create_database_session()

    print(f"🛡️ AUTOMATED SECURITY ASSESSMENT - {target}")
    print(f"📝 Session ID: {session_id}")
    print(f"🕐 Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)

    # Create output directory
    output_dir = f"simefin_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(output_dir, exist_ok=True)

    results = {
        "target": target,
        "session_id": session_id,
        "start_time": datetime.datetime.now().isoformat(),
        "scans": {},
        "findings": {
            "hosts": [],
            "ports": [],
            "vulnerabilities": [],
            "directories": [],
            "ssl_info": {},
        },
    }

    # 1. Basic connectivity and DNS
    print(f"\n🔌 Phase 1: Basic reconnaissance...")

    # Ping test
    ping_result = run_command(["ping", "-c", "3", target], timeout=30)
    results["scans"]["ping"] = ping_result
    if ping_result["success"]:
        print("✅ Target is reachable")
    else:
        print("⚠️ Target ping failed (may be filtered)")

    # DNS lookups
    dns_commands = [
        (["nslookup", target], "nslookup"),
        (["dig", target, "A"], "dig_a"),
        (["dig", target, "MX"], "dig_mx"),
        (["dig", target, "NS"], "dig_ns"),
    ]

    for cmd, name in dns_commands:
        try:
            result = run_command(cmd, timeout=15)
            results["scans"][name] = result
            if result["success"]:
                print(f"✅ {name.upper()} lookup successful")
            else:
                print(f"⚠️ {name.upper()} lookup failed")
        except Exception as e:
            print(f"❌ {name} failed: {e}")

    # 2. Port scanning
    print(f"\n🔎 Phase 2: Port scanning...")

    nmap_output = os.path.join(output_dir, f"nmap_{target}.xml")
    nmap_txt_output = os.path.join(output_dir, f"nmap_{target}.txt")

    # Quick TCP scan first
    nmap_quick_cmd = [
        "nmap",
        "-sS",
        "-F",
        "--open",
        "-T4",
        "-oX",
        nmap_output,
        "-oN",
        nmap_txt_output,
        target,
    ]

    nmap_result = run_command(nmap_quick_cmd, timeout=300)
    results["scans"]["nmap_quick"] = nmap_result

    if nmap_result["success"]:
        print("✅ Quick Nmap scan completed")
        # Parse open ports
        try:
            if os.path.exists(nmap_txt_output):
                with open(nmap_txt_output, "r") as f:
                    nmap_content = f.read()
                    # Simple port extraction
                    for line in nmap_content.split("\n"):
                        if "/tcp" in line and "open" in line:
                            port_info = line.strip()
                            results["findings"]["ports"].append(port_info)
                print(f"📊 Found {len(results['findings']['ports'])} open ports")
        except Exception as e:
            print(f"⚠️ Error parsing Nmap results: {e}")
    else:
        print("❌ Nmap scan failed")

    # 3. Web application testing
    print(f"\n🌐 Phase 3: Web application assessment...")

    # Check if web server is responding
    web_test_result = run_command(
        ["curl", "-I", "--connect-timeout", "10", f"https://{target}"], timeout=30
    )
    results["scans"]["web_test"] = web_test_result

    if web_test_result["success"]:
        print("✅ HTTPS web service detected")

        # Nikto scan
        nikto_output = os.path.join(output_dir, f"nikto_{target}.txt")
        nikto_cmd = [
            "nikto",
            "-h",
            f"https://{target}",
            "-output",
            nikto_output,
            "-Format",
            "txt",
        ]

        nikto_result = run_command(nikto_cmd, timeout=300)
        results["scans"]["nikto"] = nikto_result

        if nikto_result["success"]:
            print("✅ Nikto web vulnerability scan completed")
            # Parse vulnerabilities
            try:
                if os.path.exists(nikto_output):
                    with open(nikto_output, "r") as f:
                        nikto_content = f.read()
                        # Count findings
                        vuln_lines = [
                            line
                            for line in nikto_content.split("\n")
                            if "+" in line and ("OSVDB" in line or "CVE" in line)
                        ]
                        results["findings"]["vulnerabilities"].extend(
                            vuln_lines[:5]
                        )  # Top 5
                    print(f"📊 Nikto found {len(vuln_lines)} potential issues")
            except Exception as e:
                print(f"⚠️ Error parsing Nikto results: {e}")
        else:
            print("❌ Nikto scan failed")

        # Directory enumeration
        gobuster_output = os.path.join(output_dir, f"gobuster_{target}.txt")
        gobuster_cmd = [
            "gobuster",
            "dir",
            "-u",
            f"https://{target}",
            "-w",
            "/usr/share/wordlists/dirb/common.txt",
            "-o",
            gobuster_output,
            "-t",
            "30",
            "--timeout",
            "10s",
        ]

        gobuster_result = run_command(gobuster_cmd, timeout=300)
        results["scans"]["gobuster"] = gobuster_result

        if gobuster_result["success"]:
            print("✅ Directory enumeration completed")
            # Parse found directories
            try:
                if os.path.exists(gobuster_output):
                    with open(gobuster_output, "r") as f:
                        gobuster_content = f.read()
                        for line in gobuster_content.split("\n"):
                            if "Status:" in line:
                                results["findings"]["directories"].append(line.strip())
                    print(
                        f"📊 Found {len(results['findings']['directories'])} accessible paths"
                    )
            except Exception as e:
                print(f"⚠️ Error parsing Gobuster results: {e}")
        else:
            print("⚠️ Directory enumeration had issues")
    else:
        print("⚠️ Web service not accessible or filtered")

    # 4. SSL/TLS Analysis
    print(f"\n🔒 Phase 4: SSL/TLS assessment...")

    # SSL certificate info
    ssl_cmd = [
        "openssl",
        "s_client",
        "-connect",
        f"{target}:443",
        "-servername",
        target,
    ]
    ssl_result = run_command(ssl_cmd, timeout=30)
    results["scans"]["ssl_cert"] = ssl_result

    if ssl_result["success"]:
        print("✅ SSL certificate information retrieved")
        # Extract basic SSL info
        try:
            ssl_output = ssl_result["stdout"]
            if "subject=" in ssl_output:
                subject_line = [
                    line for line in ssl_output.split("\n") if "subject=" in line
                ][0]
                results["findings"]["ssl_info"]["subject"] = subject_line.strip()
            if "issuer=" in ssl_output:
                issuer_line = [
                    line for line in ssl_output.split("\n") if "issuer=" in line
                ][0]
                results["findings"]["ssl_info"]["issuer"] = issuer_line.strip()
        except Exception as e:
            print(f"⚠️ Error parsing SSL info: {e}")
    else:
        print("⚠️ SSL certificate analysis failed")

    # 5. OSINT and reconnaissance
    print(f"\n🕵️ Phase 5: OSINT gathering...")

    # Whois lookup
    whois_result = run_command(["whois", target], timeout=30)
    results["scans"]["whois"] = whois_result

    if whois_result["success"]:
        print("✅ Whois information retrieved")
    else:
        print("⚠️ Whois lookup failed")

    # Finalize results
    results["end_time"] = datetime.datetime.now().isoformat()
    duration = datetime.datetime.fromisoformat(
        results["end_time"]
    ) - datetime.datetime.fromisoformat(results["start_time"])
    results["duration"] = str(duration)

    # Calculate success rate
    successful_scans = sum(
        1 for scan in results["scans"].values() if scan.get("success", False)
    )
    total_scans = len(results["scans"])
    success_rate = (successful_scans / total_scans * 100) if total_scans > 0 else 0

    # Save results
    results_file = os.path.join(output_dir, f"complete_results_{session_id}.json")
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    # Generate summary report
    generate_summary_report(results, output_dir)

    # Print final summary
    print("\n" + "=" * 80)
    print("📊 ASSESSMENT COMPLETED")
    print("=" * 80)
    print(f"🎯 Target: {target}")
    print(f"📝 Session: {session_id}")
    print(f"⏱️ Duration: {results['duration']}")
    print(f"✅ Success Rate: {successful_scans}/{total_scans} ({success_rate:.1f}%)")
    print(f"🔓 Open Ports: {len(results['findings']['ports'])}")
    print(f"🌐 Web Directories: {len(results['findings']['directories'])}")
    print(f"🚨 Potential Issues: {len(results['findings']['vulnerabilities'])}")
    print(f"📁 Results Directory: {output_dir}")
    print(f"📄 Full Results: {results_file}")

    return results


def generate_summary_report(results, output_dir):
    """Generate a concise summary report"""

    report_file = os.path.join(output_dir, "SECURITY_ASSESSMENT_SUMMARY.md")

    with open(report_file, "w") as f:
        f.write(f"# Security Assessment Summary: {results['target']}\n\n")
        f.write(f"**Assessment Date:** {results['start_time'][:19]}\n")
        f.write(f"**Session ID:** {results['session_id']}\n")
        f.write(f"**Duration:** {results['duration']}\n\n")

        # Executive Summary
        f.write("## 📋 Executive Summary\n\n")
        total_scans = len(results["scans"])
        successful_scans = sum(
            1 for scan in results["scans"].values() if scan.get("success", False)
        )
        f.write(f"- **Target Assessed:** {results['target']}\n")
        f.write(f"- **Scans Executed:** {successful_scans}/{total_scans} successful\n")
        f.write(f"- **Open Ports Found:** {len(results['findings']['ports'])}\n")
        f.write(
            f"- **Web Paths Discovered:** {len(results['findings']['directories'])}\n"
        )
        f.write(
            f"- **Potential Vulnerabilities:** {len(results['findings']['vulnerabilities'])}\n\n"
        )

        # Key Findings
        f.write("## 🔍 Key Findings\n\n")

        if results["findings"]["ports"]:
            f.write("### Open Ports\n")
            for port in results["findings"]["ports"][:5]:  # Top 5
                f.write(f"- {port}\n")
            if len(results["findings"]["ports"]) > 5:
                f.write(f"- ... and {len(results['findings']['ports']) - 5} more\n")
            f.write("\n")

        if results["findings"]["directories"]:
            f.write("### Accessible Web Paths\n")
            for directory in results["findings"]["directories"][:5]:  # Top 5
                f.write(f"- {directory}\n")
            if len(results["findings"]["directories"]) > 5:
                f.write(
                    f"- ... and {len(results['findings']['directories']) - 5} more\n"
                )
            f.write("\n")

        if results["findings"]["vulnerabilities"]:
            f.write("### Potential Security Issues\n")
            for vuln in results["findings"]["vulnerabilities"]:
                f.write(f"- {vuln[:100]}...\n")
            f.write("\n")

        if results["findings"]["ssl_info"]:
            f.write("### SSL/TLS Information\n")
            for key, value in results["findings"]["ssl_info"].items():
                f.write(f"- **{key.title()}:** {value}\n")
            f.write("\n")

        # Scan Status
        f.write("## ⚙️ Scan Execution Status\n\n")
        f.write("| Scan Type | Status | Details |\n")
        f.write("|-----------|--------|---------|\n")

        for scan_name, scan_data in results["scans"].items():
            status = "✅ SUCCESS" if scan_data.get("success") else "❌ FAILED"
            details = (
                "Completed successfully"
                if scan_data.get("success")
                else scan_data.get("stderr", "Unknown error")[:50]
            )
            f.write(
                f"| {scan_name.replace('_', ' ').title()} | {status} | {details} |\n"
            )

        f.write(f"\n## 📁 Output Files\n\n")
        f.write("Raw scan outputs and detailed results are available in:\n")
        f.write(f"- **Directory:** `{output_dir}/`\n")
        f.write(
            f"- **Full Results:** `complete_results_{results['session_id']}.json`\n"
        )

        f.write(f"\n---\n*Report generated: {datetime.datetime.now().isoformat()}*\n")

    print(f"📋 Summary report generated: {report_file}")


def main():
    """Main execution function"""
    print("🛡️ KALI MCP AUTOMATED SECURITY SCANNER")
    print("🎯 Target: simefin.top")
    print("🤖 Mode: Fully Automated Assessment")
    print("=" * 80)

    # Pre-flight checks
    print("🔧 Pre-flight system checks...")

    # Check if we have the required tools
    required_tools = ["nmap", "curl", "dig", "whois"]
    optional_tools = ["nikto", "gobuster", "openssl"]

    available_tools = []
    for tool in required_tools + optional_tools:
        check_result = run_command(["which", tool], timeout=5)
        if check_result["success"]:
            available_tools.append(tool)
            print(f"✅ {tool} available")
        else:
            if tool in required_tools:
                print(f"❌ {tool} MISSING (required)")
                return False
            else:
                print(f"⚠️ {tool} missing (optional)")

    print(f"✅ System ready - {len(available_tools)} tools available")

    # Start the automated assessment
    print(f"\n🚀 Starting automated security assessment...")
    print(f"⚠️ This scan is for educational/testing purposes only")
    print(f"⚠️ Ensure you have permission to scan the target")

    try:
        results = automated_simefin_scan()
        print("\n🎉 AUTOMATED ASSESSMENT COMPLETED SUCCESSFULLY!")
        return True

    except KeyboardInterrupt:
        print("\n⚠️ Assessment interrupted by user (Ctrl+C)")
        return False

    except Exception as e:
        print(f"\n❌ Assessment failed with error: {e}")
        logger.exception("Automated assessment failed")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
