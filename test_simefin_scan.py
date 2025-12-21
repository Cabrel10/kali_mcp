#!/usr/bin/env python3

import os
import sys
import json
import time
import datetime
import subprocess
import logging
from pathlib import Path

# Add the MCP server directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), "MCP-Kali-Server"))

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
        }
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(command)}")
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": "Command timed out",
            "command": " ".join(command),
        }
    except Exception as e:
        logger.error(f"Command failed: {e}")
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "command": " ".join(command),
        }


def test_simefin_scan():
    """Comprehensive security scan of simefin.top"""

    target = "simefin.top"
    session_id = f"simefin_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"

    print(f"🎯 Starting comprehensive security assessment of {target}")
    print(f"📝 Session ID: {session_id}")
    print("=" * 80)

    # Create output directory
    output_dir = (
        f"simefin_scan_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    os.makedirs(output_dir, exist_ok=True)

    results = {
        "target": target,
        "session_id": session_id,
        "start_time": datetime.datetime.now().isoformat(),
        "scans": {},
        "summary": {},
    }

    # 1. Basic connectivity test
    print("\n🔌 Testing basic connectivity...")
    ping_result = run_command(["ping", "-c", "4", target], timeout=30)
    results["scans"]["ping"] = ping_result
    if ping_result["returncode"] == 0:
        print("✅ Target is reachable")
    else:
        print("⚠️  Connectivity issues detected")

    # 2. DNS enumeration
    print(f"\n🔍 DNS enumeration of {target}...")
    dns_commands = [
        (["nslookup", target], "nslookup"),
        (["dig", target, "ANY"], "dig_any"),
        (["dig", target, "MX"], "dig_mx"),
        (["dig", target, "NS"], "dig_ns"),
        (["dig", target, "TXT"], "dig_txt"),
    ]

    for cmd, name in dns_commands:
        result = run_command(cmd, timeout=30)
        results["scans"][name] = result
        if result["returncode"] == 0:
            print(f"✅ {name} completed")
        else:
            print(f"⚠️  {name} failed")

    # 3. Port scanning with nmap
    print(f"\n🔎 Port scanning {target}...")
    nmap_output = os.path.join(output_dir, f"nmap_{target}.xml")
    nmap_cmd = [
        "nmap",
        "-sS",
        "-sV",
        "-O",
        "--script=default,vuln",
        "-oX",
        nmap_output,
        "-oN",
        nmap_output.replace(".xml", ".txt"),
        target,
    ]

    nmap_result = run_command(nmap_cmd, timeout=600)
    results["scans"]["nmap"] = nmap_result
    results["scans"]["nmap"]["output_file"] = nmap_output

    if nmap_result["returncode"] == 0:
        print("✅ Nmap scan completed")
        # Parse nmap results
        try:
            if os.path.exists(nmap_output):
                with open(nmap_output, "r") as f:
                    nmap_xml = f.read()
                print(f"📄 Nmap results saved to: {nmap_output}")
        except Exception as e:
            print(f"⚠️  Error reading nmap output: {e}")
    else:
        print("❌ Nmap scan failed")

    # 4. Web application testing
    print(f"\n🌐 Web application assessment of https://{target}...")

    # Nikto scan
    nikto_output = os.path.join(output_dir, f"nikto_{target}.xml")
    nikto_cmd = [
        "nikto",
        "-h",
        f"https://{target}",
        "-Format",
        "xml",
        "-output",
        nikto_output,
    ]

    nikto_result = run_command(nikto_cmd, timeout=600)
    results["scans"]["nikto"] = nikto_result
    results["scans"]["nikto"]["output_file"] = nikto_output

    if nikto_result["returncode"] == 0:
        print("✅ Nikto web scan completed")
    else:
        print("⚠️  Nikto scan had issues")

    # 5. Directory enumeration
    print(f"\n📂 Directory enumeration of https://{target}...")

    # Gobuster directory scan
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
        "50",
    ]

    gobuster_result = run_command(gobuster_cmd, timeout=600)
    results["scans"]["gobuster"] = gobuster_result
    results["scans"]["gobuster"]["output_file"] = gobuster_output

    if gobuster_result["returncode"] == 0:
        print("✅ Gobuster directory scan completed")
    else:
        print("⚠️  Gobuster scan had issues")

    # 6. SSL/TLS testing
    print(f"\n🔒 SSL/TLS security assessment...")

    # Test SSL configuration
    ssl_commands = [
        (
            ["openssl", "s_client", "-connect", f"{target}:443", "-servername", target],
            "ssl_info",
        ),
        (["nmap", "--script", "ssl-enum-ciphers", "-p", "443", target], "ssl_ciphers"),
        (["nmap", "--script", "ssl-cert", "-p", "443", target], "ssl_cert"),
    ]

    for cmd, name in ssl_commands:
        result = run_command(cmd, timeout=120)
        results["scans"][name] = result
        if result["returncode"] == 0:
            print(f"✅ {name} completed")
        else:
            print(f"⚠️  {name} failed")

    # 7. OSINT gathering
    print(f"\n🕵️ OSINT gathering for {target}...")

    # Whois lookup
    whois_result = run_command(["whois", target], timeout=30)
    results["scans"]["whois"] = whois_result

    if whois_result["returncode"] == 0:
        print("✅ Whois lookup completed")
    else:
        print("⚠️  Whois lookup failed")

    # 8. Additional security checks
    print(f"\n🛡️ Additional security checks...")

    # HTTP headers analysis
    curl_headers = run_command(["curl", "-I", f"https://{target}"], timeout=30)
    results["scans"]["http_headers"] = curl_headers

    # HTTP methods testing
    curl_options = run_command(
        ["curl", "-X", "OPTIONS", f"https://{target}"], timeout=30
    )
    results["scans"]["http_options"] = curl_options

    print("✅ Additional checks completed")

    # Finalize results
    results["end_time"] = datetime.datetime.now().isoformat()
    results["duration"] = str(
        datetime.datetime.fromisoformat(results["end_time"])
        - datetime.datetime.fromisoformat(results["start_time"])
    )

    # Generate summary
    successful_scans = sum(
        1 for scan in results["scans"].values() if scan.get("returncode") == 0
    )
    total_scans = len(results["scans"])

    results["summary"] = {
        "total_scans": total_scans,
        "successful_scans": successful_scans,
        "success_rate": f"{(successful_scans / total_scans * 100):.1f}%",
        "output_directory": output_dir,
    }

    # Save results to JSON
    results_file = os.path.join(output_dir, f"scan_results_{session_id}.json")
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print("\n" + "=" * 80)
    print("📊 SCAN SUMMARY")
    print("=" * 80)
    print(f"🎯 Target: {target}")
    print(f"📝 Session: {session_id}")
    print(f"⏱️ Duration: {results['duration']}")
    print(
        f"✅ Successful scans: {successful_scans}/{total_scans} ({results['summary']['success_rate']})"
    )
    print(f"📁 Output directory: {output_dir}")
    print(f"📄 Full results: {results_file}")

    # Generate basic report
    generate_basic_report(results, output_dir)

    return results


def generate_basic_report(results, output_dir):
    """Generate a basic markdown report"""

    report_file = os.path.join(output_dir, "security_assessment_report.md")

    with open(report_file, "w") as f:
        f.write(f"# Security Assessment Report: {results['target']}\n\n")
        f.write(f"**Assessment Date:** {results['start_time']}\n")
        f.write(f"**Session ID:** {results['session_id']}\n")
        f.write(f"**Duration:** {results['duration']}\n\n")

        f.write("## Executive Summary\n\n")
        f.write(
            f"Comprehensive security assessment performed on {results['target']}.\n"
        )
        f.write(f"Total scans executed: {results['summary']['total_scans']}\n")
        f.write(f"Success rate: {results['summary']['success_rate']}\n\n")

        f.write("## Scan Results Overview\n\n")
        f.write("| Scan Type | Status | Details |\n")
        f.write("|-----------|--------|----------|\n")

        for scan_name, scan_data in results["scans"].items():
            status = "✅ SUCCESS" if scan_data.get("returncode") == 0 else "❌ FAILED"
            details = scan_data.get("output_file", "Console output only")
            f.write(f"| {scan_name} | {status} | {details} |\n")

        f.write("\n## Key Findings\n\n")

        # Analyze connectivity
        if results["scans"].get("ping", {}).get("returncode") == 0:
            f.write("- ✅ Target is reachable and responding to ICMP\n")
        else:
            f.write("- ⚠️ Target may have ICMP filtering or connectivity issues\n")

        # Analyze web services
        if results["scans"].get("nikto", {}).get("returncode") == 0:
            f.write("- ✅ Web application is accessible for testing\n")

        if results["scans"].get("ssl_info", {}).get("returncode") == 0:
            f.write("- ✅ SSL/TLS service is available on port 443\n")

        f.write("\n## Recommendations\n\n")
        f.write("1. Review detailed scan outputs for specific vulnerabilities\n")
        f.write("2. Analyze Nmap results for open ports and services\n")
        f.write("3. Check Nikto results for web application vulnerabilities\n")
        f.write("4. Review SSL/TLS configuration for security best practices\n")
        f.write("5. Implement security controls based on identified findings\n\n")

        f.write("## Detailed Results\n\n")
        f.write(
            "Detailed results and raw outputs are available in the following files:\n\n"
        )

        for scan_name, scan_data in results["scans"].items():
            if "output_file" in scan_data:
                f.write(f"- **{scan_name}**: `{scan_data['output_file']}`\n")

        f.write(f"\n---\n")
        f.write(f"*Report generated on {datetime.datetime.now().isoformat()}*\n")

    print(f"📋 Security assessment report generated: {report_file}")


def main():
    """Main execution function"""
    print("🛡️ Kali MCP Security Scanner - simefin.top Assessment")
    print("=" * 80)

    # Check if running as root (recommended for some scans)
    if os.geteuid() != 0:
        print(
            "⚠️ WARNING: Not running as root. Some scans may require elevated privileges."
        )
        print("Consider running with sudo for full functionality.\n")

    # Check required tools
    required_tools = ["nmap", "nikto", "gobuster", "dig", "curl", "openssl"]
    missing_tools = []

    for tool in required_tools:
        result = run_command(["which", tool], timeout=5)
        if result["returncode"] != 0:
            missing_tools.append(tool)

    if missing_tools:
        print(f"❌ Missing required tools: {', '.join(missing_tools)}")
        print("Please install missing tools before running the assessment.")
        return False

    print("✅ All required tools are available")

    # Confirm target
    target = "simefin.top"
    print(f"\n🎯 Target confirmed: {target}")

    response = input("Do you want to proceed with the security assessment? [y/N]: ")
    if response.lower() not in ["y", "yes"]:
        print("Assessment cancelled by user.")
        return False

    # Execute the scan
    try:
        results = test_simefin_scan()
        print("\n🎉 Security assessment completed successfully!")
        return True
    except KeyboardInterrupt:
        print("\n⚠️ Assessment interrupted by user")
        return False
    except Exception as e:
        print(f"\n❌ Assessment failed: {e}")
        logger.exception("Assessment failed with exception")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
