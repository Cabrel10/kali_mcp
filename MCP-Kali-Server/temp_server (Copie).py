#!/usr/bin/env /home/morningstar/miniconda3/envs/trading_env/bin/python3

import asyncio
import subprocess
import json
import logging
import shlex
import tempfile
import os
import re  # Added for regex parsing of Metasploit output
import datetime  # Added for logging timestamps
import xml.etree.ElementTree as ET  # Added for parsing Nmap XML output
from typing import Dict, Any, Optional, List

from fastmcp import FastMCP

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(
            "/home/morningstar/Bureau/kali_mcp/MCP-Kali-Server/kali_mcp_server.log"
        ),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# Add a directory for tool execution logs
TOOL_LOG_DIR = os.path.join(os.path.dirname(__file__), "tool_logs")
os.makedirs(TOOL_LOG_DIR, exist_ok=True)

# Global variable for the current session ID
CURRENT_SESSION_ID = None


def log_tool_execution(tool_name: str, inputs: Dict[str, Any], outputs: Dict[str, Any]):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    log_filename = os.path.join(TOOL_LOG_DIR, f"{tool_name}_{timestamp}.json")
    log_data = {
        "tool_name": tool_name,
        "timestamp": timestamp,
        "inputs": inputs,
        "outputs": outputs,
    }
    try:
        with open(log_filename, "w") as f:
            json.dump(log_data, f, indent=2)
        logger.info(f"Logged {tool_name} execution to {log_filename}")
    except Exception as e:
        logger.error(f"Failed to log {tool_name} execution: {e}")

    if CURRENT_SESSION_ID:
        session_dir = os.path.join(
            os.path.dirname(__file__), "sessions", CURRENT_SESSION_ID
        )
        tool_dir = os.path.join(session_dir, tool_name)
        os.makedirs(tool_dir, exist_ok=True)
        output_filename = os.path.join(tool_dir, f"output_{timestamp}.json")
        try:
            with open(output_filename, "w") as f:
                json.dump(outputs, f, indent=2)
            logger.info(f"Saved {tool_name} output to {output_filename}")
        except Exception as e:
            logger.error(f"Failed to save {tool_name} output: {e}")


def verify_output_file(
    file_path: str, expected_format: str, tool_name: str, min_size_bytes: int = 10
) -> Dict[str, Any]:
    """
    MANDATORY VERIFICATION FUNCTION - "Pas de sortie, pas de succès" principle

    Verifies that an output file exists, is not empty, and contains exploitable data.
    This function MUST be called after every tool execution.

    Args:
        file_path: Path to the output file to verify
        expected_format: Expected format ('xml', 'json', 'text')
        tool_name: Name of the tool for logging purposes
        min_size_bytes: Minimum acceptable file size in bytes

    Returns:
        Dict with 'success' boolean and 'error'/'details' strings
    """
    verification_result = {
        "success": False,
        "error": "",
        "details": {
            "file_exists": False,
            "file_size": 0,
            "format_valid": False,
            "contains_data": False,
            "file_path": file_path,
        },
    }

    try:
        # Step 1: Check if file exists
        if not os.path.exists(file_path):
            verification_result["error"] = f"Output file does not exist: {file_path}"
            logger.error(f"{tool_name} verification failed: File does not exist")
            return verification_result

        verification_result["details"]["file_exists"] = True

        # Step 2: Check file size
        file_size = os.path.getsize(file_path)
        verification_result["details"]["file_size"] = file_size

        if file_size < min_size_bytes:
            verification_result["error"] = (
                f"Output file is too small ({file_size} bytes). Minimum: {min_size_bytes} bytes"
            )
            logger.error(
                f"{tool_name} verification failed: File too small ({file_size} bytes)"
            )
            return verification_result

        # Step 3: Read and validate content based on format
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()

        if not content:
            verification_result["error"] = "Output file is empty"
            logger.error(f"{tool_name} verification failed: Empty file content")
            return verification_result

        # Step 4: Format-specific validation
        if expected_format == "xml":
            try:
                root = ET.fromstring(content)
                # Check if XML has meaningful content
                if len(list(root)) == 0 and not root.text:
                    verification_result["error"] = (
                        "XML file contains no meaningful data"
                    )
                    return verification_result
                verification_result["details"]["format_valid"] = True
                verification_result["details"]["contains_data"] = True
            except ET.ParseError as e:
                verification_result["error"] = f"Invalid XML format: {str(e)}"
                return verification_result

        elif expected_format == "json":
            try:
                data = json.loads(content)
                # Check if JSON has meaningful content
                if not data or (isinstance(data, (dict, list)) and len(data) == 0):
                    verification_result["error"] = (
                        "JSON file contains no meaningful data"
                    )
                    return verification_result
                verification_result["details"]["format_valid"] = True
                verification_result["details"]["contains_data"] = True
            except json.JSONDecodeError as e:
                verification_result["error"] = f"Invalid JSON format: {str(e)}"
                return verification_result

        elif expected_format == "text":
            # For text files, check for common indicators of successful tool execution
            lines = content.split("\n")
            non_empty_lines = [line for line in lines if line.strip()]

            if len(non_empty_lines) < 2:  # At least 2 meaningful lines expected
                verification_result["error"] = (
                    "Text file contains insufficient data (less than 2 meaningful lines)"
                )
                return verification_result

            # Look for common success indicators vs error indicators
            error_indicators = [
                "error",
                "failed",
                "not found",
                "no results",
                "0 results",
                "unable to",
                "cannot",
                "permission denied",
                "access denied",
                "connection refused",
                "timeout",
                "not reachable",
            ]

            success_indicators = [
                "found",
                "discovered",
                "open",
                "status:",
                "=>",
                "[+]",
                "vulnerable",
                "exploit",
                "result",
                "detected",
                "port",
            ]

            content_lower = content.lower()
            error_count = sum(
                1 for indicator in error_indicators if indicator in content_lower
            )
            success_count = sum(
                1 for indicator in success_indicators if indicator in content_lower
            )

            # If too many error indicators and no success indicators, likely failed
            if error_count > 3 and success_count == 0:
                verification_result["error"] = (
                    "Text file appears to contain mostly error messages or no results"
                )
                return verification_result

            verification_result["details"]["format_valid"] = True
            verification_result["details"]["contains_data"] = True

        else:
            # Unknown format, basic validation only
            verification_result["details"]["format_valid"] = True
            verification_result["details"]["contains_data"] = True

        # All checks passed
        verification_result["success"] = True
        logger.info(
            f"{tool_name} output verification successful: {file_path} ({file_size} bytes)"
        )
        return verification_result

    except Exception as e:
        verification_result["error"] = f"Verification failed with exception: {str(e)}"
        logger.error(f"{tool_name} verification exception: {str(e)}")
        return verification_result


# Création du serveur FastMCP
mcp = FastMCP("Kali Tools Server v2")

from functools import wraps


def resolve_session_reference(reference: str) -> Any:
    """
    Resolves a session reference to its actual value.
    A reference is in the format @session:<tool_name>:<output_key>
    """
    if not reference.startswith("@session:"):
        return reference

    parts = reference.split(":")
    if len(parts) != 3:
        raise ValueError(f"Invalid session reference format: {reference}")

    _, tool_name, output_key = parts

    if not CURRENT_SESSION_ID:
        raise ValueError("No active session. Please start a session first.")

    session_dir = os.path.join(
        os.path.dirname(__file__), "sessions", CURRENT_SESSION_ID
    )
    tool_dir = os.path.join(session_dir, tool_name)

    if not os.path.exists(tool_dir):
        raise ValueError(
            f"No output found for tool '{tool_name}' in the current session."
        )

    # Find the latest output file for the tool
    output_files = [
        f
        for f in os.listdir(tool_dir)
        if f.startswith("output_") and f.endswith(".json")
    ]
    if not output_files:
        raise ValueError(
            f"No output files found for tool '{tool_name}' in the current session."
        )

    output_files.sort(reverse=True)
    latest_output_file = os.path.join(tool_dir, output_files[0])

    with open(latest_output_file, "r") as f:
        output_data = json.load(f)

    # The output_key can be a nested key, e.g., "machine_response.parsed_data.hosts.0.addresses.0"
    keys = output_key.split(".")
    value = output_data
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        elif isinstance(value, list) and key.isdigit() and int(key) < len(value):
            value = value[int(key)]
        else:
            raise ValueError(
                f"Key '{output_key}' not found in the output of tool '{tool_name}'."
            )

    return value


def resolve_references(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        resolved_kwargs = {}
        for key, value in kwargs.items():
            if isinstance(value, str):
                try:
                    resolved_kwargs[key] = resolve_session_reference(value)
                except ValueError as e:
                    # If the reference is invalid, we just pass it as is.
                    # The tool might be able to handle it.
                    logger.warning(f"Could not resolve reference '{value}': {e}")
                    resolved_kwargs[key] = value
            else:
                resolved_kwargs[key] = value
        return await func(*args, **resolved_kwargs)

    return wrapper


@mcp.tool()
async def start_session() -> str:
    """
    Starts a new session and creates a directory to store the results.
    """
    global CURRENT_SESSION_ID
    inputs = {}

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = os.path.join(os.path.dirname(__file__), "sessions", timestamp)
    os.makedirs(session_dir, exist_ok=True)

    CURRENT_SESSION_ID = timestamp

    response_machine = {
        "status": "success",
        "session_id": timestamp,
        "session_dir": session_dir,
    }
    response_user = f"New session started with ID: {timestamp}. Results will be saved in {session_dir}"

    outputs = {"machine_response": response_machine, "user_response": response_user}
    # We don't call log_tool_execution here, as it would create a chicken-and-egg problem with the session ID

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


def run_command(command: list, timeout: int = 600) -> Dict[str, Any]:
    """Helper function to run a command and return structured output."""
    try:
        logger.info(f"Executing command: {' '.join(command)}")
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "return_code": result.returncode,
        }
    except FileNotFoundError:
        logger.error(f"Command not found: {command[0]}")
        return {
            "stdout": "",
            "stderr": f"Error: Command '{command[0]}' not found. Please ensure it is installed and in your PATH.",
            "return_code": -1,
        }
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s: {' '.join(command)}")
        return {
            "stdout": "",
            "stderr": f"Error: Command execution timed out after {timeout} seconds.",
            "return_code": -1,
        }
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        return {
            "stdout": "",
            "stderr": f"An unexpected error occurred: {str(e)}",
            "return_code": -1,
        }


@mcp.tool()
async def server_health() -> str:
    """
    Checks the status of the Kali server and the availability of essential tools.
    Essential for starting a pentest or CTF. Logs execution.
    """
    inputs = {}  # No specific inputs for server_health

    tools_to_check = [
        "nmap",
        "gobuster",
        "dirb",
        "nikto",
        "sqlmap",
        "msfconsole",
        "hydra",
        "john",
        "wpscan",
        "enum4linux",
    ]
    tool_status = {}
    for tool in tools_to_check:
        result = run_command(["which", tool])
        tool_status[tool] = result["return_code"] == 0

    response_machine = {"status": "ok", "tools": tool_status}
    response_user = f"Server status: OK. Available tools: {', '.join([t for t, s in tool_status.items() if s])}"

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("server_health", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def execute_command(command: str) -> str:
    """
    Executes an arbitrary shell command on the Kali machine.
    Useful for chaining tools or running custom commands. Logs execution.
    """
    inputs = {"command": command}

    logger.info(f"Executing arbitrary command: {command}")
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        response_machine = {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "return_code": result.returncode,
        }
        response_user = f"Command executed.\n---STDOUT---\n{result.stdout.strip()}\n---STDERR---\n{result.stderr.strip()}\nReturn Code: {result.returncode}"
    except Exception as e:
        logger.error(f"Error executing command '{command}': {e}")
        response_machine = {"stdout": "", "stderr": str(e), "return_code": -1}
        response_user = f"Failed to execute command. Error: {str(e)}"

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("execute_command", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def nmap_scan(
    target: str,
    scan_type: str = "basic",
    output_format: str = "xml",  # Default to XML as per user's request
    output_file: Optional[str] = None,
    additional_args: str = "",
    timeout: int = 600,
    intensity: str = "medium",
) -> str:
    """
    Performs network reconnaissance (ports, services) using Nmap.
    Outputs results in a specified format (default: XML) and logs execution.
    Provides structured parsing of XML output.
    MANDATORY: output_file is required for reliable operation.
    """
    inputs = {
        "target": target,
        "scan_type": scan_type,
        "output_format": output_format,
        "output_file": output_file,
        "additional_args": additional_args,
        "timeout": timeout,
        "intensity": intensity,
    }

    scan_options = {
        "basic": ["-sV", "-sC"],
        "full": ["-p-", "-sV", "-sC", "-O"],
        "quick": ["-F"],
        "os_detection": ["-O"],
        "version_detection": ["-sV"],
        "script_scan": ["-sC"],
    }

    if scan_type not in scan_options:
        error_msg = f"Invalid scan type. Choose from {list(scan_options.keys())}"
        outputs = {"status": "failed", "error": error_msg}
        log_tool_execution("nmap_scan", inputs, outputs)
        return json.dumps({"machine": outputs, "user": error_msg}, indent=2)

    # Determine output file path - ALWAYS create explicit output file
    if output_file:
        output_path = output_file
    else:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            TOOL_LOG_DIR,
            f"nmap_scan_{target.replace('/', '_')}_{timestamp}.{output_format}",
        )

    cmd = ["nmap"] + scan_options[scan_type]

    # Add intensity
    intensity_map = {"low": "-T2", "medium": "-T3", "high": "-T4"}
    if intensity in intensity_map:
        cmd.append(intensity_map[intensity])
    else:  # default to medium if invalid value
        cmd.append(intensity_map["medium"])

    if output_format == "xml":
        cmd.extend(["-oX", output_path])
    elif output_format == "gnmap":
        cmd.extend(["-oG", output_path])
    elif output_format == "normal":
        cmd.extend(["-oN", output_path])
    else:
        error_msg = f"Unsupported output format: {output_format}. Supported: xml, gnmap, normal."
        outputs = {"status": "failed", "error": error_msg}
        log_tool_execution("nmap_scan", inputs, outputs)
        return json.dumps({"machine": outputs, "user": error_msg}, indent=2)

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    cmd.append(target)

    result = run_command(cmd, timeout=timeout)

    # MANDATORY VERIFICATION STEP - Principle: "Pas de sortie, pas de succès"
    verification = verify_output_file(
        output_path, expected_format=output_format, tool_name="nmap_scan"
    )

    if not verification["success"]:
        error_msg = f"Nmap scan failed output verification: {verification['error']}"
        response_machine = {
            "status": "failed",
            "error": error_msg,
            "raw_cli_output": result["stdout"],
            "stderr": result["stderr"],
            "verification_details": verification["details"],
        }
        response_user = f"Nmap scan failed. {error_msg}"
        outputs = {"machine_response": response_machine, "user_response": response_user}
        log_tool_execution("nmap_scan", inputs, outputs)
        return json.dumps(
            {"machine": response_machine, "user": response_user}, indent=2
        )

    nmap_output_content = ""
    parsed_nmap_data = {}
    if os.path.exists(output_path):
        try:
            with open(output_path, "r") as f:
                nmap_output_content = f.read()

            if output_format == "xml":
                root = ET.fromstring(nmap_output_content)
                hosts_data = []
                for host in root.findall("host"):
                    host_info = {
                        "addresses": [],
                        "hostnames": [],
                        "ports": [],
                        "os": "Unknown",
                    }
                    for address in host.findall("address"):
                        host_info["addresses"].append(address.get("addr"))
                    for hostname in host.findall("hostnames/hostname"):
                        host_info["hostnames"].append(hostname.get("name"))

                    for port in host.findall("ports/port"):
                        port_info = {
                            "portid": port.get("portid"),
                            "protocol": port.get("protocol"),
                            "state": port.find("state").get("state")
                            if port.find("state") is not None
                            else "unknown",
                            "service": port.find("service").get("name")
                            if port.find("service") is not None
                            else "unknown",
                            "product": port.find("service").get("product")
                            if port.find("service") is not None
                            and port.find("service").get("product")
                            else None,
                            "version": port.find("service").get("version")
                            if port.find("service") is not None
                            and port.find("service").get("version")
                            else None,
                        }
                        host_info["ports"].append(port_info)

                    os_match = host.find("os/osmatch")
                    if os_match is not None:
                        host_info["os"] = os_match.get("name")

                    hosts_data.append(host_info)
                parsed_nmap_data = {"hosts": hosts_data}

        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML output from {output_path}: {e}")
            parsed_nmap_data = {"error": f"Failed to parse XML output: {e}"}
        except Exception as e:
            logger.error(f"Failed to read Nmap output file {output_path}: {e}")
            nmap_output_content = f"Error reading output file: {e}"

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
            "output_file_content": nmap_output_content,
            "parsed_data": parsed_nmap_data,
        }
        response_user = f"Nmap scan failed. Error: {result['stderr']}"
    else:
        summary_ports = []
        summary_os = []
        if "hosts" in parsed_nmap_data:
            for host_entry in parsed_nmap_data["hosts"]:
                for port_entry in host_entry["ports"]:
                    if port_entry["state"] == "open":
                        service_info = f"{port_entry['portid']}/{port_entry['protocol']} ({port_entry['service']}"
                        if port_entry["product"]:
                            service_info += f" {port_entry['product']}"
                        if port_entry["version"]:
                            service_info += f" {port_entry['version']}"
                        service_info += ")"
                        summary_ports.append(service_info)
                if host_entry["os"] != "Unknown":
                    summary_os.append(host_entry["os"])

        response_machine = {
            "status": "success",
            "target": target,
            "raw_cli_output": result["stdout"],
            "output_file_path": output_path,
            "output_file_content": nmap_output_content,
            "parsed_data": parsed_nmap_data,
        }
        user_summary = (
            f"Nmap scan on {target} complete. Results saved to {output_path}."
        )
        if summary_ports:
            user_summary += f"\nOpen ports and services: {', '.join(summary_ports)}."
        if summary_os:
            user_summary += f"\nDetected OS: {', '.join(summary_os)}."
        if not summary_ports and not summary_os:
            user_summary += "\nNo open ports or OS detected."

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("nmap_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def gobuster_scan(
    url: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    output_file: Optional[str] = None,
    additional_args: str = "",
    timeout: int = 600,
    intensity: str = "medium",
) -> str:
    """
    Scans for directories, DNS subdomains, or vhosts using Gobuster.
    Outputs results to a file, parses them, and logs execution.
    MANDATORY: output_file verification ensures reliable results.
    """
    inputs = {
        "url": url,
        "mode": mode,
        "wordlist": wordlist,
        "output_file": output_file,
        "additional_args": additional_args,
        "timeout": timeout,
        "intensity": intensity,
    }

    # Determine output file path - ALWAYS create explicit output file
    if output_file:
        output_path = output_file
    else:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            TOOL_LOG_DIR,
            f"gobuster_scan_{mode}_{url.replace('https://', '').replace('http://', '').replace('/', '_')}_{timestamp}.txt",
        )

    cmd = ["gobuster", mode]
    if mode == "dns":
        cmd.extend(["--domain", url])  # Fixed: use --domain instead of -u for DNS mode
    else:
        cmd.extend(["-u", url])

    # Add intensity (threads) - More conservative for stability
    intensity_map = {"low": "5", "medium": "15", "high": "25"}
    threads = intensity_map.get(intensity, "15")

    cmd.extend([
        "-w", wordlist,
        "--no-progress",
        "-t", threads,
        "-o", output_path,
        "--delay", "100ms",  # Add delay to avoid rate limiting
        "--timeout", "10s"   # Set explicit timeout
    ])

    # Add common extensions for file enumeration
    if mode == "dir":
        cmd.extend(["-x", "php,html,txt,js,css,json,xml,bak,old"])

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd, timeout=timeout)

    # MANDATORY VERIFICATION STEP - Principle: "Pas de sortie, pas de succès"
    verification = verify_output_file(
        output_path, expected_format="text", tool_name="gobuster_scan"
    )

    if not verification["success"]:
        error_msg = f"Gobuster scan failed output verification: {verification['error']}"
        response_machine = {
            "status": "failed",
            "error": error_msg,
            "raw_cli_output": result["stdout"],
            "stderr": result["stderr"],
            "verification_details": verification["details"],
        }
        response_user = f"Gobuster scan failed. {error_msg}"
        outputs = {"machine_response": response_machine, "user_response": response_user}
        log_tool_execution("gobuster_scan", inputs, outputs)
        return json.dumps(
            {"machine": response_machine, "user": response_user}, indent=2
        )

    gobuster_output_content = ""
    discovered_items = []
    if os.path.exists(output_path):
        try:
            with open(output_path, "r") as f:
                gobuster_output_content = f.read()
            # Enhanced parsing for discovered paths/subdomains
            for line in gobuster_output_content.split("\n"):
                line = line.strip()
                if not line or line.startswith('=') or line.startswith('[INFO]'):
                    continue

                # Multiple patterns for gobuster output (more comprehensive)
                success_patterns = [
                    "Status:",
                    "Found:",
                    "[+]",
                    "=>",
                    "(Status:",
                    "Discovered:",
                    "200",
                    "301",
                    "302",
                    "403",  # Sometimes interesting
                    "401"   # Authentication required
                ]

                if any(pattern in line for pattern in success_patterns):
                    discovered_items.append(line)
                # Also catch lines with path and status code patterns
                elif re.match(r"^[/\w\.-]+.*\(Status:\s*\d+\)", line):
                    discovered_items.append(line)
                # Catch simple path listings (some gobuster versions)
                elif line.startswith('/') and any(char in line for char in ['200', '301', '302', '403', '401']):
                    discovered_items.append(line)
        except Exception as e:
            logger.error(f"Failed to read Gobuster output file {output_path}: {e}")
            gobuster_output_content = f"Error reading output file: {e}"

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
            "output_file_content": gobuster_output_content,
            "discovered_items": discovered_items,
        }
        response_user = f"Gobuster scan failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "target_url": url,
            "mode": mode,
            "raw_cli_output": result["stdout"],
            "output_file_path": output_path,
            "output_file_content": gobuster_output_content,
            "discovered_items": discovered_items,
        }
        user_summary = f"Gobuster scan on {url} ({mode} mode) complete. Results saved to {output_path}."
        if discovered_items:
            user_summary += (
                f"\nDiscovered {len(discovered_items)} items:\n"
                + "\n".join(discovered_items[:10])
            )  # Show first 10
            if len(discovered_items) > 10:
                user_summary += "\n..."
        else:
            user_summary += "\nNo items discovered."

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("gobuster_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def dirb_scan(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Scans for web content and directories using Dirb.
    Outputs results to a file, parses them, and logs execution.
    """
    inputs = {
        "url": url,
        "wordlist": wordlist,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    # Determine output file path
    if output_file:
        output_path = output_file
    else:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            TOOL_LOG_DIR,
            f"dirb_scan_{url.replace('https://', '').replace('http://', '').replace('/', '_')}_{timestamp}.txt",
        )

    cmd = ["dirb", url, wordlist, "-o", output_path]  # Output to file
    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    # MANDATORY VERIFICATION STEP - Principle: "Pas de sortie, pas de succès"
    verification = verify_output_file(
        output_path, expected_format="text", tool_name="dirb_scan"
    )

    if not verification["success"]:
        error_msg = f"Dirb scan failed output verification: {verification['error']}"
        response_machine = {
            "status": "failed",
            "error": error_msg,
            "raw_cli_output": result["stdout"],
            "stderr": result["stderr"],
            "verification_details": verification["details"],
        }
        response_user = f"Dirb scan failed. {error_msg}"
        outputs = {"machine_response": response_machine, "user_response": response_user}
        log_tool_execution("dirb_scan", inputs, outputs)
        return json.dumps(
            {"machine": response_machine, "user": response_user}, indent=2
        )

    dirb_output_content = ""
    discovered_items = []
    if os.path.exists(output_path):
        try:
            with open(output_path, "r") as f:
                dirb_output_content = f.read()
            # Robust parsing for discovered paths
            for line in dirb_output_content.split("\n"):
                line = line.strip()
                if not line:
                    continue
                # Multiple patterns for dirb output
                if any(
                    pattern in line
                    for pattern in [
                        "+",  # Dirb marks discovered paths with '+'
                        "DIRECTORY:",
                        "FILE:",
                        "==> DIRECTORY:",
                        "==> FILE:",
                        "200",
                        "301",
                        "302",
                    ]
                ):
                    discovered_items.append(line)
                # Also catch HTTP status codes in format like "200 - 1234B"
                elif re.match(r"^.*\s+(200|301|302|403|401)\s+.*$", line):
                    discovered_items.append(line)
        except Exception as e:
            logger.error(f"Failed to read Dirb output file {output_path}: {e}")
            dirb_output_content = f"Error reading output file: {e}"

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
            "output_file_content": dirb_output_content,
            "discovered_items": discovered_items,
        }
        response_user = f"Dirb scan failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "target_url": url,
            "raw_cli_output": result["stdout"],
            "output_file_path": output_path,
            "output_file_content": dirb_output_content,
            "discovered_items": discovered_items,
        }
        user_summary = f"Dirb scan on {url} complete. Results saved to {output_path}."
        if discovered_items:
            user_summary += (
                f"\nDiscovered {len(discovered_items)} items:\n"
                + "\n".join(discovered_items[:10])
            )  # Show first 10
            if len(discovered_items) > 10:
                user_summary += "\n..."
        else:
            user_summary += "\nNo items discovered."

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("dirb_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def nikto_scan(
    target: str,
    output_format: str = "xml",  # Default to XML as per user's request
    output_file: Optional[str] = None,
    additional_args: str = "",
    timeout: int = 600,
    intensity: str = "medium",
) -> str:
    """
    Scans for web server vulnerabilities using Nikto.
    Outputs results in a specified format (default: XML) and logs execution.
    Provides structured parsing of XML output if format is XML.
    MANDATORY: output_file verification ensures reliable results.
    """
    inputs = {
        "target": target,
        "output_format": output_format,
        "output_file": output_file,
        "additional_args": additional_args,
        "timeout": timeout,
        "intensity": intensity,
    }

    # Determine output file path - ALWAYS create explicit output file
    if output_file:
        output_path = output_file
    else:
        # Generate a unique filename for the Nikto output
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            TOOL_LOG_DIR,
            f"nikto_scan_{target.replace('https://', '').replace('http://', '').replace('/', '_')}_{timestamp}.{output_format}",
        )

    cmd = ["nikto", "-h", target, "-timeout", str(timeout)]

    if output_format == "xml":
        cmd.extend(["-Format", "xml", "-o", output_path])
    elif output_format == "json":
        # Nikto doesn't have native JSON output, so we'll output XML and parse it
        cmd.extend(["-Format", "xml", "-o", output_path])
        logger.warning(
            "Nikto does not natively support JSON output. Outputting XML and will attempt to parse to JSON."
        )
    elif output_format == "html":
        cmd.extend(["-Format", "htm", "-o", output_path])
    elif output_format == "txt":
        cmd.extend(["-Format", "txt", "-o", output_path])
    else:
        error_msg = f"Unsupported output format: {output_format}. Supported: xml, json (via xml), html, txt."
        outputs = {"status": "failed", "error": error_msg}
        log_tool_execution("nikto_scan", inputs, outputs)
        return json.dumps({"machine": outputs, "user": error_msg}, indent=2)

    # Add intensity (Tuning)
    intensity_map = {
        "low": ["-Tuning", "0123"],
        "medium": ["-Tuning", "x6"],
        "high": ["-Tuning", "x6b"],
    }
    if "Tuning" not in additional_args and "-t" not in additional_args:
        if intensity in intensity_map:
            cmd.extend(intensity_map[intensity])
        else:
            cmd.extend(intensity_map["medium"])

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd, timeout=timeout)

    # MANDATORY VERIFICATION STEP - Principle: "Pas de sortie, pas de succès"
    verification = verify_output_file(
        output_path, expected_format=output_format, tool_name="nikto_scan"
    )

    if not verification["success"]:
        error_msg = f"Nikto scan failed output verification: {verification['error']}"
        response_machine = {
            "status": "failed",
            "error": error_msg,
            "raw_cli_output": result["stdout"],
            "stderr": result["stderr"],
            "verification_details": verification["details"],
        }
        response_user = f"Nikto scan failed. {error_msg}"
        outputs = {"machine_response": response_machine, "user_response": response_user}
        log_tool_execution("nikto_scan", inputs, outputs)
        return json.dumps(
            {"machine": response_machine, "user": response_user}, indent=2
        )

    nikto_output_content = ""
    parsed_nikto_data = {}
    if os.path.exists(output_path):
        try:
            with open(output_path, "r") as f:
                nikto_output_content = f.read()

            if (
                output_format == "xml" or output_format == "json"
            ):  # Parse XML if output was XML
                root = ET.fromstring(nikto_output_content)
                nikto_scan_data = {
                    "target": target,
                    "vulnerabilities": [],
                    "errors": [],
                    "statistics": {},
                }

                # Parse vulnerabilities
                for item in root.findall(".//item"):
                    vuln = {
                        "id": item.get("id"),
                        "osvdb": item.get("osvdb"),
                        "method": item.get("method"),
                        "url": item.find("uri").text
                        if item.find("uri") is not None
                        else None,
                        "description": item.find("description").text
                        if item.find("description") is not None
                        else None,
                        "solution": item.find("solution").text
                        if item.find("solution") is not None
                        else None,
                        "references": [
                            ref.text for ref in item.findall("references/reference")
                        ],
                    }
                    nikto_scan_data["vulnerabilities"].append(vuln)

                # Parse errors (if any) - Nikto XML doesn't have a dedicated error section, usually in stdout
                # For now, we'll rely on stderr from run_command for errors

                # Parse statistics (if available)
                # Nikto XML doesn't have a dedicated statistics section, usually in stdout

                parsed_nikto_data = nikto_scan_data

                if (
                    output_format == "json"
                ):  # Convert XML parsed data to JSON if requested
                    parsed_nikto_data = json.loads(
                        json.dumps(parsed_nikto_data)
                    )  # Simple conversion

        except ET.ParseError as e:
            logger.error(f"Failed to parse Nikto XML output from {output_path}: {e}")
            parsed_nikto_data = {"error": f"Failed to parse XML output: {e}"}
        except Exception as e:
            logger.error(f"Failed to read Nikto output file {output_path}: {e}")
            nikto_output_content = f"Error reading output file: {e}"

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
            "output_file_content": nikto_output_content,
            "parsed_data": parsed_nikto_data,
        }
        response_user = f"Nikto scan failed. Error: {result['stderr']}"
    else:
        summary_vulns = []
        if "vulnerabilities" in parsed_nikto_data:
            for vuln_entry in parsed_nikto_data["vulnerabilities"]:
                summary_vulns.append(
                    f"ID {vuln_entry.get('id')}: {vuln_entry.get('description')}"
                )

        response_machine = {
            "status": "success",
            "target": target,
            "raw_cli_output": result["stdout"],
            "output_file_path": output_path,
            "output_file_content": nikto_output_content,
            "parsed_data": parsed_nikto_data,
        }
        user_summary = (
            f"Nikto scan on {target} complete. Results saved to {output_path}."
        )
        if summary_vulns:
            user_summary += (
                f"\nFound {len(summary_vulns)} potential vulnerabilities:\n"
                + "\n".join(summary_vulns)
            )
        else:
            user_summary += "\nNo significant vulnerabilities found."

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("nikto_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def sqlmap_scan(
    url: str,
    data: Optional[str] = None,
    dump_data: bool = False,  # New parameter for dumping data
    output_dir: Optional[str] = None,  # New parameter for output directory
    additional_args: str = "--batch",
    timeout: int = 1200,
) -> str:
    """
    Scans for and exploits SQL injection vulnerabilities using SQLMap.
    Can optionally dump data to a specified output directory. Logs execution.
    MANDATORY: output_dir verification ensures reliable results.
    """
    inputs = {
        "url": url,
        "data": data,
        "dump_data": dump_data,
        "output_dir": output_dir,
        "additional_args": additional_args,
        "timeout": timeout,
    }

    # Always create explicit output directory for SQLMap
    if output_dir:
        sqlmap_output_path = output_dir
    else:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        sqlmap_output_path = os.path.join(
            TOOL_LOG_DIR,
            f"sqlmap_session_{url.replace('https://', '').replace('http://', '').replace('/', '_')}_{timestamp}",
        )

    os.makedirs(sqlmap_output_path, exist_ok=True)

    cmd = ["sqlmap", "-u", url, "--output-dir", sqlmap_output_path]
    if data:
        cmd.extend(["--data", data])

    if dump_data:
        cmd.extend(["--dump"])

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd, timeout=timeout)

    # MANDATORY VERIFICATION STEP - Check if SQLMap created meaningful output
    session_files = []
    log_files = []
    dumped_files = []

    if os.path.exists(sqlmap_output_path):
        for root, dirs, files in os.walk(sqlmap_output_path):
            for file in files:
                full_path = os.path.join(root, file)
                if file.endswith(".session"):
                    session_files.append(full_path)
                elif file.endswith(".log"):
                    log_files.append(full_path)
                elif dump_data and (file.endswith(".csv") or file.endswith(".txt")):
                    dumped_files.append(full_path)

    # Verify that SQLMap produced meaningful output
    if not session_files and not log_files:
        error_msg = "SQLMap failed to create session or log files - scan may have failed completely"
        response_machine = {
            "status": "failed",
            "error": error_msg,
            "raw_cli_output": result["stdout"],
            "stderr": result["stderr"],
            "output_dir_path": sqlmap_output_path,
        }
        response_user = f"SQLMap scan failed. {error_msg}"
        outputs = {"machine_response": response_machine, "user_response": response_user}
        log_tool_execution("sqlmap_scan", inputs, outputs)
        return json.dumps(
            {"machine": response_machine, "user": response_user}, indent=2
        )

    # Analyze results for vulnerability indicators
    vulnerable = False
    injection_details = []

    # Check multiple indicators of successful injection
    vuln_indicators = [
        "sqlmap identified the following injection point",
        "Parameter: ",
        "Type: ",
        "Title: ",
        "Payload: ",
        "injectable",
        "vulnerable",
    ]

    stdout_content = result["stdout"].lower()
    for indicator in vuln_indicators:
        if indicator.lower() in stdout_content:
            vulnerable = True
            break

    # Parse injection details from output
    if vulnerable:
        lines = result["stdout"].split("\n")
        for line in lines:
            if any(
                key in line for key in ["Parameter:", "Type:", "Title:", "Payload:"]
            ):
                injection_details.append(line.strip())

    if vulnerable:
        status = "success"
        user_msg = (
            f"SQLMap scan complete. SQL injection vulnerability found!\nInjection details:\n"
            + "\n".join(injection_details)
        )
        if dumped_files:
            user_msg += f"\nData dumped to {len(dumped_files)} files."
    else:
        status = "success"
        user_msg = f"SQLMap scan complete. No SQL injection vulnerability detected."

    response_machine = {
        "status": status,
        "vulnerable": vulnerable,
        "injection_details": injection_details,
        "raw_cli_output": result["stdout"],
        "stderr": result["stderr"],
        "return_code": result["return_code"],
        "output_dir_path": sqlmap_output_path,
        "session_files": session_files,
        "log_files": log_files,
        "dumped_files": dumped_files,
    }
    response_user = user_msg
    if dumped_files:
        response_user += f"\nDumped data saved to: {sqlmap_output_path}. Files: {', '.join(dumped_files)}"

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("sqlmap_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def metasploit_console_command(
    commands: List[str],  # List of commands to execute in msfconsole
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Executes a list of commands within the Metasploit console.
    Useful for running modules, interacting with sessions, etc.
    Logs execution and captures output.
    """
    inputs = {
        "commands": commands,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    rc_script_content = ""
    for cmd_line in commands:
        rc_script_content += f"{cmd_line}\n"
    rc_script_content += "exit\n"  # Ensure msfconsole exits

    rc_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".rc", dir=TOOL_LOG_DIR
        ) as rc_file:
            rc_file.write(rc_script_content)
            rc_path = rc_file.name

        cmd = ["msfconsole", "-r", rc_path]
        if additional_args:
            cmd.extend(shlex.split(additional_args))

        result = run_command(cmd)

        msf_output = result["stdout"]

        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(msf_output)
                logger.info(f"Metasploit output saved to {output_file}")
            except Exception as e:
                logger.error(f"Failed to write Metasploit output to {output_file}: {e}")
                output_file = f"Error saving to file: {e}"

        if result["return_code"] != 0:
            response_machine = {
                "status": "failed",
                "error": result["stderr"],
                "raw_cli_output": result["stdout"],
                "rc_script_path": rc_path,
            }
            response_user = (
                f"Metasploit command execution failed. Error: {result['stderr']}"
            )
        else:
            response_machine = {
                "status": "success",
                "raw_cli_output": result["stdout"],
                "raw_cli_stderr": result["stderr"],
                "rc_script_path": rc_path,
                "output_file_path": output_file,
            }
            response_user = f"Metasploit commands executed. Output:\n{result['stdout']}"
            if output_file:
                response_user += f"\nOutput also saved to: {output_file}"

    except Exception as e:
        response_machine = {"status": "failed", "error": str(e)}
        response_user = f"An error occurred while trying to run Metasploit: {e}"
    finally:
        if rc_path and os.path.exists(rc_path):
            os.remove(rc_path)

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("metasploit_console_command", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def hydra_bruteforce(
    target: str,
    service: str,
    username: Optional[str] = None,
    userlist: Optional[str] = None,
    password: Optional[str] = None,
    passlist: Optional[str] = None,
    output_file: Optional[str] = None,  # New parameter for output file
    additional_args: str = "",
) -> str:
    """
    Performs a brute-force attack on a service using Hydra.
    """
    inputs = {
        "target": target,
        "service": service,
        "username": username,
        "userlist": userlist,
        "password": password,
        "passlist": passlist,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    if not (username or userlist) or not (password or passlist):
        error_msg = "Either a username or a userlist, and a password or a passlist must be provided."
        outputs = {"status": "failed", "error": error_msg}
        log_tool_execution("hydra_bruteforce", inputs, outputs)
        return json.dumps({"machine": outputs, "user": error_msg}, indent=2)

    cmd = ["hydra"]
    if username:
        cmd.extend(["-l", username])
    elif userlist:
        cmd.extend(["-L", userlist])

    if password:
        cmd.extend(["-p", password])
    elif passlist:
        cmd.extend(["-P", passlist])

    cmd.extend([target, service])

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    if output_file:
        cmd.extend(["-o", output_file])

    result = run_command(cmd)

    if result["return_code"] == 0:
        status = "success"
        user_msg = f"Hydra scan complete.\n{result['stdout']}"
    else:
        status = "failed"
        user_msg = f"Hydra scan failed. Error: {result['stderr']}"

    response_machine = {
        "status": status,
        "raw_cli_output": result["stdout"],
        "raw_cli_stderr": result["stderr"],
        "return_code": result["return_code"],
        "output_file_path": output_file,
    }

    outputs = {"machine_response": response_machine, "user_response": user_msg}
    log_tool_execution("hydra_bruteforce", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": user_msg}, indent=2)


@mcp.tool()
@resolve_references
async def john_crack(
    hash_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    format: Optional[str] = None,
    stdout_output: bool = False,  # New parameter for --stdout
    output_file: Optional[str] = None,  # New parameter for output file
    additional_args: str = "",
) -> str:
    """
    Cracks passwords using John the Ripper.
    """
    inputs = {
        "hash_file": hash_file,
        "wordlist": wordlist,
        "format": format,
        "stdout_output": stdout_output,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    cmd = ["john", hash_file]

    if wordlist:
        cmd.append(f"--wordlist={wordlist}")

    if format:
        cmd.append(f"--format={format}")

    if stdout_output:
        cmd.append("--stdout")

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    cracked_passwords = ""
    if result["return_code"] == 0:
        # John the Ripper prints cracked passwords to stdout
        cracked_passwords = result["stdout"]
        status = "success"
        user_msg = f"John the Ripper execution complete.\nCracked passwords:\n{cracked_passwords}"
    else:
        status = "failed"
        user_msg = f"John the Ripper execution failed. Error: {result['stderr']}"

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(cracked_passwords)
            logger.info(f"John the Ripper output saved to {output_file}")
        except Exception as e:
            logger.error(
                f"Failed to write John the Ripper output to {output_file}: {e}"
            )
            output_file = f"Error saving to file: {e}"

    response_machine = {
        "status": status,
        "cracked_passwords": cracked_passwords,
        "raw_cli_output": result["stdout"],
        "raw_cli_stderr": result["stderr"],
        "return_code": result["return_code"],
        "output_file_path": output_file,
    }

    outputs = {"machine_response": response_machine, "user_response": user_msg}
    log_tool_execution("john_crack", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": user_msg}, indent=2)


@mcp.tool()
@resolve_references
async def amass_scan(
    domain: str,
    output_file: Optional[str] = None,
    additional_args: str = "",
    timeout: int = 600,
) -> str:
    """
    Performs DNS enumeration and network mapping using Amass.
    MANDATORY: output_file verification ensures reliable results.
    """
    inputs = {
        "domain": domain,
        "output_file": output_file,
        "additional_args": additional_args,
        "timeout": timeout,
    }

    # Determine output file path - ALWAYS create explicit output file
    if output_file:
        output_path = output_file
    else:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            TOOL_LOG_DIR, f"amass_scan_{domain.replace('/', '_')}_{timestamp}.txt"
        )

    cmd = ["amass", "enum", "-d", domain, "-o", output_path]

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd, timeout=timeout)

    # MANDATORY VERIFICATION STEP - Principle: "Pas de sortie, pas de succès"
    verification = verify_output_file(
        output_path, expected_format="text", tool_name="amass_scan"
    )

    if not verification["success"]:
        error_msg = f"Amass scan failed output verification: {verification['error']}"
        response_machine = {
            "status": "failed",
            "error": error_msg,
            "raw_cli_output": result["stdout"],
            "stderr": result["stderr"],
            "verification_details": verification["details"],
        }
        response_user = f"Amass scan failed. {error_msg}"
        outputs = {"machine_response": response_machine, "user_response": response_user}
        log_tool_execution("amass_scan", inputs, outputs)
        return json.dumps(
            {"machine": response_machine, "user": response_user}, indent=2
        )

    amass_output_content = ""
    subdomains_found = []

    if os.path.exists(output_path):
        try:
            with open(output_path, "r") as f:
                amass_output_content = f.read()

            # Parse subdomains from output
            lines = amass_output_content.split("\n")
            for line in lines:
                line = line.strip()
                if line and "." in line and not line.startswith("#"):
                    subdomains_found.append(line)
        except Exception as e:
            logger.error(f"Failed to read Amass output file {output_path}: {e}")
            amass_output_content = f"Error reading output file: {e}"

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
            "output_file_content": amass_output_content,
            "subdomains_found": subdomains_found,
        }
        response_user = f"Amass scan failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "domain": domain,
            "raw_cli_output": result["stdout"],
            "output_file_path": output_path,
            "output_file_content": amass_output_content,
            "subdomains_found": subdomains_found,
        }
        user_summary = (
            f"Amass scan on {domain} complete. Results saved to {output_path}."
        )
        if subdomains_found:
            user_summary += f"\nFound {len(subdomains_found)} subdomains: " + ", ".join(
                subdomains_found[:10]
            )
            if len(subdomains_found) > 10:
                user_summary += "..."
        else:
            user_summary += "\nNo subdomains discovered."

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("amass_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def dnsrecon_scan(
    domain: str,
    output_file: Optional[str] = None,
    additional_args: str = "",
    timeout: int = 600,
) -> str:
    """
    Performs DNS reconnaissance using DNSRecon.
    Outputs results to a file (if specified) and logs execution.
    MANDATORY: output_file verification ensures reliable results.
    """
    inputs = {
        "domain": domain,
        "output_file": output_file,
        "additional_args": additional_args,
        "timeout": timeout,
    }

    # Determine output file path - ALWAYS create explicit output file
    if output_file:
        output_path = output_file
    else:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            TOOL_LOG_DIR, f"dnsrecon_scan_{domain.replace('/', '_')}_{timestamp}.json"
        )

    cmd = ["dnsrecon", "-d", domain, "-j", output_path]

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd, timeout=timeout)

    # MANDATORY VERIFICATION STEP - Principle: "Pas de sortie, pas de succès"
    verification = verify_output_file(
        output_path, expected_format="json", tool_name="dnsrecon_scan"
    )

    if not verification["success"]:
        error_msg = f"DNSRecon scan failed output verification: {verification['error']}"
        response_machine = {
            "status": "failed",
            "error": error_msg,
            "raw_cli_output": result["stdout"],
            "stderr": result["stderr"],
            "verification_details": verification["details"],
        }
        response_user = f"DNSRecon scan failed. {error_msg}"
        outputs = {"machine_response": response_machine, "user_response": response_user}
        log_tool_execution("dnsrecon_scan", inputs, outputs)
        return json.dumps(
            {"machine": response_machine, "user": response_user}, indent=2
        )

    dnsrecon_output_content = ""
    parsed_data = {}
    dns_records = []

    if os.path.exists(output_path):
        try:
            with open(output_path, "r") as f:
                dnsrecon_output_content = f.read()

            # Parse JSON output
            try:
                parsed_data = json.loads(dnsrecon_output_content)
                # Extract DNS records if present
                if isinstance(parsed_data, list):
                    dns_records = parsed_data
                elif isinstance(parsed_data, dict) and "records" in parsed_data:
                    dns_records = parsed_data["records"]
            except json.JSONDecodeError:
                logger.warning(
                    f"Could not parse DNSRecon JSON output from {output_path}"
                )

        except Exception as e:
            logger.error(f"Failed to read DNSRecon output file {output_path}: {e}")
            dnsrecon_output_content = f"Error reading output file: {e}"

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
            "output_file_content": dnsrecon_output_content,
            "dns_records": dns_records,
        }
        response_user = f"DNSRecon scan failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "domain": domain,
            "raw_cli_output": result["stdout"],
            "output_file_path": output_path,
            "output_file_content": dnsrecon_output_content,
            "parsed_data": parsed_data,
            "dns_records": dns_records,
        }
        user_summary = (
            f"DNSRecon scan on {domain} complete. Results saved to {output_path}."
        )
        if dns_records:
            record_types = set()
            for record in dns_records:
                if isinstance(record, dict) and "type" in record:
                    record_types.add(record["type"])
            if record_types:
                user_summary += (
                    f"\nFound DNS records of types: {', '.join(record_types)}"
                )
            user_summary += f"\nTotal DNS records: {len(dns_records)}"
        else:
            user_summary += "\nNo DNS records discovered."

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("dnsrecon_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def theharvester_scan(
    domain: str,
    source: str = "google",  # Default source
    output_format: str = "json",  # Default to JSON
    output_file: Optional[str] = None,
    additional_args: str = "",
    timeout: int = 600,
) -> str:
    """
    Gathers emails, subdomains, hosts, employee names, open ports and banners from different public sources.
    MANDATORY: output_file verification ensures reliable results.
    """
    inputs = {
        "domain": domain,
        "source": source,
        "output_format": output_format,
        "output_file": output_file,
        "additional_args": additional_args,
        "timeout": timeout,
    }

    # Determine output file path - ALWAYS create explicit output file
    if output_file:
        output_path = output_file
    else:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            TOOL_LOG_DIR,
            f"theharvester_scan_{domain.replace('/', '_')}_{timestamp}.{output_format}",
        )

    cmd = ["theharvester", "-d", domain, "-b", source, "-f", output_path]
    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd, timeout=timeout)

    # MANDATORY VERIFICATION STEP - Principle: "Pas de sortie, pas de succès"
    verification = verify_output_file(
        output_path, expected_format=output_format, tool_name="theharvester_scan"
    )

    if not verification["success"]:
        error_msg = (
            f"TheHarvester scan failed output verification: {verification['error']}"
        )
        response_machine = {
            "status": "failed",
            "error": error_msg,
            "raw_cli_output": result["stdout"],
            "stderr": result["stderr"],
            "verification_details": verification["details"],
        }
        response_user = f"TheHarvester scan failed. {error_msg}"
        outputs = {"machine_response": response_machine, "user_response": response_user}
        log_tool_execution("theharvester_scan", inputs, outputs)
        return json.dumps(
            {"machine": response_machine, "user": response_user}, indent=2
        )

    harvester_output_content = ""
    parsed_data = {}
    emails_found = []
    hosts_found = []

    if os.path.exists(output_path):
        try:
            with open(output_path, "r") as f:
                harvester_output_content = f.read()

            # Parse based on output format
            if output_format == "json":
                try:
                    parsed_data = json.loads(harvester_output_content)
                    if "emails" in parsed_data:
                        emails_found = parsed_data["emails"]
                    if "hosts" in parsed_data:
                        hosts_found = parsed_data["hosts"]
                except json.JSONDecodeError:
                    logger.warning(
                        f"Could not parse TheHarvester JSON output from {output_path}"
                    )
            else:
                # Text format parsing
                lines = harvester_output_content.split("\n")
                for line in lines:
                    line = line.strip()
                    if "@" in line and "." in line:
                        emails_found.append(line)
                    elif "." in line and not "@" in line and not line.startswith("*"):
                        hosts_found.append(line)

        except Exception as e:
            logger.error(f"Failed to read TheHarvester output file {output_path}: {e}")
            harvester_output_content = f"Error reading output file: {e}"

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
            "output_file_content": harvester_output_content,
            "emails_found": emails_found,
            "hosts_found": hosts_found,
        }
        response_user = f"TheHarvester scan failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "domain": domain,
            "source": source,
            "raw_cli_output": result["stdout"],
            "output_file_path": output_path,
            "output_file_content": harvester_output_content,
            "parsed_data": parsed_data,
            "emails_found": emails_found,
            "hosts_found": hosts_found,
        }
        user_summary = f"TheHarvester scan on {domain} using {source} complete. Results saved to {output_path}."
        if emails_found:
            user_summary += f"\nFound {len(emails_found)} emails: " + ", ".join(
                emails_found[:5]
            )
            if len(emails_found) > 5:
                user_summary += "..."
        if hosts_found:
            user_summary += f"\nFound {len(hosts_found)} hosts: " + ", ".join(
                hosts_found[:5]
            )
            if len(hosts_found) > 5:
                user_summary += "..."
        if not emails_found and not hosts_found:
            user_summary += "\nNo emails or hosts discovered."

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("theharvester_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def wpscan_audit(
    url: str,
    output_file: Optional[str] = None,
    additional_args: str = "",
    timeout: int = 900,
) -> str:
    """
    Audits a WordPress site for vulnerabilities using WPScan.
    Requires a wpscan API token to be configured for vulnerability detection.
    Outputs results in JSON format and logs execution.
    MANDATORY: output_file verification ensures reliable results.
    """
    inputs = {
        "url": url,
        "output_file": output_file,
        "additional_args": additional_args,
        "timeout": timeout,
    }

    # Determine output file path - ALWAYS create explicit output file
    if output_file:
        output_path = output_file
    else:
        # Generate a unique filename for the WPScan output
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            TOOL_LOG_DIR,
            f"wpscan_audit_{url.replace('https://', '').replace('http://', '').replace('/', '_')}_{timestamp}.json",
        )

    cmd = [
        "wpscan",
        "--url",
        url,
        "--format",
        "json",
        "--output",
        output_path,
        "--disable-tls-checks",
    ]
    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd, timeout=timeout)  # Execute WPScan

    # MANDATORY VERIFICATION STEP - Principle: "Pas de sortie, pas de succès"
    verification = verify_output_file(
        output_path, expected_format="json", tool_name="wpscan_audit"
    )

    if not verification["success"]:
        error_msg = f"WPScan audit failed output verification: {verification['error']}"
        response_machine = {
            "status": "failed",
            "error": error_msg,
            "raw_cli_output": result["stdout"],
            "stderr": result["stderr"],
            "verification_details": verification["details"],
        }
        response_user = f"WPScan audit failed. {error_msg}"
        outputs = {"machine_response": response_machine, "user_response": response_user}
        log_tool_execution("wpscan_audit", inputs, outputs)
        return json.dumps(
            {"machine": response_machine, "user": response_user}, indent=2
        )

    scan_data = {}
    if os.path.exists(output_path):
        try:
            with open(output_path, "r") as f:
                scan_data = json.load(f)
            # Do not remove output_path here, as it's now part of the persistent logging
        except (IOError, json.JSONDecodeError) as e:
            logger.error(
                f"Failed to read or parse WPScan output file {output_path}: {e}"
            )
            scan_data = {"error": f"Failed to read or parse output: {e}"}

    if result["return_code"] != 0 and not scan_data.get(
        "error"
    ):  # Check CLI return code and if scan_data has an error
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
            "output_file_path": output_path,
            "scan_data": scan_data,
        }
        response_user = f"WPScan audit failed. Error: {result['stderr']}"
    else:
        # Summarize findings
        vulns = []
        if "interesting_findings" in scan_data:
            vulns.extend([f["to_s"] for f in scan_data["interesting_findings"]])

        main_vulns = scan_data.get("version", {}).get("vulnerabilities", [])
        if main_vulns:
            vulns.extend([f["title"] for f in main_vulns])

        response_machine = {
            "status": "success",
            "target": url,
            "vulnerabilities_summary": vulns,
            "raw_cli_output": result["stdout"],
            "output_file_path": output_path,
            "scan_data": scan_data,
        }
        response_user = f"WPScan audit on {url} complete. Results saved to {output_path}. Found {len(vulns)} potential items of interest."

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("wpscan_audit", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def enum4linux_scan(
    target: str,
    additional_args: str = "-a",  # Default to all enumeration
) -> str:
    """
    Enumerates information from Windows and Samba systems using enum4linux.
    Parses stdout for structured information and logs execution.
    """
    inputs = {"target": target, "additional_args": additional_args}

    cmd = ["enum4linux"]
    if additional_args:
        cmd.extend(shlex.split(additional_args))
    cmd.append(target)
    result = run_command(cmd)

    parsed_data = {
        "users": [],
        "groups": [],
        "shares": [],
        "printers": [],
        "os_info": [],
        "raw_output_lines": result["stdout"].split("\n"),
    }

    # Improved parsing of enum4linux stdout
    current_section = None
    for line in result["stdout"].split("\n"):
        line = line.strip()
        if not line:
            continue

        if "Users on" in line:
            current_section = "users"
        elif "Groups on" in line:
            current_section = "groups"
        elif "Share enumeration" in line:
            current_section = "shares"
        elif "Printer enumeration" in line:
            current_section = "printers"
        elif "OS information" in line:
            current_section = "os_info"
        elif "enum4linux" in line or "Nbtscan" in line or "smbclient" in line:
            # Skip tool headers
            continue
        elif current_section:
            if current_section == "users" and ("user:" in line or "rid:" in line):
                parsed_data["users"].append(line)
            elif current_section == "groups" and ("group:" in line or "rid:" in line):
                parsed_data["groups"].append(line)
            elif current_section == "shares" and (
                "sharename" in line or "Disk" in line
            ):
                parsed_data["shares"].append(line)
            elif current_section == "printers" and ("Printer" in line):
                parsed_data["printers"].append(line)
            elif current_section == "os_info" and (":" in line):
                parsed_data["os_info"].append(line)

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
            "parsed_data": parsed_data,
        }
        response_user = f"Enum4linux scan failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "target": target,
            "raw_cli_output": result["stdout"],
            "parsed_data": parsed_data,
        }
        user_summary = f"Enum4linux scan on {target} complete."
        if parsed_data["users"]:
            user_summary += f"\nFound {len(parsed_data['users'])} users."
        if parsed_data["groups"]:
            user_summary += f"\nFound {len(parsed_data['groups'])} groups."
        if parsed_data["shares"]:
            user_summary += f"\nFound {len(parsed_data['shares'])} shares."
        if parsed_data["os_info"]:
            user_summary += f"\nOS Information: {'; '.join(parsed_data['os_info'][:3])}{'...' if len(parsed_data['os_info']) > 3 else ''}."
        if not any(parsed_data.values()):
            user_summary += "\nNo significant information enumerated."

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("enum4linux_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def aircrack_ng_suite(
    command: str,
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Executes a command from the Aircrack-ng suite.
    Outputs results to a file (if specified) and logs execution.
    """
    inputs = {
        "command": command,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    cmd = shlex.split(command)

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    aircrack_results = result["stdout"]

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(aircrack_results)
            logger.info(f"Aircrack-ng results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to write Aircrack-ng output to {output_file}: {e}")
            output_file = f"Error saving to file: {e}"

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"Aircrack-ng command failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "command": command,
            "results": aircrack_results,
            "output_file_path": output_file,
        }
        user_summary = f"Aircrack-ng command '{command}' complete."
        if aircrack_results:
            user_summary += f"\nResults:\n{aircrack_results}"
        else:
            user_summary += "\nNo results."
        if output_file:
            user_summary += f"\nResults also saved to: {output_file}"

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("aircrack_ng_suite", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def tshark_capture(
    interface: str,
    duration: int,
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Captures network traffic using TShark.
    Outputs results to a file (if specified) and logs execution.
    """
    inputs = {
        "interface": interface,
        "duration": duration,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    cmd = ["tshark", "-i", interface, "-a", f"duration:{duration}"]

    if output_file:
        cmd.extend(["-w", output_file])

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    tshark_results = result["stdout"]

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"TShark capture failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "interface": interface,
            "duration": duration,
            "results": tshark_results,
            "output_file_path": output_file,
        }
        user_summary = f"TShark capture on interface '{interface}' for {duration} seconds complete."
        if not output_file:
            if tshark_results:
                user_summary += f"\nResults:\n{tshark_results}"
            else:
                user_summary += "\nNo packets captured."
        else:
            user_summary += f"\nCapture saved to: {output_file}"

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("tshark_capture", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def bettercap_scan(
    modules: str,
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Runs Bettercap with a specified set of modules.
    Outputs results to a file (if specified) and logs execution.
    """
    inputs = {
        "modules": modules,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    cmd = ["bettercap", "-eval", modules]

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    bettercap_results = result["stdout"]

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(bettercap_results)
            logger.info(f"Bettercap results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to write Bettercap output to {output_file}: {e}")
            output_file = f"Error saving to file: {e}"

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"Bettercap scan failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "modules": modules,
            "results": bettercap_results,
            "output_file_path": output_file,
        }
        user_summary = f"Bettercap scan with modules '{modules}' complete."
        if bettercap_results:
            user_summary += f"\nResults:\n{bettercap_results}"
        else:
            user_summary += "\nNo results."
        if output_file:
            user_summary += f"\nResults also saved to: {output_file}"

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("bettercap_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def wfuzz_scan(
    url: str,
    wordlist: str,
    sc: list[str] = None,
    payload: str = "FUZZ",
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Fuzzes a web application using Wfuzz.
    Outputs results to a file (if specified) and logs execution.
    """
    inputs = {
        "url": url,
        "wordlist": wordlist,
        "sc": sc,
        "payload": payload,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    cmd = ["wfuzz", "-w", wordlist]

    if sc:
        cmd.extend(["--sc", ",".join(sc)])

    cmd.extend(["-z", f"file,{wordlist}", url.replace("FUZZ", payload)])

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    wfuzz_results = result["stdout"]

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(wfuzz_results)
            logger.info(f"Wfuzz results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to write Wfuzz output to {output_file}: {e}")
            output_file = f"Error saving to file: {e}"

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"Wfuzz scan failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "url": url,
            "results": wfuzz_results,
            "output_file_path": output_file,
        }
        user_summary = f"Wfuzz scan for '{url}' complete."
        if wfuzz_results:
            user_summary += f"\nResults:\n{wfuzz_results}"
        else:
            user_summary += "\nNo results."
        if output_file:
            user_summary += f"\nResults also saved to: {output_file}"

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("wfuzz_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def whatweb_scan(
    target: str,
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Identifies technologies used by a website using WhatWeb.
    Outputs results to a file (if specified) and logs execution.
    """
    inputs = {
        "target": target,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    cmd = ["whatweb", target]

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    whatweb_results = result["stdout"]

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(whatweb_results)
            logger.info(f"WhatWeb results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to write WhatWeb output to {output_file}: {e}")
            output_file = f"Error saving to file: {e}"

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"WhatWeb scan failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "target": target,
            "results": whatweb_results,
            "output_file_path": output_file,
        }
        user_summary = f"WhatWeb scan for '{target}' complete."
        if whatweb_results:
            user_summary += f"\nResults:\n{whatweb_results}"
        else:
            user_summary += "\nNo technologies identified."
        if output_file:
            user_summary += f"\nResults also saved to: {output_file}"

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("whatweb_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def secure_browser_launcher(
    url: str,
    use_tor: bool = False,
    use_proxychains: bool = False,
    user_agent: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Launches a secure browser with options for Tor, proxychains, and a custom user-agent.
    """
    inputs = {
        "url": url,
        "use_tor": use_tor,
        "use_proxychains": use_proxychains,
        "user_agent": user_agent,
        "additional_args": additional_args,
    }

    cmd = []
    if use_tor:
        cmd.append("torsocks")
    elif use_proxychains:
        cmd.append("proxychains")

    cmd.append("chromium-browser")
    cmd.append("--incognito")

    if user_agent:
        cmd.append(f"--user-agent='{user_agent}'")
    else:
        # Use a random common user-agent
        common_user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
        ]
        import random

        cmd.append(f"--user-agent='{random.choice(common_user_agents)}'")

    cmd.append(url)

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    # We run the browser in the background as it's a GUI application
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    response_machine = {
        "status": "success",
        "pid": process.pid,
    }
    response_user = f"Secure browser launched with PID: {process.pid}"

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("secure_browser_launcher", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def torsocks_command(
    command: str,
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Runs a command through torsocks.
    Outputs results to a file (if specified) and logs execution.
    """
    inputs = {
        "command": command,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    cmd = ["torsocks"]
    cmd.extend(shlex.split(command))

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    torsocks_results = result["stdout"]

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(torsocks_results)
            logger.info(f"Torsocks results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to write Torsocks output to {output_file}: {e}")
            output_file = f"Error saving to file: {e}"

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"Torsocks command failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "command": command,
            "results": torsocks_results,
            "output_file_path": output_file,
        }
        user_summary = f"Torsocks command '{command}' complete."
        if torsocks_results:
            user_summary += f"\nResults:\n{torsocks_results}"
        else:
            user_summary += "\nNo results."
        if output_file:
            user_summary += f"\nResults also saved to: {output_file}"

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("torsocks_command", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def tor_service(
    action: str,
) -> str:
    """
    Manages the Tor service.
    """
    inputs = {"action": action}

    if action not in ["start", "stop", "status"]:
        response_user = (
            "Invalid action. Please choose between 'start', 'stop', and 'status'."
        )
        response_machine = {"status": "failed", "error": response_user}
        outputs = {"machine_response": response_machine, "user_response": response_user}
        log_tool_execution("tor_service", inputs, outputs)
        return json.dumps(
            {"machine": response_machine, "user": response_user}, indent=2
        )

    cmd = ["service", "tor", action]
    result = run_command(cmd)

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"Tor service command failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "action": action,
            "results": result["stdout"],
        }
        response_user = f"Tor service {action} command executed successfully."

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("tor_service", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def proxychains_command(
    command: str,
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Runs a command through proxychains.
    Outputs results to a file (if specified) and logs execution.
    """
    inputs = {
        "command": command,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    cmd = ["proxychains"]
    cmd.extend(shlex.split(command))

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    proxychains_results = result["stdout"]

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(proxychains_results)
            logger.info(f"Proxychains results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to write Proxychains output to {output_file}: {e}")
            output_file = f"Error saving to file: {e}"

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"Proxychains command failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "command": command,
            "results": proxychains_results,
            "output_file_path": output_file,
        }
        user_summary = f"Proxychains command '{command}' complete."
        if proxychains_results:
            user_summary += f"\nResults:\n{proxychains_results}"
        else:
            user_summary += "\nNo results."
        if output_file:
            user_summary += f"\nResults also saved to: {output_file}"

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("proxychains_command", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
async def set_privacy_level(level: int) -> str:
    """
    Sets the privacy level for the MCP.

    - Level 1 (Cameleon): Basic protection. Changes MAC address and browser user-agent.
    - Level 2 (Zombie): Intermediate protection. Routes traffic through proxies.
    - Level 3 (Ghost): Maximum protection. Routes traffic through the Tor network.
    """
    inputs = {"level": level}

    if level == 1:
        response_user = "Privacy level set to 1 (Cameleon). Use `macchanger_spoof` to change your MAC address and `secure_browser_launcher` for a secure browser."
    elif level == 2:
        response_user = "Privacy level set to 2 (Zombie). Use `proxychains_command` to run commands through a proxy chain. Configure your proxychains before using it."
    elif level == 3:
        response_user = "Privacy level set to 3 (Ghost). Use `tor_service` to start the Tor service and `torsocks_command` to run commands through Tor."
    else:
        response_user = "Invalid privacy level. Please choose between 1, 2, and 3."

    response_machine = {"status": "success", "level": level}
    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("set_privacy_level", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def macchanger_spoof(
    interface: str,
    new_mac: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Spoofs the MAC address of a network interface using macchanger.
    """
    inputs = {
        "interface": interface,
        "new_mac": new_mac,
        "additional_args": additional_args,
    }

    # First, we need to bring the interface down
    run_command(["sudo", "ifconfig", interface, "down"])

    cmd = ["sudo", "macchanger"]

    if new_mac:
        cmd.extend(["-m", new_mac, interface])
    else:
        cmd.extend(["-r", interface])  # Set a random MAC address

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    # Finally, bring the interface up
    run_command(["sudo", "ifconfig", interface, "up"])

    macchanger_results = result["stdout"]

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"Macchanger command failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "interface": interface,
            "results": macchanger_results,
        }
        user_summary = f"Macchanger command on '{interface}' complete."
        if macchanger_results:
            user_summary += f"\nResults:\n{macchanger_results}"
        else:
            user_summary += "\nNo results."

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("macchanger_spoof", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def kismet_start_server(
    interface: str,
    output_file_prefix: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Starts the Kismet server in the background.
    """
    inputs = {
        "interface": interface,
        "output_file_prefix": output_file_prefix,
        "additional_args": additional_args,
    }

    cmd = ["sudo", "kismet", "-c", interface]

    if output_file_prefix:
        cmd.extend(["--log-prefix", output_file_prefix])

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    # Run Kismet in the background
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    response_machine = {
        "status": "success",
        "pid": process.pid,
    }
    response_user = f"Kismet server started with PID: {process.pid}"

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("kismet_start_server", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def reaver_scan(
    bssid: str,
    interface: str,
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Runs a Reaver scan.
    Outputs results to a file (if specified) and logs execution.
    """
    inputs = {
        "bssid": bssid,
        "interface": interface,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    cmd = ["sudo", "reaver", "-i", interface, "-b", bssid, "-vv"]

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    reaver_results = result["stdout"]

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(reaver_results)
            logger.info(f"Reaver results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to write Reaver output to {output_file}: {e}")
            output_file = f"Error saving to file: {e}"

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"Reaver scan failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "bssid": bssid,
            "results": reaver_results,
            "output_file_path": output_file,
        }
        user_summary = f"Reaver scan on '{bssid}' complete."
        if reaver_results:
            user_summary += f"\nResults:\n{reaver_results}"
        else:
            user_summary += "\nNo results."
        if output_file:
            user_summary += f"\nResults also saved to: {output_file}"

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("reaver_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def pixiewps_scan(
    bssid: str,
    pke: str,
    pkr: str,
    e_hash1: str,
    e_hash2: str,
    authkey: str,
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Runs a PixieWPS scan.
    Outputs results to a file (if specified) and logs execution.
    """
    inputs = {
        "bssid": bssid,
        "pke": pke,
        "pkr": pkr,
        "e_hash1": e_hash1,
        "e_hash2": e_hash2,
        "authkey": authkey,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    cmd = [
        "sudo",
        "pixiewps",
        "-b",
        bssid,
        "-p",
        pke,
        "-r",
        pkr,
        "-s",
        e_hash1,
        "-z",
        e_hash2,
        "-a",
        authkey,
    ]

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    pixiewps_results = result["stdout"]

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(pixiewps_results)
            logger.info(f"PixieWPS results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to write PixieWPS output to {output_file}: {e}")
            output_file = f"Error saving to file: {e}"

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"PixieWPS scan failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "bssid": bssid,
            "results": pixiewps_results,
            "output_file_path": output_file,
        }
        user_summary = f"PixieWPS scan on '{bssid}' complete."
        if pixiewps_results:
            user_summary += f"\nResults:\n{pixiewps_results}"
        else:
            user_summary += "\nNo results."
        if output_file:
            user_summary += f"\nResults also saved to: {output_file}"

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("pixiewps_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def legion_scan(
    target: str,
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Runs a Legion scan on a target.
    Outputs results to a file (if specified) and logs execution.
    """
    inputs = {
        "target": target,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    cmd = ["sudo", "legion", target]

    if output_file:
        cmd.extend(["-o", output_file])

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    legion_results = result["stdout"]

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"Legion scan failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "target": target,
            "results": legion_results,
            "output_file_path": output_file,
        }
        user_summary = f"Legion scan on '{target}' complete."
        if legion_results:
            user_summary += f"\nResults:\n{legion_results}"
        else:
            user_summary += "\nNo results."
        if output_file:
            user_summary += f"\nResults also saved to: {output_file}"

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("legion_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def spiderfoot_scan(
    target: str,
    modules: str,
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Runs an OSINT scan using SpiderFoot.
    Outputs results to a file (if specified) and logs execution.
    """
    inputs = {
        "target": target,
        "modules": modules,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    cmd = ["spiderfoot", "-s", target, "-m", modules]

    if output_file:
        cmd.extend(["-o", output_file])

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    spiderfoot_results = result["stdout"]

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"SpiderFoot scan failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "target": target,
            "modules": modules,
            "results": spiderfoot_results,
            "output_file_path": output_file,
        }
        user_summary = (
            f"SpiderFoot scan on '{target}' with modules '{modules}' complete."
        )
        if spiderfoot_results:
            user_summary += f"\nResults:\n{spiderfoot_results}"
        else:
            user_summary += "\nNo results."
        if output_file:
            user_summary += f"\nResults also saved to: {output_file}"

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("spiderfoot_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def dnsrecon_scan(
    domain: str,
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Performs DNS reconnaissance using DNSRecon.
    Outputs results to a file (if specified) and logs execution.
    """
    inputs = {
        "domain": domain,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    cmd = ["dnsrecon", "-d", domain]

    if output_file:
        cmd.extend(["-j", output_file])

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    dnsrecon_results = result["stdout"]

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"DNSRecon scan failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "domain": domain,
            "results": dnsrecon_results,
            "output_file_path": output_file,
        }
        user_summary = f"DNSRecon scan for '{domain}' complete."
        if output_file and os.path.exists(output_file):
            with open(output_file, "r") as f:
                results = f.read()
            user_summary += f"\nResults:\n{results}"
        elif dnsrecon_results:
            user_summary += f"\nResults:\n{dnsrecon_results}"
        else:
            user_summary += "\nNo results."
        if output_file:
            user_summary += f"\nResults also saved to: {output_file}"

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("dnsrecon_scan", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def empire_shell(
    commands: List[str],
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Executes a list of commands within the Empire client.
    Useful for running modules, interacting with agents, etc.
    Logs execution and captures output.
    """
    inputs = {
        "commands": commands,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    rc_script_content = ""
    for cmd_line in commands:
        rc_script_content += f"{cmd_line}\n"
    rc_script_content += "exit\n"  # Ensure empire exits

    rc_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".rc", dir=TOOL_LOG_DIR
        ) as rc_file:
            rc_file.write(rc_script_content)
            rc_path = rc_file.name

        cmd = ["empire", "--resource", rc_path]
        if additional_args:
            cmd.extend(shlex.split(additional_args))

        result = run_command(cmd)

        empire_output = result["stdout"]

        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(empire_output)
                logger.info(f"Empire output saved to {output_file}")
            except Exception as e:
                logger.error(f"Failed to write Empire output to {output_file}: {e}")
                output_file = f"Error saving to file: {e}"

        if result["return_code"] != 0:
            response_machine = {
                "status": "failed",
                "error": result["stderr"],
                "raw_cli_output": result["stdout"],
                "rc_script_path": rc_path,
            }
            response_user = (
                f"Empire command execution failed. Error: {result['stderr']}"
            )
        else:
            response_machine = {
                "status": "success",
                "raw_cli_output": result["stdout"],
                "raw_cli_stderr": result["stderr"],
                "rc_script_path": rc_path,
                "output_file_path": output_file,
            }
            response_user = f"Empire commands executed. Output:\n{result['stdout']}"
            if output_file:
                response_user += f"\nOutput also saved to: {output_file}"

    except Exception as e:
        response_machine = {"status": "failed", "error": str(e)}
        response_user = f"An error occurred while trying to run Empire: {e}"
    finally:
        if rc_path and os.path.exists(rc_path):
            os.remove(rc_path)

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("empire_shell", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def evil_winrm_shell(
    ip: str,
    user: str,
    password: Optional[str] = None,
    command: Optional[str] = None,
    script: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Connects to a Windows machine using Evil-WinRM and executes commands.
    """
    inputs = {
        "ip": ip,
        "user": user,
        "password": password,
        "command": command,
        "script": script,
        "additional_args": additional_args,
    }

    cmd = ["evil-winrm", "-i", ip, "-u", user]

    if password:
        cmd.extend(["-p", password])

    if command:
        cmd.extend(["-c", command])

    if script:
        cmd.extend(["-s", script])

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    evil_winrm_results = result["stdout"]

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"Evil-WinRM command failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "ip": ip,
            "user": user,
            "results": evil_winrm_results,
        }
        user_summary = f"Evil-WinRM command on '{ip}' as user '{user}' complete."
        if evil_winrm_results:
            user_summary += f"\nResults:\n{evil_winrm_results}"
        else:
            user_summary += "\nNo results."

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("evil_winrm_shell", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def hashcat_crack(
    hash_file: str,
    wordlist: str,
    hash_type: str,
    attack_mode: str = "0",
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Cracks password hashes using Hashcat.
    Can output cracked passwords to a file, and logs execution.
    """
    inputs = {
        "hash_file": hash_file,
        "wordlist": wordlist,
        "hash_type": hash_type,
        "attack_mode": attack_mode,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    cmd = ["hashcat", "-m", hash_type, "-a", attack_mode, hash_file, wordlist]

    if output_file:
        cmd.extend(["-o", output_file])

    if additional_args:
        cmd.extend(shlex.split(additional_args))

    result = run_command(cmd)

    hashcat_results = result["stdout"]

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
        }
        response_user = f"Hashcat crack failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "hash_file": hash_file,
            "results": hashcat_results,
            "output_file_path": output_file,
        }
        user_summary = f"Hashcat crack for '{hash_file}' complete."
        if output_file and os.path.exists(output_file):
            with open(output_file, "r") as f:
                cracked_passwords = f.read()
            user_summary += f"\nCracked passwords:\n{cracked_passwords}"
        elif hashcat_results:
            user_summary += f"\nResults:\n{hashcat_results}"
        else:
            user_summary += "\nNo hashes cracked."
        if output_file:
            user_summary += f"\nResults also saved to: {output_file}"

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("hashcat_crack", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def searchsploit_search(
    query: str,
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Searches for exploits in the Exploit-DB database using SearchSploit.
    Outputs results to a file (if specified) and logs execution.
    MANDATORY: output_file verification ensures reliable results when output_file is specified.
    """
    inputs = {
        "query": query,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    # Determine output file path if specified
    output_path = None
    if output_file:
        output_path = output_file
    else:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(
            TOOL_LOG_DIR,
            f"searchsploit_search_{query.replace(' ', '_')}_{timestamp}.json",
        )

    cmd = ["searchsploit"]
    cmd.extend(shlex.split(query))

    # Add JSON output if specified
    if additional_args and "-j" in additional_args:
        cmd.extend(shlex.split(additional_args))
        expected_format = "json"
    elif additional_args:
        cmd.extend(shlex.split(additional_args))
        expected_format = "text"
    else:
        expected_format = "text"

    result = run_command(cmd)

    # Save output to file if specified
    searchsploit_output_content = result["stdout"]
    exploits_found = []

    if output_file or (additional_args and "-j" in additional_args):
        try:
            with open(output_path, "w") as f:
                f.write(searchsploit_output_content)
            logger.info(f"SearchSploit results saved to {output_path}")

            # MANDATORY VERIFICATION STEP if output file was created
            verification = verify_output_file(
                output_path,
                expected_format=expected_format,
                tool_name="searchsploit_search",
            )

            if not verification["success"]:
                error_msg = f"SearchSploit search failed output verification: {verification['error']}"
                response_machine = {
                    "status": "failed",
                    "error": error_msg,
                    "raw_cli_output": result["stdout"],
                    "stderr": result["stderr"],
                    "verification_details": verification["details"],
                }
                response_user = f"SearchSploit search failed. {error_msg}"
                outputs = {
                    "machine_response": response_machine,
                    "user_response": response_user,
                }
                log_tool_execution("searchsploit_search", inputs, outputs)
                return json.dumps(
                    {"machine": response_machine, "user": response_user}, indent=2
                )

        except Exception as e:
            logger.error(f"Failed to write SearchSploit output to {output_path}: {e}")
            output_path = f"Error saving to file: {e}"

    # Parse exploits from output
    if searchsploit_output_content:
        lines = searchsploit_output_content.split("\n")
        for line in lines:
            line = line.strip()
            if (
                line
                and not line.startswith("-")
                and not line.startswith("Exploit")
                and "|" in line
            ):
                exploits_found.append(line)

    if result["return_code"] != 0:
        response_machine = {
            "status": "failed",
            "error": result["stderr"],
            "raw_cli_output": result["stdout"],
            "output_file_content": searchsploit_output_content,
            "exploits_found": exploits_found,
        }
        response_user = f"SearchSploit search failed. Error: {result['stderr']}"
    else:
        response_machine = {
            "status": "success",
            "query": query,
            "raw_cli_output": result["stdout"],
            "output_file_path": output_path,
            "output_file_content": searchsploit_output_content,
            "exploits_found": exploits_found,
        }
        user_summary = f"SearchSploit search for '{query}' complete."
        if output_path:
            user_summary += f" Results saved to {output_path}."
        if exploits_found:
            user_summary += (
                f"\nFound {len(exploits_found)} potential exploits:\n"
                + "\n".join(exploits_found[:5])
            )
            if len(exploits_found) > 5:
                user_summary += "\n..."
        else:
            user_summary += "\nNo exploits found."
        if output_file:
            user_summary += f"\nResults also saved to: {output_file}"

        response_user = user_summary

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("searchsploit_search", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def create_set_attack(
    attack_type: str,
    target_url: str,
    output_file: Optional[str] = None,
    additional_args: str = "",
) -> str:
    """
    Creates and launches a Social-Engineer Toolkit (SET) attack.
    Currently supports 'credential_harvester'.
    """
    inputs = {
        "attack_type": attack_type,
        "target_url": target_url,
        "output_file": output_file,
        "additional_args": additional_args,
    }

    if attack_type != "credential_harvester":
        response_user = (
            "Invalid attack type. Currently only 'credential_harvester' is supported."
        )
        response_machine = {"status": "failed", "error": response_user}
        outputs = {"machine_response": response_machine, "user_response": response_user}
        log_tool_execution("create_set_attack", inputs, outputs)
        return json.dumps(
            {"machine": response_machine, "user": response_user}, indent=2
        )

    # Generate the SET resource file
    rc_content = f"1\n2\n3\n2\n{target_url}\n"  # 1) Social-Engineering Attacks -> 2) Website Attack Vectors -> 3) Credential Harvester Attack -> 2) Site Cloner
    rc_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".rc", dir=TOOL_LOG_DIR
        ) as rc_file:
            rc_file.write(rc_content)
            rc_path = rc_file.name

        cmd = ["sudo", "setoolkit", "-rc", rc_path]
        if additional_args:
            cmd.extend(shlex.split(additional_args))

        result = run_command(cmd)

        set_output = result["stdout"]

        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(set_output)
                logger.info(f"SET output saved to {output_file}")
            except Exception as e:
                logger.error(f"Failed to write SET output to {output_file}: {e}")
                output_file = f"Error saving to file: {e}"

        if result["return_code"] != 0:
            response_machine = {
                "status": "failed",
                "error": result["stderr"],
                "raw_cli_output": result["stdout"],
                "rc_script_path": rc_path,
            }
            response_user = f"SET attack failed. Error: {result['stderr']}"
        else:
            response_machine = {
                "status": "success",
                "raw_cli_output": result["stdout"],
                "raw_cli_stderr": result["stderr"],
                "rc_script_path": rc_path,
                "output_file_path": output_file,
            }
            response_user = f"SET attack launched. Output:\n{result['stdout']}"
            if output_file:
                response_user += f"\nOutput also saved to: {output_file}"

    except Exception as e:
        response_machine = {"status": "failed", "error": str(e)}
        response_user = f"An error occurred while trying to run SET: {e}"
    finally:
        if rc_path and os.path.exists(rc_path):
            os.remove(rc_path)

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("create_set_attack", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def generate_report(
    output_file: str,
) -> str:
    """
    Generates a Markdown report from the tool logs.
    """
    inputs = {"output_file": output_file}

    report_content = "# MCP Pentest Report\n\n"
    report_content += "## Executive Summary\n\n"
    report_content += "This report summarizes the findings of a penetration test conducted using the MCP.\n\n"
    report_content += "## Tools Executed\n\n"

    log_files = [f for f in os.listdir(TOOL_LOG_DIR) if f.endswith(".json")]
    log_files.sort()

    for log_file in log_files:
        with open(os.path.join(TOOL_LOG_DIR, log_file), "r") as f:
            log_data = json.load(f)

        tool_name = log_data.get("tool_name", "Unknown Tool")
        timestamp = log_data.get("timestamp", "Unknown Timestamp")
        inputs = log_data.get("inputs", {})
        outputs = log_data.get("outputs", {})

        report_content += f"### {tool_name} ({timestamp})\n\n"
        report_content += "**Inputs:**\n"
        report_content += "```json\n"
        report_content += json.dumps(inputs, indent=2)
        report_content += "\n```\n\n"

        report_content += "**Outputs:**\n"
        report_content += "```json\n"
        report_content += json.dumps(outputs, indent=2)
        report_content += "\n```\n\n"

    try:
        with open(output_file, "w") as f:
            f.write(report_content)
        response_user = f"Report generated successfully and saved to {output_file}"
        response_machine = {"status": "success", "output_file": output_file}
    except Exception as e:
        response_user = f"Failed to generate report: {e}"
        response_machine = {"status": "failed", "error": str(e)}

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("generate_report", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)


@mcp.tool()
@resolve_references
async def advanced_lfi_scan(
    url: str,
    payloads_file: Optional[str] = None,
    output_file: Optional[str] = None,
    additional_args: str = "",
    timeout: int = 600,
) -> str:
    """
    Advanced LFI scanning with URL encoding bypass techniques.
    Tests for Local File Inclusion vulnerabilities using various encoding methods.
    """
    inputs = {
        "url": url,
        "payloads_file": payloads_file,
        "output_file": output_file,
        "additional_args": additional_args,
        "timeout": timeout,
    }

    # Advanced LFI payloads with multiple encoding techniques
    lfi_payloads = [
        # Standard traversal
        "../../../../../../../../etc/passwd",
        "../../../../../../../../windows/system32/drivers/etc/hosts",
-e 

if __name__ == "__main__":
    import sys
    print(f"Arguments received: {sys.argv}")
    logger.info("Initializing Kali MCP Server v2")
    logger.info("Starting Kali MCP Server with stdio transport")
    try:
        mcp.run(transport="stdio")
    except Exception as e:
        logger.error(f"Failed to start MCP server: {e}")
        raise
