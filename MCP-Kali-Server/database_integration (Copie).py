#!/usr/bin/env python3

import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Tuple
import logging
from pathlib import Path
import ipaddress

from database_manager import get_db_manager

logger = logging.getLogger(__name__)


class DatabaseIntegration:
    """
    Intégration de la base de données avec les outils de scan MCP.
    Permet de parser et stocker automatiquement les résultats de tous les outils.
    """

    def __init__(self):
        self.db = get_db_manager()
        self.current_session_id = None

    def set_session(self, session_id: str):
        """Define the current session for all subsequent operations"""
        self.current_session_id = session_id
        logger.info(f"Database integration session set to: {session_id}")

    def store_scan_with_parsing(
        self,
        tool_name: str,
        target: str,
        command: str,
        raw_output: str,
        output_file: str = None,
        execution_time: float = None,
        scan_type: str = None,
    ) -> Dict[str, Any]:
        """
        Store scan result and automatically parse/structure the data
        Returns summary of what was stored
        """
        if not self.current_session_id:
            logger.error("No session set for database integration")
            return {"error": "No session set"}

        try:
            # Store the raw scan result
            scan_id = self.db.store_scan_result(
                session_id=self.current_session_id,
                tool_name=tool_name,
                target=target,
                scan_type=scan_type,
                command=command,
                raw_output=raw_output,
                parsed_results=None,  # Will be updated after parsing
                output_file=output_file,
                execution_time=execution_time,
            )

            if scan_id == -1:
                return {"error": "Failed to store scan result"}

            # Parse and store structured data based on tool type
            parsing_results = self._parse_and_store_by_tool(
                tool_name, target, raw_output, output_file, scan_id
            )

            # Update the scan result with parsed data
            if parsing_results.get("parsed_data"):
                conn = self.db.db_manager if hasattr(self.db, "db_manager") else None
                # Update parsed_results in scan_results table
                # This is a simplified approach - in production you'd want to update the record

            return {
                "scan_id": scan_id,
                "parsing_results": parsing_results,
                "session_id": self.current_session_id,
            }

        except Exception as e:
            logger.error(f"Error in store_scan_with_parsing: {e}")
            return {"error": str(e)}

    def _parse_and_store_by_tool(
        self,
        tool_name: str,
        target: str,
        raw_output: str,
        output_file: str,
        scan_id: int,
    ) -> Dict[str, Any]:
        """Parse results based on tool type and store structured data"""

        parsing_map = {
            "nmap_scan": self._parse_nmap_results,
            "gobuster_scan": self._parse_gobuster_results,
            "dirb_scan": self._parse_dirb_results,
            "nikto_scan": self._parse_nikto_results,
            "sqlmap_scan": self._parse_sqlmap_results,
            "amass_scan": self._parse_amass_results,
            "dnsrecon_scan": self._parse_dnsrecon_results,
            "theharvester_scan": self._parse_theharvester_results,
            "wpscan_audit": self._parse_wpscan_results,
            "hydra_bruteforce": self._parse_hydra_results,
            "john_crack": self._parse_john_results,
            "searchsploit_search": self._parse_searchsploit_results,
        }

        parser_func = parsing_map.get(tool_name)
        if parser_func:
            return parser_func(target, raw_output, output_file, scan_id)
        else:
            logger.warning(f"No parser available for tool: {tool_name}")
            return {"parsed_data": None, "items_stored": 0}

    def _parse_nmap_results(
        self, target: str, raw_output: str, output_file: str, scan_id: int
    ) -> Dict[str, Any]:
        """Parse Nmap XML results and store hosts/ports"""
        results = {"parsed_data": {}, "items_stored": 0}

        try:
            if output_file and Path(output_file).exists():
                # Parse XML file
                tree = ET.parse(output_file)
                root = tree.getroot()

                for host_elem in root.findall("host"):
                    # Get host information
                    address_elem = host_elem.find("address[@addrtype='ipv4']")
                    if address_elem is None:
                        continue

                    ip_address = address_elem.get("addr")

                    # Get hostname if available
                    hostname = None
                    hostnames = host_elem.find("hostnames")
                    if hostnames is not None:
                        hostname_elem = hostnames.find("hostname")
                        if hostname_elem is not None:
                            hostname = hostname_elem.get("name")

                    # Get OS information if available
                    os_info = None
                    os_elem = host_elem.find("os")
                    if os_elem is not None:
                        osmatch = os_elem.find("osmatch")
                        if osmatch is not None:
                            os_info = osmatch.get("name")

                    # Store host
                    host_id = self.db.store_discovered_host(
                        session_id=self.current_session_id,
                        scan_id=scan_id,
                        ip_address=ip_address,
                        hostname=hostname,
                        os_info=os_info,
                        discovered_by="nmap_scan",
                    )

                    if host_id != -1:
                        results["items_stored"] += 1

                        # Parse ports
                        ports_elem = host_elem.find("ports")
                        if ports_elem is not None:
                            for port_elem in ports_elem.findall("port"):
                                port_num = int(port_elem.get("portid"))
                                protocol = port_elem.get("protocol")

                                state_elem = port_elem.find("state")
                                state = (
                                    state_elem.get("state")
                                    if state_elem is not None
                                    else "unknown"
                                )

                                service_elem = port_elem.find("service")
                                service_name = None
                                service_version = None
                                service_info = None

                                if service_elem is not None:
                                    service_name = service_elem.get("name")
                                    service_version = service_elem.get("version")
                                    product = service_elem.get("product", "")
                                    version = service_elem.get("version", "")
                                    service_info = f"{product} {version}".strip()

                                # Store port
                                if self.db.store_discovered_port(
                                    host_id=host_id,
                                    session_id=self.current_session_id,
                                    scan_id=scan_id,
                                    port_number=port_num,
                                    protocol=protocol,
                                    state=state,
                                    service_name=service_name,
                                    service_version=service_version,
                                    service_info=service_info,
                                    discovered_by="nmap_scan",
                                ):
                                    results["items_stored"] += 1

                results["parsed_data"] = {"hosts_found": results["items_stored"]}

        except Exception as e:
            logger.error(f"Error parsing Nmap results: {e}")
            results["error"] = str(e)

        return results

    def _parse_gobuster_results(
        self, target: str, raw_output: str, output_file: str, scan_id: int
    ) -> Dict[str, Any]:
        """Parse Gobuster directory/file results"""
        results = {"parsed_data": {}, "items_stored": 0}

        try:
            content = raw_output
            if output_file and Path(output_file).exists():
                with open(output_file, "r") as f:
                    content = f.read()

            directories = []
            lines = content.split("\n")

            for line in lines:
                # Match various Gobuster output formats
                if any(
                    pattern in line for pattern in ["Status:", "Found:", "[+]", "=>"]
                ):
                    # Extract path and status code
                    path_match = re.search(r"(/[^\s]*)", line)
                    status_match = re.search(r"\(Status:\s*(\d+)\)", line) or re.search(
                        r"Status:\s*(\d+)", line
                    )
                    size_match = re.search(r"\[Size:\s*(\d+)\]", line)

                    if path_match:
                        directory_path = path_match.group(1)
                        http_status = (
                            int(status_match.group(1)) if status_match else None
                        )
                        content_length = (
                            int(size_match.group(1)) if size_match else None
                        )

                        # Store web directory
                        if self.db.store_web_directory(
                            session_id=self.current_session_id,
                            scan_id=scan_id,
                            base_url=target,
                            directory_path=directory_path,
                            http_status=http_status,
                            content_length=content_length,
                            discovered_by="gobuster_scan",
                        ):
                            directories.append(directory_path)
                            results["items_stored"] += 1

            results["parsed_data"] = {
                "directories_found": len(directories),
                "paths": directories[:10],  # Store first 10 paths as sample
            }

        except Exception as e:
            logger.error(f"Error parsing Gobuster results: {e}")
            results["error"] = str(e)

        return results

    def _parse_nikto_results(
        self, target: str, raw_output: str, output_file: str, scan_id: int
    ) -> Dict[str, Any]:
        """Parse Nikto XML results and store vulnerabilities"""
        results = {"parsed_data": {}, "items_stored": 0}

        try:
            if (
                output_file
                and Path(output_file).exists()
                and output_file.endswith(".xml")
            ):
                tree = ET.parse(output_file)
                root = tree.getroot()

                vulnerabilities = []

                for scandetails in root.findall(".//scandetails"):
                    for item in scandetails.findall("item"):
                        vuln_id = item.get("id", "")
                        osvdb_id = item.get("osvdb", "")
                        method = item.get("method", "GET")

                        description_elem = item.find("description")
                        description = (
                            description_elem.text
                            if description_elem is not None
                            else ""
                        )

                        uri_elem = item.find("uri")
                        uri = uri_elem.text if uri_elem is not None else ""

                        # Determine severity based on OSVDB or keywords
                        severity = "medium"  # Default
                        if (
                            "critical" in description.lower()
                            or "high" in description.lower()
                        ):
                            severity = "high"
                        elif (
                            "low" in description.lower()
                            or "info" in description.lower()
                        ):
                            severity = "low"

                        title = f"Nikto Finding {vuln_id}"
                        if osvdb_id:
                            title += f" (OSVDB: {osvdb_id})"

                        # Store vulnerability
                        if self.db.store_vulnerability(
                            session_id=self.current_session_id,
                            scan_id=scan_id,
                            target=f"{target}{uri}",
                            vuln_type="web_vulnerability",
                            severity=severity,
                            title=title,
                            description=description,
                            discovered_by="nikto_scan",
                        ):
                            vulnerabilities.append(title)
                            results["items_stored"] += 1

                results["parsed_data"] = {
                    "vulnerabilities_found": len(vulnerabilities),
                    "sample_vulnerabilities": vulnerabilities[:5],
                }

        except Exception as e:
            logger.error(f"Error parsing Nikto results: {e}")
            results["error"] = str(e)

        return results

    def _parse_sqlmap_results(
        self, target: str, raw_output: str, output_file: str, scan_id: int
    ) -> Dict[str, Any]:
        """Parse SQLMap results and store SQL injection vulnerabilities"""
        results = {"parsed_data": {}, "items_stored": 0}

        try:
            content = raw_output

            # Look for SQL injection indicators
            injection_patterns = [
                r"sqlmap identified the following injection point",
                r"Parameter: (.*?) \(.*?\)",
                r"Type: (.+)",
                r"Title: (.+)",
                r"Payload: (.+)",
            ]

            vulnerabilities_found = []

            for pattern in injection_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches and "injection point" in pattern.lower():
                    # SQL injection found
                    vuln_title = "SQL Injection Vulnerability"
                    vuln_description = (
                        f"SQLMap identified SQL injection in target: {target}"
                    )

                    # Extract additional details from output
                    param_match = re.search(r"Parameter: (.*?) \(.*?\)", content)
                    type_match = re.search(r"Type: (.+)", content)

                    if param_match:
                        vuln_description += (
                            f"\nVulnerable Parameter: {param_match.group(1)}"
                        )
                    if type_match:
                        vuln_description += f"\nInjection Type: {type_match.group(1)}"

                    # Store vulnerability
                    if self.db.store_vulnerability(
                        session_id=self.current_session_id,
                        scan_id=scan_id,
                        target=target,
                        vuln_type="sql_injection",
                        severity="high",
                        title=vuln_title,
                        description=vuln_description,
                        discovered_by="sqlmap_scan",
                    ):
                        vulnerabilities_found.append(vuln_title)
                        results["items_stored"] += 1

            results["parsed_data"] = {
                "sql_injections_found": len(vulnerabilities_found),
                "vulnerabilities": vulnerabilities_found,
            }

        except Exception as e:
            logger.error(f"Error parsing SQLMap results: {e}")
            results["error"] = str(e)

        return results

    def _parse_hydra_results(
        self, target: str, raw_output: str, output_file: str, scan_id: int
    ) -> Dict[str, Any]:
        """Parse Hydra brute force results and store credentials"""
        results = {"parsed_data": {}, "items_stored": 0}

        try:
            content = raw_output
            if output_file and Path(output_file).exists():
                with open(output_file, "r") as f:
                    content = f.read()

            credentials_found = []

            # Look for successful login patterns
            login_patterns = [
                r"\[(\d+)\]\[(\w+)\] host: ([\d\.]+)\s+login: (\w+)\s+password: (.+)",
                r"login: (\w+)\s+password: (\w+)",
            ]

            for pattern in login_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if len(match) >= 2:
                        if len(match) == 5:  # Full pattern match
                            port, service, host, username, password = match
                            port_num = int(port) if port.isdigit() else None
                        else:  # Simple pattern match
                            username, password = match[-2:]
                            service = "unknown"
                            port_num = None

                        # Store credentials
                        if self.db.store_credentials(
                            session_id=self.current_session_id,
                            scan_id=scan_id,
                            target=target,
                            username=username,
                            password=password,
                            service=service,
                            port=port_num,
                            discovered_by="hydra_bruteforce",
                        ):
                            credentials_found.append(f"{username}:{password}")
                            results["items_stored"] += 1

            results["parsed_data"] = {
                "credentials_found": len(credentials_found),
                "usernames": [cred.split(":")[0] for cred in credentials_found],
            }

        except Exception as e:
            logger.error(f"Error parsing Hydra results: {e}")
            results["error"] = str(e)

        return results

    def _parse_searchsploit_results(
        self, target: str, raw_output: str, output_file: str, scan_id: int
    ) -> Dict[str, Any]:
        """Parse SearchSploit results and store potential exploits"""
        results = {"parsed_data": {}, "items_stored": 0}

        try:
            content = raw_output
            if output_file and Path(output_file).exists():
                with open(output_file, "r") as f:
                    content = f.read()

            exploits_found = []

            # Parse searchsploit output format
            lines = content.split("\n")
            for line in lines:
                # Skip header lines and empty lines
                if not line.strip() or line.startswith("-") or "Exploit Title" in line:
                    continue

                # Match exploit entries
                parts = line.split("|")
                if len(parts) >= 2:
                    exploit_title = parts[0].strip()
                    exploit_path = parts[1].strip()

                    # Extract date and platform if available
                    date_match = re.search(r"(\d{4}-\d{2}-\d{2})", line)
                    platform_match = re.search(
                        r"(linux|windows|unix|multiple)", line.lower()
                    )

                    exploit_date = date_match.group(1) if date_match else None
                    platform = platform_match.group(1) if platform_match else "unknown"

                    # Determine exploit type
                    exploit_type = "unknown"
                    if "remote" in exploit_title.lower():
                        exploit_type = "remote"
                    elif "local" in exploit_title.lower():
                        exploit_type = "local"
                    elif "dos" in exploit_title.lower():
                        exploit_type = "denial_of_service"

                    # Store exploit
                    if self.db.store_exploit(
                        session_id=self.current_session_id,
                        scan_id=scan_id,
                        target=target,
                        exploit_title=exploit_title,
                        exploit_path=exploit_path,
                        exploit_type=exploit_type,
                        platform=platform,
                        exploit_date=exploit_date,
                        discovered_by="searchsploit_search",
                    ):
                        exploits_found.append(exploit_title)
                        results["items_stored"] += 1

            results["parsed_data"] = {
                "exploits_found": len(exploits_found),
                "sample_exploits": exploits_found[:5],
            }

        except Exception as e:
            logger.error(f"Error parsing SearchSploit results: {e}")
            results["error"] = str(e)

        return results

    def _parse_dnsrecon_results(
        self, target: str, raw_output: str, output_file: str, scan_id: int
    ) -> Dict[str, Any]:
        """Parse DNSRecon results and store DNS records"""
        results = {"parsed_data": {}, "items_stored": 0}

        try:
            content = raw_output
            if output_file and Path(output_file).exists():
                with open(output_file, "r") as f:
                    content = f.read()

            dns_records = []

            # Parse DNS record patterns
            record_patterns = {
                "A": r"A\s+(\S+)\s+(\S+)",
                "AAAA": r"AAAA\s+(\S+)\s+(\S+)",
                "CNAME": r"CNAME\s+(\S+)\s+(\S+)",
                "MX": r"MX\s+(\S+)\s+(\S+)",
                "NS": r"NS\s+(\S+)\s+(\S+)",
                "TXT": r'TXT\s+(\S+)\s+"([^"]*)"',
            }

            for record_type, pattern in record_patterns.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    if len(match) >= 2:
                        domain = match[0]
                        record_value = match[1]

                        # Store DNS record
                        if self.db.store_dns_record(
                            session_id=self.current_session_id,
                            scan_id=scan_id,
                            domain=domain,
                            record_type=record_type,
                            record_value=record_value,
                            discovered_by="dnsrecon_scan",
                        ):
                            dns_records.append(f"{domain} {record_type} {record_value}")
                            results["items_stored"] += 1

            results["parsed_data"] = {
                "dns_records_found": len(dns_records),
                "sample_records": dns_records[:5],
            }

        except Exception as e:
            logger.error(f"Error parsing DNSRecon results: {e}")
            results["error"] = str(e)

        return results

    def _parse_dirb_results(
        self, target: str, raw_output: str, output_file: str, scan_id: int
    ) -> Dict[str, Any]:
        """Parse DIRB directory results"""
        results = {"parsed_data": {}, "items_stored": 0}

        try:
            content = raw_output
            if output_file and Path(output_file).exists():
                with open(output_file, "r") as f:
                    content = f.read()

            directories = []

            # Parse DIRB output format
            lines = content.split("\n")
            for line in lines:
                if "==>" in line and "CODE:" in line:
                    # Extract URL and status code from DIRB output
                    url_match = re.search(r"==>\s*(http[s]?://\S+)", line)
                    code_match = re.search(r"CODE:(\d+)", line)
                    size_match = re.search(r"SIZE:(\d+)", line)

                    if url_match:
                        full_url = url_match.group(1)
                        # Extract path from full URL
                        path = full_url.replace(target, "") or "/"
                        http_status = int(code_match.group(1)) if code_match else None
                        content_length = (
                            int(size_match.group(1)) if size_match else None
                        )

                        # Store web directory
                        if self.db.store_web_directory(
                            session_id=self.current_session_id,
                            scan_id=scan_id,
                            base_url=target,
                            directory_path=path,
                            http_status=http_status,
                            content_length=content_length,
                            discovered_by="dirb_scan",
                        ):
                            directories.append(path)
                            results["items_stored"] += 1

            results["parsed_data"] = {
                "directories_found": len(directories),
                "paths": directories[:10],
            }

        except Exception as e:
            logger.error(f"Error parsing DIRB results: {e}")
            results["error"] = str(e)

        return results

    def _parse_amass_results(
        self, target: str, raw_output: str, output_file: str, scan_id: int
    ) -> Dict[str, Any]:
        """Parse Amass subdomain results"""
        results = {"parsed_data": {}, "items_stored": 0}

        try:
            content = raw_output
            if output_file and Path(output_file).exists():
                with open(output_file, "r") as f:
                    content = f.read()

            subdomains = []

            # Parse subdomains from output
            lines = content.split("\n")
            for line in lines:
                line = line.strip()
                if line and "." in line and not line.startswith("#"):
                    # Simple validation for subdomain format
                    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", line):
                        # Store as DNS A record
                        if self.db.store_dns_record(
                            session_id=self.current_session_id,
                            scan_id=scan_id,
                            domain=line,
                            record_type="SUBDOMAIN",
                            record_value=target,
                            discovered_by="amass_scan",
                        ):
                            subdomains.append(line)
                            results["items_stored"] += 1

            results["parsed_data"] = {
                "subdomains_found": len(subdomains),
                "sample_subdomains": subdomains[:10],
            }

        except Exception as e:
            logger.error(f"Error parsing Amass results: {e}")
            results["error"] = str(e)

        return results

    def _parse_theharvester_results(
        self, target: str, raw_output: str, output_file: str, scan_id: int
    ) -> Dict[str, Any]:
        """Parse TheHarvester results for emails and hosts"""
        results = {"parsed_data": {}, "items_stored": 0}

        try:
            content = raw_output
            if output_file and Path(output_file).exists():
                if output_file.endswith(".json"):
                    with open(output_file, "r") as f:
                        try:
                            json_data = json.load(f)
                            content = json.dumps(json_data)
                        except:
                            content = f.read()
                else:
                    with open(output_file, "r") as f:
                        content = f.read()

            emails = []
            hosts = []

            # Extract emails
            email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
            email_matches = re.findall(email_pattern, content)

            # Extract hosts/subdomains
            host_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
            host_matches = re.findall(host_pattern, content)

            # Store emails as text records
            for email in set(email_matches):
                if self.db.store_dns_record(
                    session_id=self.current_session_id,
                    scan_id=scan_id,
                    domain=target,
                    record_type="EMAIL",
                    record_value=email,
                    discovered_by="theharvester_scan",
                ):
                    emails.append(email)
                    results["items_stored"] += 1

            # Store hosts
            for host in set(host_matches):
                if target.lower() in host.lower():  # Related to target domain
                    if self.db.store_dns_record(
                        session_id=self.current_session_id,
                        scan_id=scan_id,
                        domain=host,
                        record_type="HOST",
                        record_value=target,
                        discovered_by="theharvester_scan",
                    ):
                        hosts.append(host)
                        results["items_stored"] += 1

            results["parsed_data"] = {
                "emails_found": len(emails),
                "hosts_found": len(hosts),
                "sample_emails": emails[:5],
                "sample_hosts": hosts[:5],
            }

        except Exception as e:
            logger.error(f"Error parsing TheHarvester results: {e}")
            results["error"] = str(e)

        return results

    def _parse_wpscan_results(
        self, target: str, raw_output: str, output_file: str, scan_id: int
    ) -> Dict[str, Any]:
        """Parse WPScan results and store WordPress vulnerabilities"""
        results = {"parsed_data": {}, "items_stored": 0}

        try:
            content = raw_output
            if output_file and Path(output_file).exists():
                with open(output_file, "r") as f:
                    try:
                        json_data = json.load(f)
                        content = json.dumps(json_data)
                        # Parse JSON format
                        vulnerabilities = json_data.get("vulnerabilities", [])
                        for vuln in vulnerabilities:
                            title = vuln.get("title", "WordPress Vulnerability")
                            references = vuln.get("references", {})

                            # Store vulnerability
                            if self.db.store_vulnerability(
                                session_id=self.current_session_id,
                                scan_id=scan_id,
                                target=target,
                                vuln_type="wordpress_vulnerability",
                                severity="medium",  # Default severity
                                title=title,
                                description=str(vuln),
                                references=json.dumps(references),
                                discovered_by="wpscan_audit",
                            ):
                                results["items_stored"] += 1

                    except json.JSONDecodeError:
                        content = f.read()

            # Also parse text format output
            vuln_count = len(re.findall(r"\[!\]", content))
            results["parsed_data"] = {
                "wordpress_vulnerabilities": results["items_stored"],
                "warnings_found": vuln_count,
            }

        except Exception as e:
            logger.error(f"Error parsing WPScan results: {e}")
            results["error"] = str(e)

        return results

    def _parse_john_results(
        self, target: str, raw_output: str, output_file: str, scan_id: int
    ) -> Dict[str, Any]:
        """Parse John the Ripper results and store cracked passwords"""
        results = {"parsed_data": {}, "items_stored": 0}

        try:
            content = raw_output
            if output_file and Path(output_file).exists():
                with open(output_file, "r") as f:
                    content = f.read()

            cracked_passwords = []

            # Parse John output for cracked passwords
            lines = content.split("\n")
            for line in lines:
                # Look for cracked password format: username:password
                if ":" in line and not line.startswith("#") and line.strip():
                    parts = line.strip().split(":")
                    if len(parts) >= 2:
                        username = parts[0]
                        password = ":".join(parts[1:])  # Handle passwords with colons

                        # Store credentials
                        if self.db.store_credentials(
                            session_id=self.current_session_id,
                            scan_id=scan_id,
                            target=target,
                            username=username,
                            password=password,
                            discovered_by="john_crack",
                        ):
                            cracked_passwords.append(f"{username}:{password}")
                            results["items_stored"] += 1

            results["parsed_data"] = {
                "passwords_cracked": len(cracked_passwords),
                "usernames": [pwd.split(":")[0] for pwd in cracked_passwords],
            }

        except Exception as e:
            logger.error(f"Error parsing John results: {e}")
            results["error"] = str(e)

        return results

    def get_session_statistics(self, session_id: str = None) -> Dict[str, Any]:
        """Get comprehensive statistics for current or specified session"""
        if session_id is None:
            session_id = self.current_session_id

        if not session_id:
            return {"error": "No session specified"}

        return self.db.get_session_summary(session_id)

    def export_session_report(
        self, session_id: str = None, format: str = "json"
    ) -> str:
        """Export complete session report"""
        if session_id is None:
            session_id = self.current_session_id

        if not session_id:
            return json.dumps({"error": "No session specified"})

        return self.db.export_session_data(session_id, format)

    def search_findings(self, **criteria) -> List[Dict[str, Any]]:
        """Search for specific findings across all sessions"""
        results = []

        # Search vulnerabilities
        if criteria.get("vulnerability_type") or criteria.get("severity"):
            vulns = self.db.search_vulnerabilities(
                severity=criteria.get("severity"),
                vuln_type=criteria.get("vulnerability_type"),
                cve_id=criteria.get("cve_id"),
            )
            results.extend([{"type": "vulnerability", "data": v} for v in vulns])

        return results

    def cleanup_session(self, session_id: str = None) -> bool:
        """Clean up a specific session's data"""
        if session_id is None:
            session_id = self.current_session_id

        if not session_id:
            return False

        try:
            # This would require implementing session deletion in DatabaseManager
            logger.info(f"Session cleanup requested for: {session_id}")
            return True
        except Exception as e:
            logger.error(f"Error cleaning up session: {e}")
            return False


# Global database integration instance
db_integration = None


def get_db_integration() -> DatabaseIntegration:
    """Get the global database integration instance"""
    global db_integration
    if db_integration is None:
        db_integration = DatabaseIntegration()
    return db_integration


def store_and_parse_scan_result(
    tool_name: str,
    target: str,
    command: str,
    raw_output: str,
    output_file: str = None,
    execution_time: float = None,
    scan_type: str = None,
    session_id: str = None,
) -> Dict[str, Any]:
    """
    Convenience function to store and parse scan results
    This is the main entry point for integration with MCP server tools
    """
    db_int = get_db_integration()

    if session_id:
        db_int.set_session(session_id)

    return db_int.store_scan_with_parsing(
        tool_name=tool_name,
        target=target,
        command=command,
        raw_output=raw_output,
        output_file=output_file,
        execution_time=execution_time,
        scan_type=scan_type,
    )


if __name__ == "__main__":
    # Test the database integration
    print("🧪 Testing Database Integration...")

    # Create test instance
    db_int = DatabaseIntegration()

    # Create test session
    session_id = f"test_integration_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    db_int.db.create_session(
        session_id, "Test Integration Target", "Testing database integration"
    )
    db_int.set_session(session_id)

    # Test Nmap parsing
    nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <nmaprun>
        <host>
            <address addr="192.168.1.1" addrtype="ipv4"/>
            <hostnames>
                <hostname name="router.local" type="PTR"/>
            </hostnames>
            <ports>
                <port protocol="tcp" portid="22">
                    <state state="open"/>
                    <service name="ssh" version="7.4" product="OpenSSH"/>
                </port>
                <port protocol="tcp" portid="80">
                    <state state="open"/>
                    <service name="http" version="2.4" product="Apache"/>
                </port>
            </ports>
        </host>
    </nmaprun>"""

    # Create test XML file
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
        f.write(nmap_xml)
        temp_xml_path = f.name

    # Test parsing
    result = db_int.store_scan_with_parsing(
        tool_name="nmap_scan",
        target="192.168.1.1",
        command="nmap -sS 192.168.1.1",
        raw_output="Nmap scan report...",
        output_file=temp_xml_path,
        execution_time=10.5,
        scan_type="basic",
    )

    print("Parsing Result:", json.dumps(result, indent=2))

    # Get session statistics
    stats = db_int.get_session_statistics()
    print("Session Statistics:", json.dumps(stats, indent=2))

    # Clean up
    os.unlink(temp_xml_path)

    print("✅ Database Integration test completed!")
