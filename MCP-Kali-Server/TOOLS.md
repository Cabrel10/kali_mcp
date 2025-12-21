# Kali MCP Server Tools

This document provides a description of the tools available in the Kali MCP Server.

## Table of Contents

- [server_health](#server_health)
- [execute_command](#execute_command)
- [nmap_scan](#nmap_scan)
- [gobuster_scan](#gobuster_scan)
- [dirb_scan](#dirb_scan)
- [nikto_scan](#nikto_scan)
- [sqlmap_scan](#sqlmap_scan)
- [metasploit_console_command](#metasploit_console_command)
- [hydra_bruteforce](#hydra_bruteforce)
- [john_crack](#john_crack)
- [amass_scan](#amass_scan)
- [theharvester_scan](#theharvester_scan)
- [wpscan_audit](#wpscan_audit)
- [enum4linux_scan](#enum4linux_scan)
- [aircrack_ng_suite](#aircrack_ng_suite)
- [tshark_capture](#tshark_capture)
- [bettercap_scan](#bettercap_scan)
- [wfuzz_scan](#wfuzz_scan)
- [whatweb_scan](#whatweb_scan)
- [kismet_start_server](#kismet_start_server)
- [reaver_scan](#reaver_scan)
- [pixiewps_scan](#pixiewps_scan)
- [legion_scan](#legion_scan)
- [spiderfoot_scan](#spiderfoot_scan)
- [dnsrecon_scan](#dnsrecon_scan)
- [empire_shell](#empire_shell)
- [evil_winrm_shell](#evil_winrm_shell)
- [hashcat_crack](#hashcat_crack)
- [searchsploit_search](#searchsploit_search)

## Tools

### server_health

Checks the status of the Kali server and the availability of essential tools. Essential for starting a pentest or CTF. Logs execution.

**Parameters:**

- None

### execute_command

Executes an arbitrary shell command on the Kali machine. Useful for chaining tools or running custom commands. Logs execution.

**Parameters:**

- `command` (str): The command to execute.

### nmap_scan

Performs network reconnaissance (ports, services) using Nmap. Outputs results in a specified format (default: XML) and logs execution. Provides structured parsing of XML output.

**Parameters:**

- `target` (str): The target to scan.
- `scan_type` (str, optional): The type of scan to perform. Defaults to "basic".
- `output_format` (str, optional): The output format. Defaults to "xml".
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Nmap. Defaults to "".
- `timeout` (int, optional): The timeout for the scan. Defaults to 600.
- `intensity` (str, optional): The intensity of the scan. Defaults to "medium".

### gobuster_scan

Scans for directories, DNS subdomains, or vhosts using Gobuster. Outputs results to a file, parses them, and logs execution.

**Parameters:**

- `url` (str): The URL to scan.
- `mode` (str, optional): The mode of the scan. Defaults to "dir".
- `wordlist` (str, optional): The wordlist to use. Defaults to "/usr/share/wordlists/dirb/common.txt".
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Gobuster. Defaults to "".
- `timeout` (int, optional): The timeout for the scan. Defaults to 600.
- `intensity` (str, optional): The intensity of the scan. Defaults to "medium".

### dirb_scan

Scans for web content and directories using Dirb. Outputs results to a file, parses them, and logs execution.

**Parameters:**

- `url` (str): The URL to scan.
- `wordlist` (str, optional): The wordlist to use. Defaults to "/usr/share/wordlists/dirb/common.txt".
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Dirb. Defaults to "".

### nikto_scan

Scans for web server vulnerabilities using Nikto. Outputs results in a specified format (default: XML) and logs execution. Provides structured parsing of XML output if format is XML.

**Parameters:**

- `target` (str): The target to scan.
- `output_format` (str, optional): The output format. Defaults to "xml".
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Nikto. Defaults to "".
- `timeout` (int, optional): The timeout for the scan. Defaults to 600.
- `intensity` (str, optional): The intensity of the scan. Defaults to "medium".

### sqlmap_scan

Scans for and exploits SQL injection vulnerabilities using SQLMap. Can optionally dump data to a specified output directory. Logs execution.

**Parameters:**

- `url` (str): The URL to scan.
- `data` (str, optional): The data to send with the request. Defaults to None.
- `dump_data` (bool, optional): Whether to dump data. Defaults to False.
- `output_dir` (str, optional): The output directory for dumped data. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to SQLMap. Defaults to "--batch".

### metasploit_console_command

Executes a list of commands within the Metasploit Framework console (msfconsole). Useful for running modules, database exports (e.g., db_export -f xml), or other msfconsole commands. Logs execution and captures output.

**Parameters:**

- `commands` (List[str]): The commands to execute.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Metasploit. Defaults to "".

### hydra_bruteforce

Performs brute-force login attacks using Hydra. Outputs results to a file (if specified), parses them, and logs execution.

**Parameters:**

- `target` (str): The target to attack.
- `service` (str): The service to attack.
- `username` (str, optional): The username to use. Defaults to None.
- `userlist` (str, optional): The userlist to use. Defaults to None.
- `password` (str, optional): The password to use. Defaults to None.
- `passlist` (str, optional): The passlist to use. Defaults to None.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Hydra. Defaults to "".

### john_crack

Cracks password hashes using John the Ripper. Can output cracked passwords to stdout or a file, and logs execution.

**Parameters:**

- `hash_file` (str): The hash file to crack.
- `wordlist` (str, optional): The wordlist to use. Defaults to "/usr/share/wordlists/rockyou.txt".
- `format` (str, optional): The hash format. Defaults to None.
- `stdout_output` (bool, optional): Whether to output to stdout. Defaults to False.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to John the Ripper. Defaults to "".

### amass_scan

Performs subdomain enumeration using Amass. Outputs results in JSON format and logs execution. Provides structured parsing of JSON output.

**Parameters:**

- `domain` (str): The domain to scan.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Amass. Defaults to "".
- `timeout` (int, optional): The timeout for the scan. Defaults to 600.

### theharvester_scan

Collects emails, names, subdomains, etc., using TheHarvester. Outputs results in JSON or XML format and logs execution. Provides structured parsing of JSON/XML output.

**Parameters:**

- `domain` (str): The domain to scan.
- `source` (str, optional): The source to use. Defaults to "google".
- `output_format` (str, optional): The output format. Defaults to "json".
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to TheHarvester. Defaults to "".

### wpscan_audit

Audits a WordPress site for vulnerabilities using WPScan. Requires a wpscan API token to be configured for vulnerability detection. Outputs results in JSON format and logs execution.

**Parameters:**

- `url` (str): The URL to scan.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to WPScan. Defaults to "".

### enum4linux_scan

Enumerates information from Windows and Samba systems using enum4linux. Parses stdout for structured information and logs execution.

**Parameters:**

- `target` (str): The target to scan.
- `additional_args` (str, optional): Additional arguments to pass to enum4linux. Defaults to "-a".

### aircrack_ng_suite

Executes a command from the Aircrack-ng suite. Outputs results to a file (if specified) and logs execution.

**Parameters:**

- `command` (str): The command to execute.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Aircrack-ng. Defaults to "".

### tshark_capture

Captures network traffic using TShark. Outputs results to a file (if specified) and logs execution.

**Parameters:**

- `interface` (str): The interface to capture from.
- `duration` (int): The duration of the capture.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to TShark. Defaults to "".

### bettercap_scan

Runs Bettercap with a specified set of modules. Outputs results to a file (if specified) and logs execution.

**Parameters:**

- `modules` (str): The modules to run.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Bettercap. Defaults to "".

### wfuzz_scan

Fuzzes a web application using Wfuzz. Outputs results to a file (if specified) and logs execution.

**Parameters:**

- `url` (str): The URL to fuzz.
- `wordlist` (str): The wordlist to use.
- `sc` (list[str], optional): The status codes to show. Defaults to None.
- `payload` (str, optional): The payload to use. Defaults to "FUZZ".
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Wfuzz. Defaults to "".

### whatweb_scan

Identifies technologies used by a website using WhatWeb. Outputs results to a file (if specified) and logs execution.

**Parameters:**

- `target` (str): The target to scan.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to WhatWeb. Defaults to "".

### kismet_start_server

Starts the Kismet server in the background.

**Parameters:**

- `interface` (str): The interface to use.
- `output_file_prefix` (str, optional): The prefix for the output files. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Kismet. Defaults to "".

### reaver_scan

Runs a Reaver scan. Outputs results to a file (if specified) and logs execution.

**Parameters:**

- `bssid` (str): The BSSID of the target.
- `interface` (str): The interface to use.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Reaver. Defaults to "".

### pixiewps_scan

Runs a PixieWPS scan. Outputs results to a file (if specified) and logs execution.

**Parameters:**

- `bssid` (str): The BSSID of the target.
- `pke` (str): The PKE.
- `pkr` (str): The PKR.
- `e_hash1` (str): The E-Hash1.
- `e_hash2` (str): The E-Hash2.
- `authkey` (str): The AuthKey.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to PixieWPS. Defaults to "".

### legion_scan

Runs a Legion scan on a target. Outputs results to a file (if specified) and logs execution.

**Parameters:**

- `target` (str): The target to scan.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Legion. Defaults to "".

### spiderfoot_scan

Runs an OSINT scan using SpiderFoot. Outputs results to a file (if specified) and logs execution.

**Parameters:**

- `target` (str): The target to scan.
- `modules` (str): The modules to use.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to SpiderFoot. Defaults to "".

### dnsrecon_scan

Performs DNS reconnaissance using DNSRecon. Outputs results to a file (if specified) and logs execution.

**Parameters:**

- `domain` (str): The domain to scan.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to DNSRecon. Defaults to "".

### empire_shell

Executes a list of commands within the Empire client. Useful for running modules, interacting with agents, etc. Logs execution and captures output.

**Parameters:**

- `commands` (List[str]): The commands to execute.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Empire. Defaults to "".

### evil_winrm_shell

Connects to a Windows machine using Evil-WinRM and executes commands.

**Parameters:**

- `ip` (str): The IP address of the target.
- `user` (str): The username to use.
- `password` (str, optional): The password to use. Defaults to None.
- `command` (str, optional): The command to execute. Defaults to None.
- `script` (str, optional): The script to execute. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Evil-WinRM. Defaults to "".

### hashcat_crack

Cracks password hashes using Hashcat. Can output cracked passwords to a file, and logs execution.

**Parameters:**

- `hash_file` (str): The hash file to crack.
- `wordlist` (str): The wordlist to use.
- `hash_type` (str): The hash type.
- `attack_mode` (str, optional): The attack mode. Defaults to "0".
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to Hashcat. Defaults to "".

### searchsploit_search

Searches for exploits in the Exploit-DB database using SearchSploit. Outputs results to a file (if specified) and logs execution.

**Parameters:**

- `query` (str): The query to search for.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to SearchSploit. Defaults to "".

### set_privacy_level

Sets the privacy level for the MCP.

- Level 1 (Cameleon): Basic protection. Changes MAC address and browser user-agent.
- Level 2 (Zombie): Intermediate protection. Routes traffic through proxies.
- Level 3 (Ghost): Maximum protection. Routes traffic through the Tor network.

**Parameters:**

- `level` (int): The privacy level to set.

### proxychains_command

Runs a command through proxychains. Outputs results to a file (if specified) and logs execution.

**Parameters:**

- `command` (str): The command to execute.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to proxychains. Defaults to "".

### tor_service

Manages the Tor service.

**Parameters:**

- `action` (str): The action to perform (start, stop, status).

### torsocks_command

Runs a command through torsocks. Outputs results to a file (if specified) and logs execution.

**Parameters:**

- `command` (str): The command to execute.
- `output_file` (str, optional): The output file. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to torsocks. Defaults to "".

### secure_browser_launcher

Launches a secure browser with options for Tor, proxychains, and a custom user-agent.

**Parameters:**

- `url` (str): The URL to open.
- `use_tor` (bool, optional): Whether to use Tor. Defaults to False.
- `use_proxychains` (bool, optional): Whether to use proxychains. Defaults to False.
- `user_agent` (str, optional): The user-agent to use. Defaults to None.
- `additional_args` (str, optional): Additional arguments to pass to the browser. Defaults to "".

### macchanger_spoof

Spoofs the MAC address of a network interface using macchanger.

**Parameters:**

- `interface` (str): The interface to spoof.
- `new_mac` (str, optional): The new MAC address to set. Defaults to None (random).
- `additional_args` (str, optional): Additional arguments to pass to macchanger. Defaults to "".

### start_session

Starts a new session and creates a directory to store the results.

**Parameters:**

- None
