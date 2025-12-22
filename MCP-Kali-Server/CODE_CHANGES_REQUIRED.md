# Code Changes Required - Exact Implementation

## File: kali_mcp_server_v3.py

### Change 1: Add Imports
**Location**: Top of file after existing imports

```python
from src.core.task_manager import TaskManager, TaskStatus, get_task_manager
from src.core.async_executor import get_executor
```

### Change 2: Initialize TaskManager
**Location**: In the server initialization section

```python
# Initialize task manager
tasks = get_task_manager()
executor = get_executor()
```

### Change 3: Add Task Management Tools

**Add after `server_health()` tool:**

```python
@mcp.tool()
async def check_task(task_id: str) -> str:
    """
    Check the status of a background task
    
    Returns task status, progress, and results if completed
    """
    status = tasks.get_task_status(task_id)
    
    if not status:
        return json.dumps({
            "error": "Task not found",
            "task_id": task_id
        })
    
    return json.dumps(status)


@mcp.tool()
async def list_tasks(
    status_filter: Optional[str] = None,
    tool_filter: Optional[str] = None,
    limit: int = 50
) -> str:
    """
    List all background tasks with optional filters
    
    Args:
        status_filter: Filter by status (pending, running, completed, failed)
        tool_filter: Filter by tool name (nmap, sqlmap, etc.)
        limit: Maximum number of tasks to return
    """
    status_enum = None
    if status_filter:
        try:
            status_enum = TaskStatus[status_filter.upper()]
        except KeyError:
            return json.dumps({
                "error": f"Invalid status. Choose from: {[s.value for s in TaskStatus]}"
            })
    
    task_list = tasks.list_tasks(
        status_filter=status_enum,
        tool_filter=tool_filter
    )
    
    return json.dumps({
        "total": len(task_list),
        "tasks": task_list[:limit]
    })


@mcp.tool()
async def cancel_task(task_id: str) -> str:
    """
    Cancel a running or pending task
    
    Returns success status
    """
    success = tasks.cancel_task(task_id)
    
    return json.dumps({
        "task_id": task_id,
        "cancelled": success,
        "message": "Task cancelled successfully" if success else "Task not found or already finished"
    })


@mcp.tool()
async def get_task_stats() -> str:
    """
    Get statistics about all background tasks
    
    Returns counts by status and tool
    """
    stats = tasks.get_stats()
    
    return json.dumps(stats)
```

### Change 4: Refactor nmap_scan Tool

**Replace the entire `nmap_scan` function with:**

```python
@mcp.tool()
@resolve_references
async def nmap_scan(
    target: str,
    scan_type: str = "comprehensive",
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    intensity: str = "medium",
    output_file: Optional[str] = None,
    additional_args: str = "",
    timeout: int = 900,
    background: bool = True
) -> str:
    """
    Advanced Nmap scanning with background execution support
    
    When background=True (default), returns immediately with task_id.
    Use check_task(task_id) to monitor progress.
    
    When background=False, waits for completion (may timeout).
    """
    
    # Create task
    task_id = tasks.create_task(target, "nmap", f"nmap {target}")
    
    if background:
        # Start background execution
        tasks.start_background_task(
            task_id,
            _run_nmap_background,
            target, scan_type, ports, scripts, intensity, output_file, additional_args, timeout
        )
        
        # Return immediately
        return json.dumps({
            "status": "background_started",
            "task_id": task_id,
            "target": target,
            "scan_type": scan_type,
            "message": f"Nmap scan started in background. Use check_task('{task_id}') to check status.",
            "estimated_time": "5-15 minutes depending on scan type"
        })
    else:
        # Run synchronously (for quick scans only)
        result = await _run_nmap_background(
            target, scan_type, ports, scripts, intensity, output_file, additional_args, timeout
        )
        tasks.tasks[task_id].complete(result)
        return result


async def _run_nmap_background(
    target: str,
    scan_type: str = "comprehensive",
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    intensity: str = "medium",
    output_file: Optional[str] = None,
    additional_args: str = "",
    timeout: int = 900
) -> str:
    """Background execution of nmap scan"""
    
    inputs = {
        "target": target, "scan_type": scan_type, "ports": ports,
        "scripts": scripts, "intensity": intensity, "timeout": timeout
    }
    
    # Scan profiles optimized for different scenarios
    scan_profiles = {
        "quick": ["-F", "-T4", "--open"],
        "basic": ["-sV", "-sC", "-T3"],
        "comprehensive": ["-sV", "-sC", "-O", "-A", "--version-all"],
        "stealth": ["-sS", "-T2", "-f", "--data-length", "50"],
        "vuln": ["-sV", "--script=vuln,exploit,auth", "-T3"],
        "udp": ["-sU", "-sV", "--top-ports", "100", "-T4"],
        "aggressive": ["-sS", "-sV", "-sC", "-O", "-A", "-T4", "--script=default,vuln"]
    }
    
    intensity_timing = {
        "stealth": "-T1",
        "low": "-T2", 
        "medium": "-T3",
        "high": "-T4",
        "aggressive": "-T5"
    }
    
    if scan_type not in scan_profiles:
        error_msg = f"Invalid scan_type. Choose from: {list(scan_profiles.keys())}"
        return json.dumps({"status": "error", "message": error_msg})
    
    # Build output path
    if not output_file:
        timestamp = generate_timestamp()
        output_file = os.path.join(TOOL_LOG_DIR, f"nmap_{sanitize_filename(target)}_{timestamp}.xml")
    
    # Build command
    cmd = ["nmap"] + scan_profiles[scan_type]
    
    # Add timing
    if intensity in intensity_timing and "-T" not in str(scan_profiles[scan_type]):
        cmd.append(intensity_timing[intensity])
    
    # Add ports
    if ports:
        cmd.extend(["-p", ports])
    elif scan_type == "comprehensive":
        cmd.extend(["-p-"])  # All ports for comprehensive
    
    # Add scripts
    if scripts:
        cmd.extend(["--script", scripts])
    
    # Output format
    cmd.extend(["-oX", output_file, "-oN", output_file.replace(".xml", ".txt")])
    
    # Additional args
    if additional_args:
        cmd.extend(shlex.split(additional_args))
    
    cmd.append(target)
    
    # Execute using AsyncExecutor
    executor = get_executor()
    stdout, stderr, returncode = await executor.run_command(
        ' '.join(cmd),
        timeout=timeout
    )
    
    # Parse results
    parsed_data = {"hosts": [], "ports": [], "services": [], "os_matches": [], "scripts": []}
    
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                content = f.read()
            
            root = ET.fromstring(content)
            
            for host in root.findall("host"):
                host_info = {
                    "addresses": [],
                    "hostnames": [],
                    "ports": [],
                    "os": [],
                    "status": "unknown"
                }
                
                # Status
                status = host.find("status")
                if status is not None:
                    host_info["status"] = status.get("state", "unknown")
                
                # Addresses
                for addr in host.findall("address"):
                    host_info["addresses"].append({
                        "addr": addr.get("addr"),
                        "type": addr.get("addrtype")
                    })
                
                # Hostnames
                for hostname in host.findall("hostnames/hostname"):
                    host_info["hostnames"].append(hostname.get("name"))
                
                # Ports
                for port in host.findall("ports/port"):
                    port_info = {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state": "unknown",
                        "service": "unknown",
                        "product": None,
                        "version": None,
                        "scripts": []
                    }
                    
                    state = port.find("state")
                    if state is not None:
                        port_info["state"] = state.get("state")
                    
                    service = port.find("service")
                    if service is not None:
                        port_info["service"] = service.get("name", "unknown")
                        port_info["product"] = service.get("product")
                        port_info["version"] = service.get("version")
                        port_info["extrainfo"] = service.get("extrainfo")
                    
                    # Scripts
                    for script in port.findall("script"):
                        port_info["scripts"].append({
                            "id": script.get("id"),
                            "output": script.get("output", "")[:500]
                        })
                    
                    host_info["ports"].append(port_info)
                    
                    if port_info["state"] == "open":
                        parsed_data["ports"].append(f"{port_info['port']}/{port_info['protocol']}")
                        parsed_data["services"].append({
                            "port": port_info["port"],
                            "service": port_info["service"],
                            "product": port_info["product"],
                            "version": port_info["version"]
                        })
                
                # OS Detection
                for osmatch in host.findall("os/osmatch"):
                    os_info = {
                        "name": osmatch.get("name"),
                        "accuracy": osmatch.get("accuracy")
                    }
                    host_info["os"].append(os_info)
                    parsed_data["os_matches"].append(os_info)
                
                parsed_data["hosts"].append(host_info)
                
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
    
    # Build response
    open_ports = [p for h in parsed_data["hosts"] for p in h["ports"] if p["state"] == "open"]
    
    output = {
        "status": "success" if returncode == 0 else "partial",
        "target": target,
        "scan_type": scan_type,
        "output_file": output_file,
        "summary": {
            "hosts_up": len([h for h in parsed_data["hosts"] if h["status"] == "up"]),
            "open_ports": len(open_ports),
            "services_detected": len(parsed_data["services"])
        },
        "open_ports": parsed_data["ports"],
        "services": parsed_data["services"],
        "os_detection": parsed_data["os_matches"],
        "hosts": parsed_data["hosts"],
        "raw_output": stdout[:2000] if stdout else "",
        "errors": stderr if stderr else None
    }
    
    log_tool_execution("nmap_scan", inputs, output)
    return json.dumps(output, indent=2)
```

## Pattern for Other Heavy Tools

Apply the same pattern to these tools:
- `sqlmap_scan`
- `gobuster_scan`
- `subdomain_enum`
- `nuclei_scan`
- `hydra_attack`
- `john_crack`
- `nikto_scan`
- `metasploit_exploit`

**Template:**

```python
@mcp.tool()
async def tool_name(
    # ... parameters ...
    background: bool = True
) -> str:
    """Tool description"""
    
    # Create task
    task_id = tasks.create_task(target, "tool_name")
    
    if background:
        # Start background
        tasks.start_background_task(
            task_id,
            _run_tool_name_background,
            # ... parameters ...
        )
        
        # Return immediately
        return json.dumps({
            "status": "background_started",
            "task_id": task_id,
            "message": f"Tool started. Use check_task('{task_id}') to check status."
        })
    else:
        # Run synchronously
        result = await _run_tool_name_background(# ... parameters ...)
        tasks.tasks[task_id].complete(result)
        return result


async def _run_tool_name_background(# ... parameters ...) -> str:
    """Background execution of tool"""
    # ... implementation ...
    return json.dumps(output, indent=2)
```

## Testing

Add this test file: `test_background_tasks.py`

```python
#!/usr/bin/env python3
"""Test background task execution"""

import asyncio
import json
from kali_mcp_server_v3 import (
    nmap_scan, check_task, list_tasks, cancel_task, get_task_stats
)

async def test_background_nmap():
    """Test background nmap execution"""
    print("Testing background nmap scan...")
    
    # Start scan
    result = await nmap_scan("127.0.0.1", background=True)
    data = json.loads(result)
    
    assert data["status"] == "background_started"
    assert "task_id" in data
    
    task_id = data["task_id"]
    print(f"✅ Task created: {task_id}")
    
    # Check status
    status = await check_task(task_id)
    status_data = json.loads(status)
    
    assert status_data["status"] in ["pending", "running"]
    print(f"✅ Task status: {status_data['status']}")
    
    # List tasks
    tasks_list = await list_tasks()
    tasks_data = json.loads(tasks_list)
    
    assert tasks_data["total"] > 0
    print(f"✅ Total tasks: {tasks_data['total']}")
    
    # Get stats
    stats = await get_task_stats()
    stats_data = json.loads(stats)
    
    assert "running" in stats_data or "pending" in stats_data
    print(f"✅ Task stats: {stats_data}")
    
    print("\n✅ All tests passed!")

if __name__ == "__main__":
    asyncio.run(test_background_nmap())
```

## Deployment Checklist

- [ ] Add imports to kali_mcp_server_v3.py
- [ ] Initialize TaskManager and AsyncExecutor
- [ ] Add check_task() tool
- [ ] Add list_tasks() tool
- [ ] Add cancel_task() tool
- [ ] Add get_task_stats() tool
- [ ] Refactor nmap_scan to use background execution
- [ ] Refactor sqlmap_scan to use background execution
- [ ] Refactor gobuster_scan to use background execution
- [ ] Refactor subdomain_enum to use background execution
- [ ] Refactor nuclei_scan to use background execution
- [ ] Refactor hydra_attack to use background execution
- [ ] Refactor john_crack to use background execution
- [ ] Refactor nikto_scan to use background execution
- [ ] Refactor metasploit_exploit to use background execution
- [ ] Run unit tests
- [ ] Run integration tests
- [ ] Test with concurrent tasks
- [ ] Verify no zombie processes
- [ ] Update documentation
- [ ] Deploy to production
