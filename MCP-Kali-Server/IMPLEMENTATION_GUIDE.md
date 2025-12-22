# Implementation Guide - Server Recovery

## Current State Analysis

### ✅ What's Already Working
1. **AsyncExecutor** - Has proper timeout handling with process groups
2. **TaskManager** - Has proper task state management
3. **Process Group Management** - Uses `preexec_fn=os.setsid` for proper cleanup

### ❌ What's Broken
1. **Tool Integration** - Tools don't use TaskManager properly
2. **Background Execution** - Tools block the event loop instead of running async
3. **Task Status Updates** - Tasks stay in "pending" forever

## The Fix

### Problem Pattern (Current - Broken)
```python
@mcp.tool()
async def nmap_scan(target: str) -> str:
    # ❌ This blocks the event loop for 10+ minutes
    result = await executor.run_command(f"nmap {target}", timeout=900)
    return json.dumps(result)
```

### Solution Pattern (Fixed)
```python
@mcp.tool()
async def nmap_scan(target: str) -> str:
    # ✅ Create task and return immediately
    task_id = tasks.create_task(target, "nmap")
    
    # ✅ Start background execution
    tasks.start_background_task(
        task_id,
        _run_nmap_background,
        target
    )
    
    # ✅ Return task_id immediately
    return json.dumps({
        "status": "background_started",
        "task_id": task_id,
        "message": f"Nmap scan started. Use check_task('{task_id}') to check status"
    })

async def _run_nmap_background(target: str):
    # ✅ This runs in background without blocking
    cmd = f"nmap -sV -sC -O {target}"
    stdout, stderr, code = await executor.run_command(cmd, timeout=900)
    return json.dumps({
        "stdout": stdout,
        "stderr": stderr,
        "return_code": code
    })
```

## Tools to Fix (Priority Order)

### High Priority (Heavy Tools)
1. `nmap_scan` - Can run 10+ minutes
2. `sqlmap_scan` - Can run 20+ minutes
3. `gobuster_scan` - Can run 5+ minutes
4. `subdomain_enum` - Can run 10+ minutes
5. `nuclei_scan` - Can run 5+ minutes

### Medium Priority (Medium Duration)
6. `hydra_attack` - Can run 5+ minutes
7. `john_crack` - Can run 5+ minutes
8. `nikto_scan` - Can run 2+ minutes
9. `metasploit_exploit` - Can run 5+ minutes

### Low Priority (Quick Tools)
10. `web_tech_detect` - Usually < 30 seconds
11. `xss_scan` - Usually < 1 minute
12. `lfi_scan` - Usually < 1 minute

## Implementation Steps

### Step 1: Add check_task Tool
```python
@mcp.tool()
async def check_task(task_id: str) -> str:
    """Check status of a background task"""
    status = tasks.get_task_status(task_id)
    if not status:
        return json.dumps({"error": "Task not found"})
    
    return json.dumps(status)
```

### Step 2: Add list_tasks Tool
```python
@mcp.tool()
async def list_tasks(status: Optional[str] = None) -> str:
    """List all background tasks"""
    status_filter = TaskStatus[status.upper()] if status else None
    task_list = tasks.list_tasks(status_filter=status_filter)
    return json.dumps({"tasks": task_list})
```

### Step 3: Refactor Each Heavy Tool
For each tool:
1. Create a background function `_run_<tool>_background`
2. Update the main tool to create task and return immediately
3. Move all execution logic to background function
4. Ensure results are stored properly

## Testing Strategy

### Unit Test
```python
async def test_nmap_background():
    # Create task
    result = await nmap_scan("127.0.0.1")
    data = json.loads(result)
    
    # Should return task_id immediately
    assert "task_id" in data
    assert data["status"] == "background_started"
    
    # Check task status
    task_id = data["task_id"]
    status = await check_task(task_id)
    status_data = json.loads(status)
    
    # Should be running or completed
    assert status_data["status"] in ["running", "completed"]
```

### Integration Test
```python
async def test_multiple_concurrent_tasks():
    # Start multiple tasks
    task_ids = []
    for i in range(3):
        result = await nmap_scan(f"192.168.1.{i}")
        data = json.loads(result)
        task_ids.append(data["task_id"])
    
    # All should be running
    for task_id in task_ids:
        status = await check_task(task_id)
        data = json.loads(status)
        assert data["status"] in ["running", "pending"]
```

## Rollback Plan

If issues occur:
1. Stop server: `pkill -f kali_mcp_server`
2. Kill processes: `pkill -9 sqlmap nmap gobuster`
3. Revert changes: `git checkout HEAD -- kali_mcp_server_v3.py`
4. Restart: `./start_tactical.sh`

## Success Criteria

- ✅ Server doesn't crash on heavy tool execution
- ✅ Tools return immediately with task_id
- ✅ `check_task()` returns accurate status
- ✅ Multiple concurrent tasks work without interference
- ✅ No zombie processes after timeout
- ✅ Results stored correctly in session directory
