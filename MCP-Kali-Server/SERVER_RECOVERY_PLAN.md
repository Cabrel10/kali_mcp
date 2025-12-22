# MCP Kali Server Recovery Plan

## Problem Summary
The server crashes due to:
1. **Timeout Cascades**: Heavy tools (SQLMap, Nmap) run synchronously, blocking the event loop
2. **Zombie Processes**: When requests timeout, background processes continue running
3. **Task Manager Freeze**: Asynchronous tasks get stuck in "pending" status
4. **No Process Cleanup**: Orphaned processes accumulate and consume resources

## Root Causes Identified

### Issue 1: Synchronous Tool Execution
```python
# ❌ WRONG - Blocks event loop for 10-30 minutes
result = await run_command("sqlmap ...", timeout=600)
```

### Issue 2: Missing Process Group Management
```python
# ❌ WRONG - Process continues after timeout
process = await asyncio.create_subprocess_shell(cmd)
```

### Issue 3: Task Manager Not Properly Integrated
```python
# ❌ WRONG - Task stays in "pending" forever
asyncio.create_task(background_function())
```

## Solution Architecture

### 1. Process Manager (Handles Cleanup)
- Tracks all spawned processes
- Kills orphaned processes on timeout
- Manages process groups for proper cleanup

### 2. Async Executor (Handles Timeouts)
- Uses process groups (`preexec_fn=os.setsid`)
- Implements forced kill on timeout
- Returns immediately on timeout

### 3. Task Manager Integration (Handles Status)
- Properly links background tasks to task manager
- Updates task status: pending → running → completed
- Stores results in session directory

### 4. Tool Refactoring (Implements Async)
- All heavy tools use background tasks
- Return task_id immediately
- Use `check_task(task_id)` to poll results

## Implementation Steps

### Step 1: Create ProcessManager
Location: `src/core/process_manager.py`
- Tracks active processes
- Kills orphaned processes
- Cleans up on startup

### Step 2: Update AsyncExecutor
Location: `src/core/async_executor.py`
- Add process group management
- Implement forced kill on timeout
- Return immediately on timeout

### Step 3: Fix Task Manager Integration
Location: `task_manager.py`
- Ensure tasks transition through states properly
- Link background execution to task manager
- Store results correctly

### Step 4: Refactor Heavy Tools
Tools to update:
- `nmap_scan` → Use background task
- `sqlmap_scan` → Use background task
- `gobuster_scan` → Use background task
- `subdomain_enum` → Use background task
- `nuclei_scan` → Use background task
- `hydra_attack` → Use background task
- `john_crack` → Use background task
- `metasploit_exploit` → Use background task

## Expected Behavior After Fix

### Before (Broken)
```
User: nmap_scan(target="example.com")
Server: [Blocks for 10 minutes]
Result: Timeout or crash
```

### After (Fixed)
```
User: nmap_scan(target="example.com")
Server: Returns immediately with task_id
User: check_task(task_id="nmap_12345")
Server: Returns status and partial results
User: [Wait 5 minutes]
User: check_task(task_id="nmap_12345")
Server: Returns complete results
```

## Testing Strategy

1. **Unit Tests**: Test ProcessManager cleanup
2. **Integration Tests**: Test AsyncExecutor with timeout
3. **End-to-End Tests**: Test full tool workflow
4. **Load Tests**: Verify no resource leaks

## Rollback Plan

If issues occur:
1. Stop the server: `pkill -f kali_mcp_server`
2. Kill all tool processes: `pkill -9 sqlmap nmap gobuster`
3. Revert to previous version
4. Restart: `./start_tactical.sh`

## Success Criteria

- ✅ Server doesn't crash on heavy tool execution
- ✅ Tasks transition through states properly
- ✅ No zombie processes after timeout
- ✅ Results stored correctly in session directory
- ✅ `check_task()` returns accurate status
- ✅ Multiple concurrent tasks work without interference
