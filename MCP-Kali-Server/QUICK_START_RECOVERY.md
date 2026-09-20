# Quick Start - Server Recovery

## TL;DR

The server crashes because heavy tools block the event loop. The fix is to make them run in the background and return a task_id immediately.

## What's Broken

```
User: nmap_scan("example.com")
Server: [Blocks for 10 minutes]
Result: Timeout or crash ❌
```

## What We're Fixing

```
User: nmap_scan("example.com")
Server: Returns {"task_id": "abc123"} immediately ✅
User: check_task("abc123")
Server: Returns {"status": "running", "progress": 45} ✅
User: [Wait 5 minutes]
User: check_task("abc123")
Server: Returns {"status": "completed", "result": {...}} ✅
```

## Implementation Overview

### 1. Add Task Management Tools (5 minutes)
```python
# New tools to add:
- check_task(task_id)      # Check task status
- list_tasks(status)       # List all tasks
- cancel_task(task_id)     # Cancel a task
- get_task_stats()         # Get statistics
```

### 2. Refactor Heavy Tools (2-3 hours)
```python
# For each heavy tool (nmap, sqlmap, gobuster, etc.):
# 1. Create background function: _run_<tool>_background()
# 2. Update main tool to create task and return immediately
# 3. Move execution logic to background function
```

### 3. Test (1-2 hours)
```python
# Test:
- Single background task
- Multiple concurrent tasks
- Task status transitions
- Timeout and cleanup
```

## Files to Modify

1. **kali_mcp_server_v3.py** - Main server file
   - Add imports for TaskManager and AsyncExecutor
   - Add task management tools
   - Refactor heavy tools

2. **No other files need modification** - Infrastructure is already in place!

## Key Concepts

### TaskManager
- Tracks background tasks
- Manages task lifecycle (pending → running → completed)
- Stores results

### AsyncExecutor
- Runs commands asynchronously
- Handles timeouts with process group cleanup
- No blocking of event loop

### Background Execution Pattern
```python
# 1. Create task
task_id = tasks.create_task(target, "tool_name")

# 2. Start background execution
tasks.start_background_task(
    task_id,
    _run_tool_background,
    # ... parameters ...
)

# 3. Return immediately
return json.dumps({"task_id": task_id, "status": "background_started"})

# 4. User checks status later
check_task(task_id)  # Returns current status
```

## Expected Results After Fix

### Server Stability
- ✅ No crashes on heavy tool execution
- ✅ Handles 10+ concurrent tasks
- ✅ No zombie processes
- ✅ Memory usage stable

### User Experience
- ✅ Tools return immediately
- ✅ Can check progress with check_task()
- ✅ Can cancel tasks with cancel_task()
- ✅ Can list all tasks with list_tasks()

### Resource Usage
- ✅ Event loop not blocked
- ✅ Other requests processed normally
- ✅ CPU usage reasonable
- ✅ Memory usage stable

## Rollback Plan

If something goes wrong:
```bash
# 1. Stop server
pkill -f kali_mcp_server

# 2. Kill processes
pkill -9 sqlmap nmap gobuster

# 3. Revert changes
git checkout HEAD -- kali_mcp_server_v3.py

# 4. Restart
./start_tactical.sh
```

## Success Criteria

After implementation, verify:
1. Server starts without errors
2. check_task() tool works
3. nmap_scan() returns task_id immediately
4. check_task() shows running status
5. After completion, check_task() shows results
6. No zombie processes after timeout
7. Multiple concurrent tasks work

## Next Steps

1. **Review** the CURRENT_STATUS.md and CODE_CHANGES_REQUIRED.md
2. **Implement** the changes following the template
3. **Test** with the provided test script
4. **Deploy** to production
5. **Monitor** for issues

## Questions?

- **Why background tasks?** - Event loop can't be blocked by long-running commands
- **Why task_id?** - Allows user to check progress without blocking
- **Will this break existing code?** - Yes, but in a good way. Tools return immediately instead of blocking.
- **Can I still run quick tools?** - Yes, set background=False for quick tools
- **How long will tasks take?** - Same as before. Nmap still takes 10 minutes, but server won't crash.

## Timeline

- **Phase 1** (Add tools): 30 minutes
- **Phase 2** (Refactor tools): 2-3 hours
- **Phase 3** (Testing): 1-2 hours
- **Total**: 4-6 hours

## Resources

- CURRENT_STATUS.md - Detailed analysis
- CODE_CHANGES_REQUIRED.md - Exact code changes
- IMPLEMENTATION_GUIDE.md - Step-by-step guide
- SERVER_RECOVERY_PLAN.md - Architecture overview

---

**Status**: Ready for implementation
**Last Updated**: December 22, 2025
**Estimated Completion**: December 22, 2025 (6 hours)
