# MCP Kali Server - Recovery & Implementation Guide

## Overview

This document provides a complete guide to recovering the MCP Kali Server from crashes caused by heavy tool execution. The solution involves implementing background task execution using the existing TaskManager and AsyncExecutor infrastructure.

## Problem Statement

The server crashes when running heavy tools (Nmap, SQLMap, Gobuster, etc.) because:

1. **Event Loop Blocking**: Tools execute synchronously, blocking the async event loop
2. **Timeout Cascades**: Multiple timeouts cause resource exhaustion
3. **Zombie Processes**: Orphaned processes accumulate when requests timeout
4. **No Task Tracking**: Users can't check progress or cancel tasks

## Solution Overview

Implement background task execution by:

1. Creating tasks immediately and returning task_id
2. Running tool execution in the background
3. Allowing users to check progress with check_task()
4. Properly cleaning up processes on timeout

## Documentation Structure

### Quick Reference
- **QUICK_START_RECOVERY.md** - TL;DR version, start here
- **CURRENT_STATUS.md** - Detailed analysis of current state

### Implementation
- **CODE_CHANGES_REQUIRED.md** - Exact code changes needed
- **IMPLEMENTATION_GUIDE.md** - Step-by-step implementation guide
- **ARCHITECTURE_DIAGRAM.md** - Visual diagrams of architecture

### Planning
- **SERVER_RECOVERY_PLAN.md** - High-level recovery plan
- **README_RECOVERY.md** - This file

## Key Components

### TaskManager (`src/core/task_manager.py`)
- ✅ Already implemented
- Tracks background tasks
- Manages task lifecycle
- Stores results

### AsyncExecutor (`src/core/async_executor.py`)
- ✅ Already implemented
- Runs commands asynchronously
- Handles timeouts with process group cleanup
- No event loop blocking

### Background Execution
- ❌ Not yet implemented
- Need to refactor tools to use background execution
- Need to add task management tools

## Implementation Roadmap

### Phase 1: Add Task Management Tools (30 minutes)
```python
- check_task(task_id)      # Check task status
- list_tasks(status)       # List all tasks
- cancel_task(task_id)     # Cancel a task
- get_task_stats()         # Get statistics
```

### Phase 2: Refactor Heavy Tools (2-3 hours)
```python
# For each tool:
- nmap_scan
- sqlmap_scan
- gobuster_scan
- subdomain_enum
- nuclei_scan
- hydra_attack
- john_crack
- nikto_scan
- metasploit_exploit
```

### Phase 3: Testing (1-2 hours)
```python
- Unit tests for background execution
- Integration tests for concurrent tasks
- Load tests for resource usage
- Timeout tests for proper cleanup
```

### Phase 4: Documentation (30 minutes)
```
- Update README with new workflow
- Add examples for background task usage
- Document task status transitions
- Add troubleshooting guide
```

## Expected Behavior After Implementation

### Before (Broken)
```
User: nmap_scan("example.com")
Server: [Blocks for 10 minutes]
Result: Timeout or crash ❌
```

### After (Fixed)
```
User: nmap_scan("example.com")
Server: Returns {"task_id": "abc123"} immediately ✅

User: check_task("abc123")
Server: Returns {"status": "running", "progress": 45} ✅

User: [Wait 5 minutes]
User: check_task("abc123")
Server: Returns {"status": "completed", "result": {...}} ✅
```

## File Changes Summary

### Modified Files
- `kali_mcp_server_v3.py` - Add task management tools and refactor heavy tools

### New Files
- None required (infrastructure already exists)

### Unchanged Files
- `src/core/task_manager.py` - Already correct
- `src/core/async_executor.py` - Already correct
- All other files - No changes needed

## Testing Checklist

- [ ] Server starts without errors
- [ ] check_task() tool works
- [ ] list_tasks() tool works
- [ ] cancel_task() tool works
- [ ] get_task_stats() tool works
- [ ] nmap_scan() returns task_id immediately
- [ ] check_task() shows running status
- [ ] After completion, check_task() shows results
- [ ] Multiple concurrent tasks work
- [ ] No zombie processes after timeout
- [ ] Memory usage stable
- [ ] CPU usage reasonable

## Deployment Steps

1. **Backup current version**
   ```bash
   cp kali_mcp_server_v3.py kali_mcp_server_v3.py.backup
   ```

2. **Implement changes**
   - Follow CODE_CHANGES_REQUIRED.md
   - Add task management tools
   - Refactor heavy tools

3. **Test locally**
   ```bash
   python3 test_background_tasks.py
   ```

4. **Deploy to production**
   ```bash
   ./start_tactical.sh
   ```

5. **Monitor**
   - Check server logs
   - Monitor resource usage
   - Verify task completion

## Rollback Plan

If issues occur:
```bash
# 1. Stop server
pkill -f kali_mcp_server

# 2. Kill processes
pkill -9 sqlmap nmap gobuster

# 3. Restore backup
cp kali_mcp_server_v3.py.backup kali_mcp_server_v3.py

# 4. Restart
./start_tactical.sh
```

## Success Metrics

After implementation:
- ✅ Server handles 10+ concurrent heavy tool executions
- ✅ No crashes or timeouts
- ✅ Tasks complete successfully
- ✅ Results stored correctly
- ✅ No zombie processes
- ✅ Memory usage stable
- ✅ CPU usage reasonable

## FAQ

### Q: Why not just increase timeouts?
A: Timeouts don't solve the problem. The event loop is still blocked, and other requests will timeout while waiting.

### Q: Why not run tools in separate processes?
A: We already do! The AsyncExecutor uses `asyncio.create_subprocess_shell()` which runs in a separate process. The problem is we wait for it synchronously.

### Q: Will this break existing workflows?
A: Yes, but in a good way. Tools will return immediately instead of blocking. Users need to use `check_task()` to get results.

### Q: How long will tasks take?
A: Same as before. Nmap still takes 10 minutes, SQLMap still takes 20 minutes. But now the server won't crash while waiting.

### Q: Can I still run quick tools synchronously?
A: Yes! Quick tools (< 30 seconds) can still run synchronously. Only heavy tools need background execution.

### Q: What if a task fails?
A: The task status will be "failed" and the error will be stored in task.error. Use check_task() to see the error.

### Q: Can I cancel a running task?
A: Yes! Use cancel_task(task_id) to cancel a running or pending task.

### Q: How many concurrent tasks can the server handle?
A: Default is 10 concurrent tasks. This can be configured in TaskManager initialization.

## Performance Expectations

### Before (Broken)
- Response time: 10+ minutes (blocked)
- Concurrent tasks: 1
- Server crashes: Yes
- Memory leaks: Yes

### After (Fixed)
- Response time: < 100ms (immediate)
- Concurrent tasks: 10+
- Server crashes: No
- Memory leaks: No

## Resource Requirements

### CPU
- Before: 100% during scan (blocked)
- After: 5-10% for server, 50-80% for background tools

### Memory
- Before: Grows over time (leaks)
- After: Stable, ~200MB base + tool overhead

### Network
- Before: Blocked during scan
- After: Responsive, can handle multiple requests

## Monitoring

### Check Server Health
```bash
curl http://localhost:8000/server_health
```

### Check Task Status
```bash
curl http://localhost:8000/check_task?task_id=abc123
```

### List All Tasks
```bash
curl http://localhost:8000/list_tasks
```

### Get Task Statistics
```bash
curl http://localhost:8000/get_task_stats
```

## Support

For issues or questions:
1. Check CURRENT_STATUS.md for analysis
2. Review CODE_CHANGES_REQUIRED.md for implementation details
3. Check ARCHITECTURE_DIAGRAM.md for visual explanation
4. Review server logs for errors

## Timeline

- **Phase 1** (Add tools): 30 minutes
- **Phase 2** (Refactor tools): 2-3 hours
- **Phase 3** (Testing): 1-2 hours
- **Phase 4** (Documentation): 30 minutes
- **Total**: 4-6 hours

## Conclusion

The MCP Kali Server has all the infrastructure needed to handle background tasks. This recovery guide provides a step-by-step implementation plan to enable background execution and prevent server crashes.

The solution is:
- ✅ Low risk (infrastructure already exists)
- ✅ High impact (prevents crashes)
- ✅ Well documented (multiple guides)
- ✅ Easy to implement (follow the template)
- ✅ Easy to test (provided test script)
- ✅ Easy to rollback (backup provided)

---

**Document Version**: 1.0
**Last Updated**: December 22, 2025
**Status**: Ready for implementation
**Estimated Completion**: 4-6 hours
**Difficulty**: Medium
**Risk Level**: Low
