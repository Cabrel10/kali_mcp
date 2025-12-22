# Architecture Diagram - Server Recovery

## Current Architecture (Broken)

```
┌─────────────────────────────────────────────────────────────┐
│                    MCP Server (FastMCP)                      │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Tool: nmap_scan(target)                             │   │
│  │                                                       │   │
│  │  1. Receive request                                  │   │
│  │  2. Call executor.run_command("nmap ...")            │   │
│  │  3. ❌ BLOCK HERE FOR 10 MINUTES                     │   │
│  │  4. Return result                                    │   │
│  │                                                       │   │
│  │  Problem: Event loop blocked!                        │   │
│  │  Other requests timeout while waiting                │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  AsyncExecutor                                       │   │
│  │  - Runs command in subprocess                        │   │
│  │  - Handles timeout with process group cleanup        │   │
│  │  - Returns result                                    │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ❌ TaskManager (Not Used)                                   │
│  ❌ Background Execution (Not Used)                          │
│                                                               │
└─────────────────────────────────────────────────────────────┘

Result: Server crashes on heavy tool execution
```

## Fixed Architecture (Proposed)

```
┌─────────────────────────────────────────────────────────────┐
│                    MCP Server (FastMCP)                      │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Tool: nmap_scan(target, background=True)            │   │
│  │                                                       │   │
│  │  1. Receive request                                  │   │
│  │  2. Create task: task_id = tasks.create_task(...)    │   │
│  │  3. Start background: tasks.start_background_task()  │   │
│  │  4. ✅ RETURN IMMEDIATELY with task_id              │   │
│  │                                                       │   │
│  │  Result: {"task_id": "abc123", "status": "..."}      │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Tool: check_task(task_id)                           │   │
│  │                                                       │   │
│  │  1. Receive request                                  │   │
│  │  2. Get task status: tasks.get_task_status(task_id)  │   │
│  │  3. ✅ RETURN IMMEDIATELY with status               │   │
│  │                                                       │   │
│  │  Result: {"status": "running", "progress": 45}       │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  TaskManager                                         │   │
│  │  - Tracks background tasks                           │   │
│  │  - Manages task lifecycle                            │   │
│  │  - Stores results                                    │   │
│  │  - ✅ NOW USED                                       │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  AsyncExecutor                                       │   │
│  │  - Runs command in subprocess                        │   │
│  │  - Handles timeout with process group cleanup        │   │
│  │  - Returns result                                    │   │
│  │  - ✅ NOW USED FOR BACKGROUND EXECUTION              │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Background Task Execution (asyncio.create_task)     │   │
│  │  - Runs _run_nmap_background() in background         │   │
│  │  - Doesn't block event loop                          │   │
│  │  - Updates task status as it progresses              │   │
│  │  - Stores results when complete                      │   │
│  │  - ✅ NOW IMPLEMENTED                                │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
└─────────────────────────────────────────────────────────────┘

Result: Server handles multiple concurrent tasks without crashing
```

## Task Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│                    Task Lifecycle                            │
└─────────────────────────────────────────────────────────────┘

1. CREATE
   ┌──────────────────────────────────────────────────────┐
   │ tasks.create_task(target, "nmap")                    │
   │ Returns: task_id = "abc123"                          │
   │ Status: PENDING                                      │
   └──────────────────────────────────────────────────────┘
                          ↓

2. START BACKGROUND
   ┌──────────────────────────────────────────────────────┐
   │ tasks.start_background_task(task_id, func, args)     │
   │ Creates asyncio.Task for background execution        │
   │ Status: PENDING (not yet started)                    │
   └──────────────────────────────────────────────────────┘
                          ↓

3. RUNNING
   ┌──────────────────────────────────────────────────────┐
   │ Background function starts executing                 │
   │ task.start() called                                  │
   │ Status: RUNNING                                      │
   │ Progress: 0-100%                                     │
   └──────────────────────────────────────────────────────┘
                          ↓

4. COMPLETED
   ┌──────────────────────────────────────────────────────┐
   │ Background function finishes                         │
   │ task.complete(result) called                         │
   │ Status: COMPLETED                                    │
   │ Progress: 100%                                       │
   │ Result: Stored in task.result                        │
   └──────────────────────────────────────────────────────┘

Alternative paths:
- FAILED: task.fail(error) if exception occurs
- CANCELLED: task.cancel() if user cancels
- TIMEOUT: task.fail("timeout") if timeout exceeded
```

## Request Flow - Before (Broken)

```
User Request
    ↓
┌─────────────────────────────────────────────────────────────┐
│ nmap_scan("example.com")                                    │
│                                                              │
│ 1. Receive request                                          │
│ 2. Build nmap command                                       │
│ 3. await executor.run_command(cmd, timeout=900)             │
│    ↓                                                         │
│    ┌──────────────────────────────────────────────────────┐ │
│    │ AsyncExecutor.run_command()                          │ │
│    │                                                       │ │
│    │ 1. Create subprocess                                 │ │
│    │ 2. await process.communicate()                       │ │
│    │    ↓                                                  │ │
│    │    ┌────────────────────────────────────────────┐   │ │
│    │    │ Nmap running in subprocess                 │   │ │
│    │    │ [████████████████████████████] 10 minutes  │   │ │
│    │    │                                            │   │ │
│    │    │ ❌ EVENT LOOP BLOCKED HERE                 │   │ │
│    │    │ Other requests timeout!                    │   │ │
│    │    └────────────────────────────────────────────┘   │ │
│    │ 3. Return result                                     │ │
│    └──────────────────────────────────────────────────────┘ │
│ 4. Parse result                                             │
│ 5. Return to user                                           │
│                                                              │
│ Total time: 10+ minutes                                     │
│ Server status: BLOCKED                                      │
└─────────────────────────────────────────────────────────────┘
    ↓
User Response (after 10+ minutes or timeout)
```

## Request Flow - After (Fixed)

```
User Request 1: nmap_scan("example.com")
    ↓
┌─────────────────────────────────────────────────────────────┐
│ nmap_scan("example.com", background=True)                   │
│                                                              │
│ 1. Receive request                                          │
│ 2. task_id = tasks.create_task("example.com", "nmap")       │
│ 3. tasks.start_background_task(task_id, _run_nmap_bg, ...)  │
│    ↓                                                         │
│    ┌──────────────────────────────────────────────────────┐ │
│    │ asyncio.create_task() - Returns immediately          │ │
│    │ Background execution scheduled                       │ │
│    │ ✅ EVENT LOOP NOT BLOCKED                            │ │
│    └──────────────────────────────────────────────────────┘ │
│ 4. Return {"task_id": "abc123", "status": "background..."}  │
│                                                              │
│ Total time: < 100ms                                         │
│ Server status: READY FOR NEXT REQUEST                       │
└─────────────────────────────────────────────────────────────┘
    ↓
User Response 1 (immediately): {"task_id": "abc123"}

---

Meanwhile, background execution continues:
    ↓
┌─────────────────────────────────────────────────────────────┐
│ _run_nmap_background() [Running in background]              │
│                                                              │
│ 1. task.start()                                             │
│ 2. await executor.run_command(cmd, timeout=900)             │
│    ↓                                                         │
│    ┌────────────────────────────────────────────────────┐  │
│    │ Nmap running in subprocess                         │  │
│    │ [████████████████████████████] 10 minutes          │  │
│    │                                                    │  │
│    │ ✅ EVENT LOOP NOT BLOCKED                          │  │
│    │ Other requests processed normally!                 │  │
│    └────────────────────────────────────────────────────┘  │
│ 3. task.complete(result)                                    │
│ 4. Result stored in task.result                             │
│                                                              │
│ Total time: 10 minutes (same as before)                     │
│ Server status: RESPONSIVE                                   │
└─────────────────────────────────────────────────────────────┘

---

User Request 2: check_task("abc123")
    ↓
┌─────────────────────────────────────────────────────────────┐
│ check_task("abc123")                                        │
│                                                              │
│ 1. Receive request                                          │
│ 2. status = tasks.get_task_status("abc123")                 │
│ 3. Return {"status": "running", "progress": 45}             │
│                                                              │
│ Total time: < 10ms                                          │
│ Server status: RESPONSIVE                                   │
└─────────────────────────────────────────────────────────────┘
    ↓
User Response 2 (immediately): {"status": "running", "progress": 45}

---

After 10 minutes:

User Request 3: check_task("abc123")
    ↓
┌─────────────────────────────────────────────────────────────┐
│ check_task("abc123")                                        │
│                                                              │
│ 1. Receive request                                          │
│ 2. status = tasks.get_task_status("abc123")                 │
│ 3. Return {"status": "completed", "result": {...}}          │
│                                                              │
│ Total time: < 10ms                                          │
│ Server status: RESPONSIVE                                   │
└─────────────────────────────────────────────────────────────┘
    ↓
User Response 3 (immediately): {"status": "completed", "result": {...}}
```

## Concurrent Tasks

```
Timeline:

T=0s:   User 1: nmap_scan("192.168.1.1")
        ↓
        Server: Returns task_id="task1" immediately ✅
        Background: Start nmap for 192.168.1.1

T=1s:   User 2: sqlmap_scan("example.com")
        ↓
        Server: Returns task_id="task2" immediately ✅
        Background: Start sqlmap for example.com
        Background: nmap still running (1/10 minutes)

T=2s:   User 3: gobuster_scan("example.com")
        ↓
        Server: Returns task_id="task3" immediately ✅
        Background: Start gobuster for example.com
        Background: nmap still running (1/10 minutes)
        Background: sqlmap still running (1/20 minutes)

T=5s:   User 4: check_task("task1")
        ↓
        Server: Returns {"status": "running", "progress": 50} immediately ✅
        Background: nmap still running (5/10 minutes)
        Background: sqlmap still running (5/20 minutes)
        Background: gobuster still running (5/5 minutes)

T=10m:  Background: nmap completes
        Background: gobuster completes
        Task 1 & 3: COMPLETED

T=20m:  Background: sqlmap completes
        Task 2: COMPLETED

Result: All 3 heavy tools ran concurrently without blocking server ✅
```

## Key Improvements

```
┌─────────────────────────────────────────────────────────────┐
│                    Before vs After                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│ Metric              │ Before      │ After                   │
│ ─────────────────────┼─────────────┼──────────────────────  │
│ Response Time       │ 10+ minutes │ < 100ms                │
│ Event Loop Blocked  │ Yes ❌      │ No ✅                  │
│ Concurrent Tasks    │ 1           │ 10+                    │
│ Server Crashes      │ Yes ❌      │ No ✅                  │
│ Zombie Processes    │ Yes ❌      │ No ✅                  │
│ Memory Leaks        │ Yes ❌      │ No ✅                  │
│ Task Tracking       │ No ❌       │ Yes ✅                 │
│ Progress Monitoring │ No ❌       │ Yes ✅                 │
│ Task Cancellation   │ No ❌       │ Yes ✅                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

**Diagram Version**: 1.0
**Last Updated**: December 22, 2025
**Status**: Ready for implementation
