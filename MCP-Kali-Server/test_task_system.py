#!/usr/bin/env python3
"""
Test script to verify that the TaskManager system is working correctly
"""

import asyncio
import sys
import os
import json

# Add the project root to the path so we can import the server modules
sys.path.insert(0, '/home/morningstar/Bureau/kali_mcp/MCP-Kali-Server')

from src.core.task_manager import TaskManager


async def test_task_lifecycle():
    """Test that tasks properly transition through their lifecycle states"""
    print("🧪 Testing TaskManager task lifecycle...")
    
    # Create a task manager
    manager = TaskManager()
    
    # Test task function that simulates work
    async def simulate_work(duration: int):
        await asyncio.sleep(duration)
        return f"Work completed after {duration} seconds"
    
    # Create a task
    task_id = manager.create_task("127.0.0.1", "test_tool", "test command")
    print(f"✅ Task created with ID: {task_id}")
    
    # Check initial status
    status = manager.get_task_status(task_id)
    print(f"📊 Initial status: {status['status']}")
    assert status['status'] == 'pending', f"Expected 'pending', got '{status['status']}'"
    
    # Start the task in background
    manager.start_background_task(task_id, simulate_work, 2)
    print("🚀 Task started in background")
    
    # Check status immediately after starting (might still be pending due to async scheduling)
    status = manager.get_task_status(task_id)
    print(f"📊 Status immediately after start: {status['status']}")
    
    # Wait a bit for the task to actually start running
    await asyncio.sleep(0.1)
    
    # Check status after a short delay
    status = manager.get_task_status(task_id)
    print(f"📊 Status after short delay: {status['status']}")
    
    # Wait for task to complete
    await asyncio.sleep(3)
    
    # Check final status
    status = manager.get_task_status(task_id)
    print(f"📊 Final status: {status['status']}")
    assert status['status'] == 'completed', f"Expected 'completed', got '{status['status']}'"
    
    # Check result
    result = manager.get_task_result(task_id)
    print(f"📄 Task result: {result}")
    assert result is not None, "Expected result to be present"
    assert "Work completed" in result, f"Expected result to contain 'Work completed', got '{result}'"
    
    print("✅ All task lifecycle tests passed!")
    return True


async def test_multiple_tasks():
    """Test that multiple tasks can run concurrently"""
    print("\n🧪 Testing multiple concurrent tasks...")
    
    manager = TaskManager()
    
    async def quick_task(name: str):
        await asyncio.sleep(1)
        return f"Quick task {name} completed"
    
    # Create multiple tasks
    task_ids = []
    for i in range(3):
        task_id = manager.create_task(f"target_{i}", "quick_test")
        task_ids.append(task_id)
        manager.start_background_task(task_id, quick_task, str(i))
        print(f"🚀 Started task {i+1}: {task_id}")
    
    # Wait for all tasks to complete
    await asyncio.sleep(2)
    
    # Check all tasks completed
    for i, task_id in enumerate(task_ids):
        status = manager.get_task_status(task_id)
        print(f"📊 Task {i+1} status: {status['status']}")
        assert status['status'] == 'completed', f"Task {i+1} should be completed"
        
        result = manager.get_task_result(task_id)
        print(f"📄 Task {i+1} result: {result}")
        assert result is not None, f"Task {i+1} should have a result"
    
    print("✅ All concurrent task tests passed!")
    return True


async def test_task_failure():
    """Test that failed tasks are properly handled"""
    print("\n🧪 Testing task failure handling...")
    
    manager = TaskManager()
    
    async def failing_task():
        raise Exception("This is a test failure")
    
    # Create and start a failing task
    task_id = manager.create_task("failing_target", "fail_test")
    manager.start_background_task(task_id, failing_task)
    print("🚀 Started failing task")
    
    # Wait for task to fail
    await asyncio.sleep(1)
    
    # Check status
    status = manager.get_task_status(task_id)
    print(f"📊 Failed task status: {status['status']}")
    assert status['status'] == 'failed', f"Expected 'failed', got '{status['status']}'"
    
    # Check error
    assert status['error'] is not None, "Expected error to be present"
    print(f"📄 Error message: {status['error']}")
    assert "test failure" in status['error'], f"Expected error to mention 'test failure', got '{status['error']}'"
    
    print("✅ Task failure handling test passed!")
    return True


async def main():
    """Run all tests"""
    print("🚀 Starting TaskManager System Tests")
    print("=" * 50)
    
    try:
        # Run all tests
        await test_task_lifecycle()
        await test_multiple_tasks()
        await test_task_failure()
        
        print("\n" + "=" * 50)
        print("🎉 ALL TASK MANAGER TESTS PASSED!")
        print("✅ The TaskManager system is working correctly")
        return True
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)