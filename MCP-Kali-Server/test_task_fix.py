#!/usr/bin/env python3
"""
Test script to verify that the task manager fixes work correctly
"""

import asyncio
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.core.task_manager import TaskManager

async def test_task_manager():
    """Test the task manager functionality"""
    print("Testing TaskManager fixes...")
    
    # Create a task manager instance
    tasks = TaskManager()
    
    # Test creating a task
    task_id = tasks.create_task("test_target", "test_tool")
    print(f"Created task with ID: {task_id}")
    
    # Check task status
    status = tasks.get_task_status(task_id)
    print(f"Task status: {status['status']}")
    
    # Test starting a background task
    async def dummy_task():
        await asyncio.sleep(1)
        return "Task completed successfully"
    
    # Start the background task using the proper method
    future = tasks.start_background_task(task_id, dummy_task)
    print("Started background task")
    
    # Wait for the task to complete
    await future
    
    # Check final status
    status = tasks.get_task_status(task_id)
    print(f"Final task status: {status['status']}")
    
    if status['status'] == 'completed':
        print("✅ Task manager fixes are working correctly!")
        return True
    else:
        print("❌ Task manager fixes are not working correctly!")
        return False

if __name__ == "__main__":
    result = asyncio.run(test_task_manager())
    sys.exit(0 if result else 1)