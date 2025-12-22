#!/usr/bin/env python3
"""
Test script to verify that the Nmap task issue has been fixed
"""

import asyncio
import sys
import os
import json

# Add the project root to the path so we can import the server modules
sys.path.insert(0, '/home/morningstar/Bureau/kali_mcp/MCP-Kali-Server')

from src.core.task_manager import TaskManager


async def test_nmap_task_fix():
    """Test that Nmap tasks properly transition through their lifecycle states"""
    print("🧪 Testing Nmap Task Fix...")
    
    # Create a task manager
    manager = TaskManager()
    
    # Test Nmap-like background function
    async def simulate_nmap_scan(task_id: str, target: str, scan_type: str, ports: str, intensity: str, timeout: int):
        """Simulate what _run_nmap_background does"""
        print(f"🔬 Simulating Nmap scan for {target} with scan_type={scan_type}")
        
        # Simulate some work
        await asyncio.sleep(2)
        
        # Format result like the real Nmap function would
        formatted_result = {
            "stdout": f"Starting Nmap scan for {target}\nNmap scan report for {target}\nHost is up.\nPORT    STATE SERVICE\n80/tcp  open  http\n443/tcp open  https\n\nDone.",
            "stderr": "",
            "return_code": 0,
            "command": f"nmap -sV -sC -T3 {target}"
        }
        
        # Store result in task manager (like the real function does)
        # The real function stores the JSON string directly
        result_json = json.dumps(formatted_result, indent=2)
        if task_id in manager.tasks:
            manager.tasks[task_id].complete(result_json)
        
        return result_json
    
    # Create an Nmap task like the real nmap_scan tool does
    target = "127.0.0.1"
    task_id = manager.create_task(target, "nmap")
    print(f"✅ Nmap task created with ID: {task_id}")
    
    # Check initial status
    status = manager.get_task_status(task_id)
    print(f"📊 Initial status: {status['status']}")
    assert status['status'] == 'pending', f"Expected 'pending', got '{status['status']}'"
    
    # Start the task in background like the real nmap_scan tool does
    manager.start_background_task(
        task_id, 
        simulate_nmap_scan,
        task_id, target, "comprehensive", None, "medium", 900
    )
    print("🚀 Nmap task started in background")
    
    # Check status immediately after starting (might still be pending due to async scheduling)
    status = manager.get_task_status(task_id)
    print(f"📊 Status immediately after start: {status['status']}")
    
    # Wait a bit for the task to actually start running
    await asyncio.sleep(0.1)
    
    # Check status after a short delay
    status = manager.get_task_status(task_id)
    print(f"📊 Status after short delay: {status['status']}")
    assert status['status'] == 'running', f"Expected 'running', got '{status['status']}'"
    
    # Wait for task to complete
    await asyncio.sleep(3)
    
    # Check final status
    status = manager.get_task_status(task_id)
    print(f"📊 Final status: {status['status']}")
    assert status['status'] == 'completed', f"Expected 'completed', got '{status['status']}'"
    
    # Check result
    result = manager.get_task_result(task_id)
    print(f"📄 Task result preview: {repr(result[:100])}..." if result else "No result")
    assert result is not None, "Expected result to be present"
    
    # Print the full result for debugging
    print(f"📄 Full result: {repr(result)}")
    
    # The result should already be a JSON string (as the real Nmap function stores it)
    # Just verify it's not empty and looks like JSON
    assert result.startswith("{") and result.endswith("}"), "Result should be a JSON string"
    
    # Parse the result to make sure it's valid JSON
    try:
        parsed_result = json.loads(result)
        print(f"✅ Result is valid JSON with keys: {list(parsed_result.keys())}")
        assert "stdout" in parsed_result, "Result should contain stdout"
        assert "stderr" in parsed_result, "Result should contain stderr"
        assert "return_code" in parsed_result, "Result should contain return_code"
    except json.JSONDecodeError as e:
        print(f"❌ JSON decode error: {e}")
        assert False, "Result should be valid JSON"
    
    print("✅ Nmap task fix verification passed!")
    return True


async def main():
    """Run the Nmap task fix test"""
    print("🚀 Starting Nmap Task Fix Verification")
    print("=" * 50)
    
    try:
        # Run the test
        await test_nmap_task_fix()
        
        print("\n" + "=" * 50)
        print("🎉 NMAP TASK FIX VERIFICATION PASSED!")
        print("✅ The Nmap task system is working correctly")
        print("✅ Tasks properly transition from pending → running → completed")
        return True
        
    except Exception as e:
        print(f"\n❌ VERIFICATION FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)