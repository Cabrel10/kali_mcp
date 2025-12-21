#!/usr/bin/env python3
"""
Task Manager - Manages asynchronous long-running tasks
Prevents LLM timeouts by running scans in background
"""

import asyncio
import time
import hashlib
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime
from enum import Enum


class TaskStatus(Enum):
    """Status of a background task"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class Task:
    """Represents a background task"""
    
    def __init__(
        self,
        task_id: str,
        target: str,
        tool: str,
        command: str = ""
    ):
        self.task_id = task_id
        self.target = target
        self.tool = tool
        self.command = command
        self.status = TaskStatus.PENDING
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.result: Optional[str] = None
        self.error: Optional[str] = None
        self.progress: int = 0  # 0-100
    
    def start(self):
        """Mark task as started"""
        self.status = TaskStatus.RUNNING
        self.start_time = time.time()
    
    def complete(self, result: str):
        """Mark task as completed with result"""
        self.status = TaskStatus.COMPLETED
        self.end_time = time.time()
        self.result = result
        self.progress = 100
    
    def fail(self, error: str):
        """Mark task as failed with error"""
        self.status = TaskStatus.FAILED
        self.end_time = time.time()
        self.error = error
    
    def cancel(self):
        """Mark task as cancelled"""
        self.status = TaskStatus.CANCELLED
        self.end_time = time.time()
    
    def get_elapsed_time(self) -> float:
        """Get elapsed time in seconds"""
        if not self.start_time:
            return 0.0
        
        end = self.end_time or time.time()
        return end - self.start_time
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary"""
        return {
            'task_id': self.task_id,
            'target': self.target,
            'tool': self.tool,
            'status': self.status.value,
            'progress': self.progress,
            'elapsed_time': round(self.get_elapsed_time(), 2),
            'start_time': datetime.fromtimestamp(self.start_time).isoformat() if self.start_time else None,
            'end_time': datetime.fromtimestamp(self.end_time).isoformat() if self.end_time else None,
            'result': self.result[:500] if self.result else None,  # Truncate result
            'error': self.error
        }


class TaskManager:
    """
    Manages background tasks for long-running operations
    Prevents LLM timeouts and allows checking task status later
    """
    
    def __init__(self, max_concurrent_tasks: int = 10):
        """
        Initialize task manager
        
        Args:
            max_concurrent_tasks: Maximum number of concurrent tasks
        """
        self.tasks: Dict[str, Task] = {}
        self.max_concurrent_tasks = max_concurrent_tasks
        self._task_futures: Dict[str, asyncio.Task] = {}
        self._cleanup_interval = 3600  # Cleanup old tasks every hour
        self._last_cleanup = time.time()
    
    def create_task(
        self,
        target: str,
        tool: str,
        command: str = "",
        custom_id: Optional[str] = None
    ) -> str:
        """
        Create a new task and return its ID
        
        Args:
            target: Target (IP, domain, URL)
            tool: Tool name
            command: Optional command being executed
            custom_id: Optional custom task ID
            
        Returns:
            Task ID
        """
        # Generate unique task ID
        if custom_id:
            task_id = custom_id
        else:
            unique_str = f"{target}{tool}{time.time()}"
            task_id = hashlib.md5(unique_str.encode()).hexdigest()[:12]
        
        # Create task object
        task = Task(task_id, target, tool, command)
        self.tasks[task_id] = task
        
        # Cleanup old tasks if needed
        self._maybe_cleanup()
        
        return task_id
    
    async def run_task(
        self,
        task_id: str,
        async_func: Callable,
        *args,
        **kwargs
    ):
        """
        Execute a task asynchronously
        
        Args:
            task_id: Task ID
            async_func: Async function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function
        """
        task = self.tasks.get(task_id)
        if not task:
            raise ValueError(f"Task {task_id} not found")
        
        # Mark as started
        task.start()
        
        try:
            # Execute the async function
            result = await async_func(*args, **kwargs)
            
            # Mark as completed
            task.complete(str(result))
        
        except Exception as e:
            # Mark as failed
            task.fail(str(e))
    
    def start_background_task(
        self,
        task_id: str,
        async_func: Callable,
        *args,
        **kwargs
    ) -> asyncio.Task:
        """
        Start a task in the background without waiting
        
        Args:
            task_id: Task ID
            async_func: Async function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            asyncio.Task object
        """
        # Create asyncio task
        future = asyncio.create_task(
            self.run_task(task_id, async_func, *args, **kwargs)
        )
        
        self._task_futures[task_id] = future
        
        return future
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the status of a task
        
        Args:
            task_id: Task ID
            
        Returns:
            Dictionary with task status or None if not found
        """
        task = self.tasks.get(task_id)
        
        if not task:
            return None
        
        return task.to_dict()
    
    def get_task_result(self, task_id: str) -> Optional[str]:
        """
        Get the result of a completed task
        
        Args:
            task_id: Task ID
            
        Returns:
            Task result or None
        """
        task = self.tasks.get(task_id)
        
        if not task or task.status != TaskStatus.COMPLETED:
            return None
        
        return task.result
    
    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a running task
        
        Args:
            task_id: Task ID
            
        Returns:
            True if cancelled, False if not found or already finished
        """
        task = self.tasks.get(task_id)
        
        if not task or task.status not in [TaskStatus.PENDING, TaskStatus.RUNNING]:
            return False
        
        # Cancel the asyncio future
        future = self._task_futures.get(task_id)
        if future and not future.done():
            future.cancel()
        
        # Mark task as cancelled
        task.cancel()
        
        return True
    
    def list_tasks(
        self,
        status_filter: Optional[TaskStatus] = None,
        tool_filter: Optional[str] = None,
        target_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List all tasks with optional filters
        
        Args:
            status_filter: Filter by status
            tool_filter: Filter by tool name
            target_filter: Filter by target
            
        Returns:
            List of task dictionaries
        """
        tasks = []
        
        for task in self.tasks.values():
            # Apply filters
            if status_filter and task.status != status_filter:
                continue
            if tool_filter and task.tool != tool_filter:
                continue
            if target_filter and task.target != target_filter:
                continue
            
            tasks.append(task.to_dict())
        
        # Sort by start time (most recent first)
        tasks.sort(key=lambda x: x['start_time'] or '', reverse=True)
        
        return tasks
    
    def get_running_tasks_count(self) -> int:
        """Get count of currently running tasks"""
        return sum(1 for task in self.tasks.values() if task.status == TaskStatus.RUNNING)
    
    def can_start_new_task(self) -> bool:
        """Check if a new task can be started"""
        return self.get_running_tasks_count() < self.max_concurrent_tasks
    
    def cleanup_old_tasks(self, max_age_seconds: int = 86400):
        """
        Remove old completed/failed tasks
        
        Args:
            max_age_seconds: Maximum age in seconds (default 24 hours)
        """
        current_time = time.time()
        tasks_to_remove = []
        
        for task_id, task in self.tasks.items():
            # Only cleanup finished tasks
            if task.status not in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
                continue
            
            # Check age
            if task.end_time and (current_time - task.end_time) > max_age_seconds:
                tasks_to_remove.append(task_id)
        
        # Remove old tasks
        for task_id in tasks_to_remove:
            del self.tasks[task_id]
            if task_id in self._task_futures:
                del self._task_futures[task_id]
        
        return len(tasks_to_remove)
    
    def _maybe_cleanup(self):
        """Cleanup old tasks if enough time has passed"""
        current_time = time.time()
        
        if (current_time - self._last_cleanup) > self._cleanup_interval:
            self.cleanup_old_tasks()
            self._last_cleanup = current_time
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about tasks"""
        stats = {
            'total_tasks': len(self.tasks),
            'running': 0,
            'completed': 0,
            'failed': 0,
            'pending': 0,
            'cancelled': 0,
            'by_tool': {}
        }
        
        for task in self.tasks.values():
            # Count by status
            if task.status == TaskStatus.RUNNING:
                stats['running'] += 1
            elif task.status == TaskStatus.COMPLETED:
                stats['completed'] += 1
            elif task.status == TaskStatus.FAILED:
                stats['failed'] += 1
            elif task.status == TaskStatus.PENDING:
                stats['pending'] += 1
            elif task.status == TaskStatus.CANCELLED:
                stats['cancelled'] += 1
            
            # Count by tool
            tool = task.tool
            stats['by_tool'][tool] = stats['by_tool'].get(tool, 0) + 1
        
        return stats
    
    def clear_all_tasks(self):
        """Clear all tasks (use with caution)"""
        # Cancel all running tasks
        for task_id in list(self.tasks.keys()):
            self.cancel_task(task_id)
        
        self.tasks.clear()
        self._task_futures.clear()


# Singleton instance
_task_manager_instance: Optional[TaskManager] = None


def get_task_manager() -> TaskManager:
    """Get or create singleton TaskManager instance"""
    global _task_manager_instance
    
    if _task_manager_instance is None:
        _task_manager_instance = TaskManager()
    
    return _task_manager_instance


if __name__ == "__main__":
    # Test the task manager
    async def test():
        manager = TaskManager()
        
        print("Testing TaskManager...")
        print("=" * 60)
        
        # Create a test task
        async def long_operation(duration: int):
            await asyncio.sleep(duration)
            return f"Completed after {duration} seconds"
        
        # Create and start tasks
        print("\n1. Creating background tasks:")
        task_id_1 = manager.create_task("192.168.1.1", "nmap")
        task_id_2 = manager.create_task("example.com", "nuclei")
        
        print(f"Task 1: {task_id_1}")
        print(f"Task 2: {task_id_2}")
        
        # Start tasks in background
        manager.start_background_task(task_id_1, long_operation, 2)
        manager.start_background_task(task_id_2, long_operation, 3)
        
        # Check status immediately
        print("\n2. Immediate status check:")
        print(f"Task 1: {manager.get_task_status(task_id_1)['status']}")
        print(f"Task 2: {manager.get_task_status(task_id_2)['status']}")
        
        # Wait a bit
        await asyncio.sleep(1)
        
        # Check status again
        print("\n3. Status after 1 second:")
        print(f"Task 1: {manager.get_task_status(task_id_1)['status']}")
        
        # Wait for completion
        await asyncio.sleep(3)
        
        print("\n4. Final status:")
        print(f"Task 1: {manager.get_task_status(task_id_1)['status']}")
        print(f"Task 1 Result: {manager.get_task_result(task_id_1)}")
        print(f"Task 2: {manager.get_task_status(task_id_2)['status']}")
        print(f"Task 2 Result: {manager.get_task_result(task_id_2)}")
        
        # Get stats
        print("\n5. Statistics:")
        stats = manager.get_stats()
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        print("\n✅ Tests completed")
    
    asyncio.run(test())
