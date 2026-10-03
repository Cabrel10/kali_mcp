#!/usr/bin/env python3
"""
TASK-ORCH-02 Test Suite: Task Sequencing and Dependency Ordering

Tests:
1. Task creation and dependency tracking
2. Dependency resolution for execution order
3. Conflict detection (circular dependencies, unsatisfiable constraints)
4. Task scheduling within phases
5. Progress tracking
"""

import pytest
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set, Dict
import uuid


class TaskStatus(str, Enum):
    """Task execution status."""
    PENDING = "pending"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class TaskDependency:
    """Task dependency specification."""
    task_id: str
    required_status: str = "completed"  # completed, evidence_gathered, etc.


@dataclass
class ExecutableTask:
    """A task to be executed by the orchestrator."""
    task_id: str
    tool_id: str
    phase: str  # "baseline", "payload", "evidence", etc.
    target: str
    parameters: Dict[str, str] = field(default_factory=dict)
    dependencies: List[TaskDependency] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    priority: int = 1  # 1=low, 5=high
    max_retries: int = 3


class TaskScheduler:
    """Schedules and orders tasks for execution."""
    
    def __init__(self):
        """Initialize scheduler."""
        self.tasks: Dict[str, ExecutableTask] = {}
        self.execution_order: List[str] = []
        self.completed_tasks: Set[str] = set()
    
    def add_task(self, task: ExecutableTask) -> None:
        """Add a task to the scheduler."""
        if not isinstance(task, ExecutableTask):
            raise TypeError("task must be ExecutableTask")
        
        self.tasks[task.task_id] = task
    
    def get_task(self, task_id: str) -> Optional[ExecutableTask]:
        """Retrieve a task."""
        return self.tasks.get(task_id)
    
    def get_ready_tasks(self) -> List[ExecutableTask]:
        """Get all tasks ready for execution."""
        ready = []
        
        for task in self.tasks.values():
            if task.status != TaskStatus.PENDING:
                continue
            
            # Check if all dependencies are completed
            all_deps_met = True
            for dep in task.dependencies:
                if dep.task_id not in self.completed_tasks:
                    all_deps_met = False
                    break
            
            if all_deps_met:
                ready.append(task)
        
        # Sort by priority (higher first)
        return sorted(ready, key=lambda t: -t.priority)
    
    def mark_completed(self, task_id: str) -> None:
        """Mark task as completed."""
        if task_id in self.tasks:
            self.tasks[task_id].status = TaskStatus.COMPLETED
            self.completed_tasks.add(task_id)
    
    def resolve_dependencies(self) -> List[str]:
        """Resolve task order respecting dependencies."""
        order = []
        remaining = set(self.tasks.keys())
        
        while remaining:
            # Find tasks with no unmet dependencies
            ready = []
            for task_id in remaining:
                task = self.tasks[task_id]
                deps_met = all(
                    dep.task_id not in remaining or dep.task_id in order
                    for dep in task.dependencies
                )
                if deps_met:
                    ready.append(task_id)
            
            if not ready:
                # Circular dependency detected
                raise ValueError("Circular dependency detected")
            
            # Sort by priority
            ready.sort(key=lambda tid: -self.tasks[tid].priority)
            order.extend(ready)
            remaining -= set(ready)
        
        self.execution_order = order
        return order
    
    def detect_circular_dependencies(self) -> bool:
        """Detect if there are circular dependencies."""
        try:
            self.resolve_dependencies()
            return False
        except ValueError as e:
            if "Circular" in str(e):
                return True
            raise
    
    def get_task_count(self) -> int:
        """Get total number of tasks."""
        return len(self.tasks)
    
    def get_completed_count(self) -> int:
        """Get number of completed tasks."""
        return len(self.completed_tasks)


class TestTaskCreation:
    """Test task creation."""
    
    def test_create_basic_task(self):
        """Create basic executable task."""
        task = ExecutableTask(
            task_id="task-001",
            tool_id="nuclei",
            phase="payload",
            target="http://example.com"
        )
        assert task.task_id == "task-001"
        assert task.tool_id == "nuclei"
        assert task.status == TaskStatus.PENDING
    
    def test_create_task_with_dependencies(self):
        """Create task with dependencies."""
        dep = TaskDependency(task_id="task-000", required_status="completed")
        task = ExecutableTask(
            task_id="task-001",
            tool_id="sqlmap",
            phase="payload",
            target="http://example.com",
            dependencies=[dep]
        )
        assert len(task.dependencies) == 1
        assert task.dependencies[0].task_id == "task-000"
    
    def test_create_task_with_priority(self):
        """Create task with priority."""
        task = ExecutableTask(
            task_id="task-001",
            tool_id="tool",
            phase="baseline",
            target="http://example.com",
            priority=5
        )
        assert task.priority == 5


class TestTaskScheduling:
    """Test task scheduling."""
    
    def test_add_tasks(self):
        """Add tasks to scheduler."""
        scheduler = TaskScheduler()
        
        task1 = ExecutableTask("t1", "tool1", "baseline", "http://example.com")
        task2 = ExecutableTask("t2", "tool2", "payload", "http://example.com")
        
        scheduler.add_task(task1)
        scheduler.add_task(task2)
        
        assert scheduler.get_task_count() == 2
    
    def test_get_ready_tasks_no_deps(self):
        """Get ready tasks when there are no dependencies."""
        scheduler = TaskScheduler()
        
        task1 = ExecutableTask("t1", "tool1", "baseline", "http://example.com")
        task2 = ExecutableTask("t2", "tool2", "baseline", "http://example.com")
        
        scheduler.add_task(task1)
        scheduler.add_task(task2)
        
        ready = scheduler.get_ready_tasks()
        assert len(ready) == 2
    
    def test_get_ready_tasks_with_deps(self):
        """Get ready tasks respecting dependencies."""
        scheduler = TaskScheduler()
        
        task1 = ExecutableTask("t1", "tool1", "baseline", "http://example.com")
        dep = TaskDependency("t1")
        task2 = ExecutableTask(
            "t2", "tool2", "payload", "http://example.com",
            dependencies=[dep]
        )
        
        scheduler.add_task(task1)
        scheduler.add_task(task2)
        
        # Only t1 is ready
        ready = scheduler.get_ready_tasks()
        assert len(ready) == 1
        assert ready[0].task_id == "t1"
        
        # Mark t1 as completed
        scheduler.mark_completed("t1")
        
        # Now t2 should be ready
        ready = scheduler.get_ready_tasks()
        assert len(ready) == 1
        assert ready[0].task_id == "t2"
    
    def test_priority_ordering(self):
        """Tasks ordered by priority."""
        scheduler = TaskScheduler()
        
        task1 = ExecutableTask("t1", "tool1", "baseline", "http://example.com", priority=1)
        task2 = ExecutableTask("t2", "tool2", "baseline", "http://example.com", priority=5)
        task3 = ExecutableTask("t3", "tool3", "baseline", "http://example.com", priority=3)
        
        scheduler.add_task(task1)
        scheduler.add_task(task2)
        scheduler.add_task(task3)
        
        ready = scheduler.get_ready_tasks()
        # Should be ordered: t2 (5), t3 (3), t1 (1)
        assert ready[0].task_id == "t2"
        assert ready[1].task_id == "t3"
        assert ready[2].task_id == "t1"


class TestDependencyResolution:
    """Test dependency resolution."""
    
    def test_resolve_linear_dependencies(self):
        """Resolve linear dependency chain."""
        scheduler = TaskScheduler()
        
        task1 = ExecutableTask("t1", "tool1", "baseline", "http://example.com")
        task2 = ExecutableTask(
            "t2", "tool2", "payload", "http://example.com",
            dependencies=[TaskDependency("t1")]
        )
        task3 = ExecutableTask(
            "t3", "tool3", "payload", "http://example.com",
            dependencies=[TaskDependency("t2")]
        )
        
        scheduler.add_task(task1)
        scheduler.add_task(task2)
        scheduler.add_task(task3)
        
        order = scheduler.resolve_dependencies()
        
        assert order == ["t1", "t2", "t3"]
    
    def test_resolve_parallel_dependencies(self):
        """Resolve parallel independent tasks."""
        scheduler = TaskScheduler()
        
        task1 = ExecutableTask("t1", "tool1", "baseline", "http://example.com")
        task2 = ExecutableTask("t2", "tool2", "baseline", "http://example.com")
        task3 = ExecutableTask(
            "t3", "tool3", "payload", "http://example.com",
            dependencies=[TaskDependency("t1"), TaskDependency("t2")]
        )
        
        scheduler.add_task(task1)
        scheduler.add_task(task2)
        scheduler.add_task(task3)
        
        order = scheduler.resolve_dependencies()
        
        # t1 and t2 can be in any order, t3 must be last
        assert order[2] == "t3"
    
    def test_detect_circular_dependency(self):
        """Detect circular dependencies."""
        scheduler = TaskScheduler()
        
        task1 = ExecutableTask(
            "t1", "tool1", "baseline", "http://example.com",
            dependencies=[TaskDependency("t2")]
        )
        task2 = ExecutableTask(
            "t2", "tool2", "baseline", "http://example.com",
            dependencies=[TaskDependency("t1")]
        )
        
        scheduler.add_task(task1)
        scheduler.add_task(task2)
        
        assert scheduler.detect_circular_dependencies() is True


class TestProgressTracking:
    """Test progress tracking."""
    
    def test_mark_task_completed(self):
        """Mark task as completed."""
        scheduler = TaskScheduler()
        
        task = ExecutableTask("t1", "tool1", "baseline", "http://example.com")
        scheduler.add_task(task)
        
        assert scheduler.get_completed_count() == 0
        
        scheduler.mark_completed("t1")
        
        assert scheduler.get_completed_count() == 1
        assert scheduler.get_task("t1").status == TaskStatus.COMPLETED
    
    def test_track_progress(self):
        """Track overall progress."""
        scheduler = TaskScheduler()
        
        for i in range(5):
            task = ExecutableTask(f"t{i}", "tool", "baseline", "http://example.com")
            scheduler.add_task(task)
        
        assert scheduler.get_completed_count() == 0
        assert scheduler.get_task_count() == 5
        
        scheduler.mark_completed("t0")
        scheduler.mark_completed("t1")
        
        assert scheduler.get_completed_count() == 2


class TestAcceptanceCriteria:
    """Test acceptance criteria."""
    
    def test_ac1_task_tracking(self):
        """AC1: Task creation and dependency tracking."""
        task = ExecutableTask(
            "t1", "tool", "baseline", "http://example.com",
            dependencies=[TaskDependency("t0")]
        )
        assert len(task.dependencies) == 1
    
    def test_ac2_dependency_resolution(self):
        """AC2: Dependency resolution for execution order."""
        scheduler = TaskScheduler()
        scheduler.add_task(ExecutableTask("t1", "tool", "baseline", "http://example.com"))
        scheduler.add_task(ExecutableTask(
            "t2", "tool", "payload", "http://example.com",
            dependencies=[TaskDependency("t1")]
        ))
        
        order = scheduler.resolve_dependencies()
        assert order[0] == "t1" and order[1] == "t2"
    
    def test_ac3_circular_detection(self):
        """AC3: Circular dependency detection."""
        scheduler = TaskScheduler()
        scheduler.add_task(ExecutableTask(
            "t1", "tool", "baseline", "http://example.com",
            dependencies=[TaskDependency("t2")]
        ))
        scheduler.add_task(ExecutableTask(
            "t2", "tool", "baseline", "http://example.com",
            dependencies=[TaskDependency("t1")]
        ))
        
        assert scheduler.detect_circular_dependencies() is True
    
    def test_ac4_task_scheduling(self):
        """AC4: Task scheduling within phases."""
        scheduler = TaskScheduler()
        t1 = ExecutableTask("t1", "tool1", "baseline", "http://example.com")
        t2 = ExecutableTask("t2", "tool2", "baseline", "http://example.com")
        
        scheduler.add_task(t1)
        scheduler.add_task(t2)
        
        ready = scheduler.get_ready_tasks()
        assert len(ready) == 2
    
    def test_ac5_progress_tracking(self):
        """AC5: Progress tracking."""
        scheduler = TaskScheduler()
        scheduler.add_task(ExecutableTask("t1", "tool", "baseline", "http://example.com"))
        scheduler.add_task(ExecutableTask("t2", "tool", "baseline", "http://example.com"))
        
        scheduler.mark_completed("t1")
        
        assert scheduler.get_completed_count() == 1
        assert scheduler.get_task_count() == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
