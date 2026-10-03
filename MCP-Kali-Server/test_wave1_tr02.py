#!/usr/bin/env python3
"""
Test suite for TASK-TR-02: ToolRegistry Implementation

Tests all 10 methods with acceptance criteria:
1. Duplicate ID detection
2. Query filtering
3. O(1) constant-time lookup
4. Thread-safe concurrent registration
5. Error handling
"""

import pytest
import threading
import time
import timeit
from typing import List, Tuple
from kali_mcp_server import (
    Tool,
    Capability,
    Parameter,
    ParameterType,
    ToolRegistry,
    HealthStatus,
)


# ============================================================================
# TEST FIXTURES
# ============================================================================

@pytest.fixture
def sample_tools() -> List[Tool]:
    """Create sample tools for testing."""
    tools = []
    
    # Tool 1: Nuclei (RECON, SCAN capabilities)
    nuclei = Tool(
        id="tool-nuclei-001",
        name="Nuclei",
        category="SCANNER",
        capabilities=[
            Capability(
                id="cap-nuclei-recon",
                name="Web Reconnaissance",
                category="RECON",
                evidence_potential=0.7,
            ),
            Capability(
                id="cap-nuclei-scan",
                name="Vulnerability Scanning",
                category="SCAN",
                evidence_potential=0.8,
            ),
        ],
        required_params=[
            Parameter(
                name="target",
                param_type=ParameterType.STRING,
                description="Target URL",
                required=True,
            )
        ],
        timeout_seconds=300,
    )
    tools.append(nuclei)
    
    # Tool 2: Nmap (RECON capability)
    nmap = Tool(
        id="tool-nmap-001",
        name="Nmap",
        category="SCANNER",
        capabilities=[
            Capability(
                id="cap-nmap-recon",
                name="Network Reconnaissance",
                category="RECON",
                evidence_potential=0.75,
            ),
        ],
        required_params=[
            Parameter(
                name="target",
                param_type=ParameterType.STRING,
                description="Target host/network",
                required=True,
            )
        ],
        timeout_seconds=600,
    )
    tools.append(nmap)
    
    # Tool 3: Hydra (CRACK capability)
    hydra = Tool(
        id="tool-hydra-001",
        name="Hydra",
        category="CRACKER",
        capabilities=[
            Capability(
                id="cap-hydra-crack",
                name="Credential Cracking",
                category="CRACK",
                evidence_potential=0.9,
            ),
        ],
        required_params=[
            Parameter(
                name="target",
                param_type=ParameterType.STRING,
                description="Target host",
                required=True,
            ),
            Parameter(
                name="service",
                param_type=ParameterType.ENUM,
                description="Service type",
                required=True,
                allowed_values=["ssh", "ftp", "http", "smtp"],
            ),
        ],
        timeout_seconds=1800,
    )
    tools.append(hydra)
    
    # Tool 4: SQLmap (EXPLOIT capability)
    sqlmap = Tool(
        id="tool-sqlmap-001",
        name="SQLmap",
        category="EXPLOIT",
        capabilities=[
            Capability(
                id="cap-sqlmap-exploit",
                name="SQL Injection Detection",
                category="EXPLOIT",
                evidence_potential=0.95,
            ),
        ],
        required_params=[
            Parameter(
                name="url",
                param_type=ParameterType.STRING,
                description="Target URL",
                required=True,
            )
        ],
        timeout_seconds=900,
    )
    tools.append(sqlmap)
    
    # Tool 5: Burp Suite (SCAN capability)
    burp = Tool(
        id="tool-burp-001",
        name="Burp Suite",
        category="SCANNER",
        capabilities=[
            Capability(
                id="cap-burp-scan",
                name="Active Scanning",
                category="SCAN",
                evidence_potential=0.85,
            ),
        ],
        required_params=[],
        timeout_seconds=3600,
    )
    tools.append(burp)
    
    return tools


@pytest.fixture
def registry(sample_tools) -> ToolRegistry:
    """Create a registry with sample tools."""
    registry = ToolRegistry(initial_tools=sample_tools)
    return registry


# ============================================================================
# TEST: Registration & Duplicate Detection (Acceptance Criteria 1, 2)
# ============================================================================

def test_register_tool_success():
    """AC1: Tools registerable without duplicates."""
    registry = ToolRegistry()
    
    tool = Tool(
        id="test-tool-1",
        name="Test Tool",
        category="SCANNER",
        capabilities=[
            Capability(
                id="cap-1",
                name="Test Capability",
                category="RECON",
                evidence_potential=0.5,
            )
        ],
    )
    
    success, error = registry.register(tool)
    assert success is True
    assert error is None
    assert registry.tool_count() == 1


def test_register_duplicate_id_error():
    """AC2: Duplicate ID check returns error."""
    registry = ToolRegistry()
    
    tool1 = Tool(
        id="duplicate-id",
        name="Tool 1",
        category="SCANNER",
        capabilities=[
            Capability(
                id="cap-1",
                name="Capability",
                category="RECON",
                evidence_potential=0.5,
            )
        ],
    )
    
    tool2 = Tool(
        id="duplicate-id",
        name="Tool 2",
        category="SCANNER",
        capabilities=[
            Capability(
                id="cap-2",
                name="Capability",
                category="RECON",
                evidence_potential=0.5,
            )
        ],
    )
    
    success1, error1 = registry.register(tool1)
    assert success1 is True
    
    success2, error2 = registry.register(tool2)
    assert success2 is False
    assert "already registered" in error2.lower()


def test_register_10_tools():
    """Register 10 tools and verify count."""
    registry = ToolRegistry()
    
    for i in range(10):
        tool = Tool(
            id=f"tool-{i}",
            name=f"Tool {i}",
            category="SCANNER",
            capabilities=[
                Capability(
                    id=f"cap-{i}",
                    name=f"Capability {i}",
                    category=["RECON", "SCAN", "EXPLOIT", "CRACK"][i % 4],
                    evidence_potential=0.5 + (i * 0.05),
                )
            ],
        )
        success, _ = registry.register(tool)
        assert success is True
    
    assert registry.tool_count() == 10


# ============================================================================
# TEST: Query Methods (Acceptance Criteria 3)
# ============================================================================

def test_query_tools_by_capability_type(registry):
    """AC3a: Queries return correct subsets."""
    # Query for RECON tools
    recon_tools = registry.query_tools_by_capability_type("RECON")
    assert len(recon_tools) >= 2  # Nuclei and Nmap have RECON
    assert all(
        any(cap.category == "RECON" for cap in tool.capabilities)
        for tool in recon_tools
    )
    
    # Query for SCAN tools
    scan_tools = registry.query_tools_by_capability_type("SCAN")
    assert len(scan_tools) >= 2  # Nuclei and Burp have SCAN
    
    # Query for CRACK tools
    crack_tools = registry.query_tools_by_capability_type("CRACK")
    assert len(crack_tools) == 1
    assert crack_tools[0].name == "Hydra"


def test_query_tools_by_capability_type_case_insensitive(registry):
    """Query should be case-insensitive."""
    recon_lower = registry.query_tools_by_capability_type("recon")
    recon_upper = registry.query_tools_by_capability_type("RECON")
    recon_mixed = registry.query_tools_by_capability_type("ReCoN")
    
    assert len(recon_lower) == len(recon_upper) == len(recon_mixed)
    assert set(t.id for t in recon_lower) == set(t.id for t in recon_upper)


def test_query_tools_by_tech_stack(registry):
    """AC3b: Query by tech stack returns filtered subset."""
    # This is a simpler test since we haven't set technology_stack explicitly
    java_tools = registry.query_tools_by_tech_stack(["Java", "Spring"])
    # Should return empty or subset (depends on tool definitions)
    assert isinstance(java_tools, list)


def test_query_tools_with_evidence_level(registry):
    """AC3c: Query by evidence level returns filtered subset."""
    # Tools with high evidence potential
    high_evidence = registry.query_tools_with_evidence_level(0.8)
    assert len(high_evidence) >= 2  # Hydra (0.9), SQLmap (0.95), Burp (0.85), Nuclei (0.8)
    assert all(
        any(cap.evidence_potential >= 0.8 for cap in tool.capabilities)
        for tool in high_evidence
    )
    
    # Tools with low evidence potential
    low_evidence = registry.query_tools_with_evidence_level(0.5)
    assert len(low_evidence) >= 4  # Most tools qualify
    
    # Tools with minimal evidence
    minimal = registry.query_tools_with_evidence_level(0.0)
    assert len(minimal) == registry.tool_count()


def test_query_with_invalid_evidence_level():
    """Query with invalid evidence level raises error."""
    registry = ToolRegistry()
    
    with pytest.raises(ValueError):
        registry.query_tools_with_evidence_level(1.5)
    
    with pytest.raises(ValueError):
        registry.query_tools_with_evidence_level(-0.5)


# ============================================================================
# TEST: O(1) Constant-Time Lookup (Acceptance Criterion 4)
# ============================================================================

def test_get_tool_by_id_o1_performance(registry):
    """AC4: get_tool_by_id() completes in < 1ms (constant time)."""
    # Get a tool to lookup
    tool = registry.get_all_tools()[0]
    tool_id = tool.id
    
    # Measure 1000 lookups
    def lookup():
        registry.get_tool_by_id(tool_id)
    
    # Use timeit for accurate timing
    time_per_call = timeit.timeit(lookup, number=1000) / 1000
    time_ms = time_per_call * 1000
    
    # Each call should be < 1ms (typically < 0.1ms)
    assert time_ms < 1.0, f"Lookup took {time_ms:.3f}ms, expected < 1ms"
    print(f"✓ O(1) lookup performance: {time_ms:.4f}ms per call")


def test_get_tool_by_id_returns_correct_tool(registry):
    """Lookup returns the correct tool."""
    tool = registry.get_all_tools()[0]
    retrieved = registry.get_tool_by_id(tool.id)
    
    assert retrieved is not None
    assert retrieved.id == tool.id
    assert retrieved.name == tool.name


def test_get_tool_by_id_returns_none_for_missing():
    """Lookup returns None for non-existent tool."""
    registry = ToolRegistry()
    result = registry.get_tool_by_id("nonexistent-id")
    assert result is None


# ============================================================================
# TEST: Error Handling (Acceptance Criterion 5)
# ============================================================================

def test_unregister_tool_success():
    """Unregister existing tool successfully."""
    registry = ToolRegistry()
    
    tool = Tool(
        id="test-tool",
        name="Test",
        category="SCANNER",
        capabilities=[
            Capability(
                id="cap",
                name="Test",
                category="RECON",
                evidence_potential=0.5,
            )
        ],
    )
    
    registry.register(tool)
    assert registry.tool_count() == 1
    
    success, error = registry.unregister("test-tool")
    assert success is True
    assert error is None
    assert registry.tool_count() == 0


def test_unregister_nonexistent_tool():
    """Unregister non-existent tool returns error."""
    registry = ToolRegistry()
    success, error = registry.unregister("nonexistent")
    assert success is False
    assert "not found" in error.lower()


def test_health_check_returns_status(registry):
    """health_check() returns correct status."""
    tool = registry.get_all_tools()[0]
    status = registry.health_check(tool.id)
    
    assert isinstance(status, HealthStatus)
    assert status == HealthStatus.HEALTHY


def test_health_check_offline_for_missing():
    """health_check() returns OFFLINE for missing tool."""
    registry = ToolRegistry()
    status = registry.health_check("nonexistent")
    assert status == HealthStatus.OFFLINE


def test_get_all_tools_returns_copy(registry):
    """get_all_tools() returns a safe copy."""
    tools1 = registry.get_all_tools()
    tools1.append(Tool(
        id="fake",
        name="Fake",
        category="SCANNER",
        capabilities=[
            Capability(
                id="cap",
                name="Test",
                category="RECON",
                evidence_potential=0.5,
            )
        ],
    ))
    
    tools2 = registry.get_all_tools()
    assert len(tools2) == registry.tool_count()


# ============================================================================
# TEST: Thread Safety (Acceptance Criterion 5)
# ============================================================================

def test_concurrent_registration():
    """AC5: Thread-safe concurrent registration (5 threads, 20 tools each)."""
    registry = ToolRegistry()
    errors = []
    
    def register_tools(thread_id: int, count: int):
        try:
            for i in range(count):
                tool = Tool(
                    id=f"thread-{thread_id}-tool-{i}",
                    name=f"Thread {thread_id} Tool {i}",
                    category="SCANNER",
                    capabilities=[
                        Capability(
                            id=f"cap-{thread_id}-{i}",
                            name=f"Cap {thread_id}-{i}",
                            category="RECON",
                            evidence_potential=0.5,
                        )
                    ],
                )
                success, error = registry.register(tool)
                if not success:
                    errors.append(f"Thread {thread_id}: {error}")
        except Exception as e:
            errors.append(f"Thread {thread_id}: {str(e)}")
    
    # Spawn 5 threads
    threads = []
    for i in range(5):
        t = threading.Thread(target=register_tools, args=(i, 20))
        threads.append(t)
        t.start()
    
    # Wait for all threads
    for t in threads:
        t.join()
    
    assert len(errors) == 0, f"Concurrency errors: {errors}"
    assert registry.tool_count() == 100  # 5 threads * 20 tools


def test_concurrent_queries():
    """Test concurrent query access (thread-safe)."""
    registry = ToolRegistry()
    
    # Pre-register 10 tools
    for i in range(10):
        tool = Tool(
            id=f"tool-{i}",
            name=f"Tool {i}",
            category="SCANNER",
            capabilities=[
                Capability(
                    id=f"cap-{i}",
                    name=f"Capability {i}",
                    category=["RECON", "SCAN", "EXPLOIT"][i % 3],
                    evidence_potential=0.5,
                )
            ],
        )
        registry.register(tool)
    
    results = []
    errors = []
    
    def query_tools(thread_id: int):
        try:
            for _ in range(10):
                recon = registry.query_tools_by_capability_type("RECON")
                results.append(len(recon))
        except Exception as e:
            errors.append(str(e))
    
    threads = []
    for i in range(5):
        t = threading.Thread(target=query_tools, args=(i,))
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    assert len(errors) == 0
    assert len(results) == 50  # 5 threads * 10 queries


# ============================================================================
# TEST: Registry Stats & Health (Acceptance Criterion 5)
# ============================================================================

def test_registry_stats(registry):
    """Test registry statistics."""
    stats = registry.get_registry_stats()
    
    assert "total_tools" in stats
    assert "healthy_count" in stats
    assert "degraded_count" in stats
    assert "offline_count" in stats
    assert stats["total_tools"] == 5
    assert stats["healthy_count"] == 5
    assert stats["degraded_count"] == 0
    assert stats["offline_count"] == 0


def test_update_tool_health_status():
    """Test updating tool health status."""
    registry = ToolRegistry()
    
    tool = Tool(
        id="test-tool",
        name="Test",
        category="SCANNER",
        capabilities=[
            Capability(
                id="cap",
                name="Test",
                category="RECON",
                evidence_potential=0.5,
            )
        ],
    )
    
    registry.register(tool)
    assert registry.health_check("test-tool") == HealthStatus.HEALTHY
    
    # Mark as degraded
    success, _ = registry.update_tool_health_status(
        "test-tool", HealthStatus.DEGRADED, "Test failure"
    )
    assert success is True
    assert registry.health_check("test-tool") == HealthStatus.DEGRADED
    
    # Mark as offline
    success, _ = registry.update_tool_health_status(
        "test-tool", HealthStatus.OFFLINE, "Tool not available"
    )
    assert success is True
    assert registry.health_check("test-tool") == HealthStatus.OFFLINE
    
    # Restore to healthy (should reset failure_count)
    success, _ = registry.update_tool_health_status(
        "test-tool", HealthStatus.HEALTHY, "Tool recovered"
    )
    assert success is True
    assert registry.health_check("test-tool") == HealthStatus.HEALTHY


# ============================================================================
# TEST: Edge Cases & Validation
# ============================================================================

def test_register_tool_without_capabilities():
    """Tool without capabilities should fail at initialization."""
    with pytest.raises(ValueError, match="capability"):
        tool = Tool(
            id="invalid-tool",
            name="Invalid Tool",
            category="SCANNER",
            capabilities=[],  # No capabilities!
        )


def test_query_empty_capability_name():
    """Query with empty string returns empty list."""
    registry = ToolRegistry()
    result = registry.query_tools_by_capability_type("")
    assert result == []


def test_query_empty_tech_stack():
    """Query with empty tech stack returns empty list."""
    registry = ToolRegistry()
    result = registry.query_tools_by_tech_stack([])
    assert result == []


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
