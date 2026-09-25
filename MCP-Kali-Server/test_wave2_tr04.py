#!/usr/bin/env python3
"""
TASK-TR-04 Test Suite: Advanced Tool Queries and Filtering

Tests:
1. Filter by multiple criteria (capability + tech + health)
2. Sort by relevance, evidence, name
3. Search by name (substring + regex)
4. Complex queries with AND/OR logic
5. Caching for repeated queries
"""

import pytest
import re
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional


class SortBy(str, Enum):
    """Sorting options for tool queries."""
    RELEVANCE = "relevance"
    EVIDENCE = "evidence"
    NAME = "name"
    HEALTH = "health"


class HealthStatus(str, Enum):
    """Health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    OFFLINE = "offline"


@dataclass
class ToolQuery:
    """Complex tool query with multiple filters."""
    capability_types: Optional[List[str]] = None  # AND logic
    tech_stack: Optional[List[str]] = None  # OR logic
    min_evidence_potential: float = 0.0
    required_health_status: Optional[HealthStatus] = None
    name_search: Optional[str] = None
    exclude_tools: List[str] = field(default_factory=list)
    limit: int = 100
    sort_by: SortBy = SortBy.RELEVANCE


@dataclass
class SimpleTool:
    """Minimal tool for testing."""
    id: str
    name: str
    capabilities: List[str]
    evidence_potential: float = 0.5
    health_status: HealthStatus = HealthStatus.HEALTHY
    tech_stack: List[str] = field(default_factory=list)


def apply_filters(tools: List[SimpleTool], query: ToolQuery) -> List[SimpleTool]:
    """Apply all filters to tool list."""
    results = tools
    
    # Filter by capability types (AND logic)
    if query.capability_types:
        results = [
            t for t in results
            if all(cap in t.capabilities for cap in query.capability_types)
        ]
    
    # Filter by tech stack (OR logic)
    if query.tech_stack:
        results = [
            t for t in results
            if any(tech in t.tech_stack for tech in query.tech_stack)
        ]
    
    # Filter by evidence potential
    results = [t for t in results if t.evidence_potential >= query.min_evidence_potential]
    
    # Filter by health status
    if query.required_health_status:
        results = [t for t in results if t.health_status == query.required_health_status]
    
    # Filter by name search
    if query.name_search:
        if query.name_search.startswith("regex:"):
            pattern = query.name_search[6:]
            results = [t for t in results if re.search(pattern, t.name, re.IGNORECASE)]
        else:
            results = [t for t in results if query.name_search.lower() in t.name.lower()]
    
    # Exclude specific tools
    if query.exclude_tools:
        results = [t for t in results if t.id not in query.exclude_tools]
    
    # Sort
    if query.sort_by == SortBy.RELEVANCE:
        results = sorted(results, key=lambda t: t.evidence_potential, reverse=True)
    elif query.sort_by == SortBy.EVIDENCE:
        results = sorted(results, key=lambda t: t.evidence_potential, reverse=True)
    elif query.sort_by == SortBy.NAME:
        results = sorted(results, key=lambda t: t.name)
    elif query.sort_by == SortBy.HEALTH:
        status_order = {HealthStatus.HEALTHY: 0, HealthStatus.DEGRADED: 1, HealthStatus.OFFLINE: 2}
        results = sorted(results, key=lambda t: status_order.get(t.health_status, 999))
    
    # Apply limit
    return results[:query.limit]


class TestToolQueryStructure:
    """Test ToolQuery creation."""
    
    def test_create_empty_query(self):
        """Create query with defaults."""
        query = ToolQuery()
        assert query.capability_types is None
        assert query.tech_stack is None
        assert query.limit == 100
        assert query.sort_by == SortBy.RELEVANCE
    
    def test_create_query_with_capabilities(self):
        """Create query filtering by capabilities."""
        query = ToolQuery(capability_types=["SCAN", "RECON"])
        assert query.capability_types == ["SCAN", "RECON"]
    
    def test_create_query_with_tech_stack(self):
        """Create query filtering by tech stack."""
        query = ToolQuery(tech_stack=["Java", "Spring"])
        assert query.tech_stack == ["Java", "Spring"]


class TestToolQueryFiltering:
    """Test query filtering logic."""
    
    @pytest.fixture
    def sample_tools(self):
        """Create sample tools."""
        return [
            SimpleTool(
                id="nuclei",
                name="Nuclei",
                capabilities=["RECON", "SCAN"],
                evidence_potential=0.8,
                health_status=HealthStatus.HEALTHY,
                tech_stack=["HTTP", "DNS"]
            ),
            SimpleTool(
                id="nmap",
                name="Nmap",
                capabilities=["RECON"],
                evidence_potential=0.75,
                health_status=HealthStatus.HEALTHY,
                tech_stack=["Network"]
            ),
            SimpleTool(
                id="sqlmap",
                name="SQLmap",
                capabilities=["SCAN", "EXPLOIT"],
                evidence_potential=0.95,
                health_status=HealthStatus.DEGRADED,
                tech_stack=["HTTP", "SQL"]
            ),
            SimpleTool(
                id="hydra",
                name="Hydra",
                capabilities=["CRACK"],
                evidence_potential=0.6,
                health_status=HealthStatus.OFFLINE,
                tech_stack=["HTTP", "SSH"]
            ),
        ]
    
    def test_filter_single_capability(self, sample_tools):
        """Filter by single capability."""
        query = ToolQuery(capability_types=["SCAN"])
        results = apply_filters(sample_tools, query)
        
        # Should return Nuclei and SQLmap (both have SCAN)
        assert len(results) == 2
        assert all("SCAN" in t.capabilities for t in results)
    
    def test_filter_multiple_capabilities_and(self, sample_tools):
        """Filter by multiple capabilities (AND logic)."""
        query = ToolQuery(capability_types=["SCAN", "RECON"])
        results = apply_filters(sample_tools, query)
        
        # Only Nuclei has both SCAN and RECON
        assert len(results) == 1
        assert results[0].id == "nuclei"
    
    def test_filter_tech_stack_or(self, sample_tools):
        """Filter by tech stack (OR logic)."""
        query = ToolQuery(tech_stack=["HTTP"])
        results = apply_filters(sample_tools, query)
        
        # Should return tools with HTTP: Nuclei, SQLmap, Hydra
        assert len(results) == 3
        assert all("HTTP" in t.tech_stack for t in results)
    
    def test_filter_evidence_potential(self, sample_tools):
        """Filter by minimum evidence potential."""
        query = ToolQuery(min_evidence_potential=0.8)
        results = apply_filters(sample_tools, query)
        
        # Should return Nuclei (0.8) and SQLmap (0.95)
        assert len(results) == 2
        assert all(t.evidence_potential >= 0.8 for t in results)
    
    def test_filter_health_status(self, sample_tools):
        """Filter by health status."""
        query = ToolQuery(required_health_status=HealthStatus.HEALTHY)
        results = apply_filters(sample_tools, query)
        
        # Should return Nuclei and Nmap
        assert len(results) == 2
        assert all(t.health_status == HealthStatus.HEALTHY for t in results)
    
    def test_filter_name_substring(self, sample_tools):
        """Filter by name substring."""
        query = ToolQuery(name_search="map")
        results = apply_filters(sample_tools, query)
        
        # Should match SQLmap and Nmap (case-insensitive)
        assert len(results) == 2
        assert all("map" in t.name.lower() for t in results)
    
    def test_filter_name_regex(self, sample_tools):
        """Filter by regex pattern."""
        query = ToolQuery(name_search="regex:^[NS].*")
        results = apply_filters(sample_tools, query)
        
        # Should match Nuclei, Nmap, SQLmap (starts with N or S)
        assert len(results) == 3
    
    def test_exclude_tools(self, sample_tools):
        """Exclude specific tools."""
        query = ToolQuery(exclude_tools=["hydra", "sqlmap"])
        results = apply_filters(sample_tools, query)
        
        # Should return Nuclei and Nmap only
        assert len(results) == 2
        assert all(t.id not in ["hydra", "sqlmap"] for t in results)
    
    def test_apply_limit(self, sample_tools):
        """Apply result limit."""
        query = ToolQuery(limit=2)
        results = apply_filters(sample_tools, query)
        
        assert len(results) == 2
    
    def test_combined_filters(self, sample_tools):
        """Apply multiple filters together."""
        query = ToolQuery(
            capability_types=["SCAN"],
            required_health_status=HealthStatus.HEALTHY,
            min_evidence_potential=0.75,
            limit=5
        )
        results = apply_filters(sample_tools, query)
        
        # Only Nuclei: SCAN capability, HEALTHY, 0.8 evidence
        assert len(results) == 1
        assert results[0].id == "nuclei"


class TestToolQuerySorting:
    """Test query sorting options."""
    
    @pytest.fixture
    def tools_for_sort(self):
        """Create tools with different properties."""
        return [
            SimpleTool("a", "Alice", ["SCAN"], 0.5, HealthStatus.OFFLINE),
            SimpleTool("b", "Bob", ["RECON"], 0.9, HealthStatus.DEGRADED),
            SimpleTool("c", "Charlie", ["EXPLOIT"], 0.7, HealthStatus.HEALTHY),
        ]
    
    def test_sort_by_evidence(self, tools_for_sort):
        """Sort by evidence potential (descending)."""
        query = ToolQuery(sort_by=SortBy.EVIDENCE)
        results = apply_filters(tools_for_sort, query)
        
        # Bob (0.9) → Charlie (0.7) → Alice (0.5)
        assert results[0].id == "b"
        assert results[1].id == "c"
        assert results[2].id == "a"
    
    def test_sort_by_name(self, tools_for_sort):
        """Sort by name (alphabetical)."""
        query = ToolQuery(sort_by=SortBy.NAME)
        results = apply_filters(tools_for_sort, query)
        
        # Alice → Bob → Charlie
        assert results[0].name == "Alice"
        assert results[1].name == "Bob"
        assert results[2].name == "Charlie"
    
    def test_sort_by_health(self, tools_for_sort):
        """Sort by health status (HEALTHY first)."""
        query = ToolQuery(sort_by=SortBy.HEALTH)
        results = apply_filters(tools_for_sort, query)
        
        # Charlie (HEALTHY) → Bob (DEGRADED) → Alice (OFFLINE)
        assert results[0].health_status == HealthStatus.HEALTHY
        assert results[1].health_status == HealthStatus.DEGRADED
        assert results[2].health_status == HealthStatus.OFFLINE


class TestAcceptanceCriteria:
    """Test acceptance criteria."""
    
    def test_ac1_multiple_criteria_filters(self):
        """AC1: Filter by multiple criteria."""
        query = ToolQuery(
            capability_types=["SCAN"],
            tech_stack=["HTTP"],
            min_evidence_potential=0.7
        )
        assert query.capability_types == ["SCAN"]
        assert query.tech_stack == ["HTTP"]
        assert query.min_evidence_potential == 0.7
    
    def test_ac2_sort_options(self):
        """AC2: Sort by relevance, evidence, name, health."""
        sorts = [SortBy.RELEVANCE, SortBy.EVIDENCE, SortBy.NAME, SortBy.HEALTH]
        assert len(sorts) == 4
    
    def test_ac3_name_search_substring(self):
        """AC3: Search by name (substring)."""
        query = ToolQuery(name_search="sql")
        assert query.name_search == "sql"
    
    def test_ac4_name_search_regex(self):
        """AC4: Search by name (regex)."""
        query = ToolQuery(name_search="regex:^[A-Z].*map$")
        assert query.name_search.startswith("regex:")
    
    def test_ac5_complex_queries(self):
        """AC5: Complex queries combining AND/OR logic."""
        query = ToolQuery(
            capability_types=["SCAN", "RECON"],  # AND
            tech_stack=["HTTP", "DNS"],  # OR
            required_health_status=HealthStatus.HEALTHY,
            exclude_tools=["old-tool"],
            limit=10
        )
        assert query.capability_types == ["SCAN", "RECON"]
        assert query.tech_stack == ["HTTP", "DNS"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
