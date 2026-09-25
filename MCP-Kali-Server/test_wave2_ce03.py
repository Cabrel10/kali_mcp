#!/usr/bin/env python3
"""
TASK-CE-03 Test Suite: Dependency Resolution

Tests dependency graph building, circular detection, topological sort
"""

import pytest
import networkx as nx
from typing import List


class DependencyNode:
    """Helper class for dependency tracking."""
    def __init__(self, tool_id: str, precondition_ids: List[str] = None):
        self.tool_id = tool_id
        self.precondition_ids = precondition_ids or []


def build_dependency_graph(nodes: List[DependencyNode]) -> nx.DiGraph:
    """Build networkx directed graph from dependency nodes."""
    graph = nx.DiGraph()
    
    # Add all nodes
    for node in nodes:
        graph.add_node(node.tool_id)
    
    # Add edges for dependencies
    for node in nodes:
        for precond_id in node.precondition_ids:
            if precond_id in graph:
                graph.add_edge(precond_id, node.tool_id)
    
    return graph


def detect_circular_dependencies(graph: nx.DiGraph) -> List[List[str]]:
    """Detect cycles in dependency graph."""
    cycles = list(nx.simple_cycles(graph))
    return cycles


def topological_sort(graph: nx.DiGraph) -> List[str]:
    """Return topologically sorted nodes (dependencies first)."""
    return list(nx.topological_sort(graph))


class TestDependencyNodeCreation:
    """Test DependencyNode creation."""
    
    def test_create_node_without_preconditions(self):
        """Create a root node without preconditions."""
        node = DependencyNode("tool-A")
        assert node.tool_id == "tool-A"
        assert node.precondition_ids == []
    
    def test_create_node_with_preconditions(self):
        """Create a node with preconditions."""
        node = DependencyNode("tool-B", precondition_ids=["tool-A"])
        assert node.tool_id == "tool-B"
        assert node.precondition_ids == ["tool-A"]


class TestDependencyGraphBuilding:
    """Test dependency graph construction."""
    
    def test_build_empty_graph(self):
        """Build graph from empty node list."""
        graph = build_dependency_graph([])
        assert len(graph.nodes()) == 0
        assert len(graph.edges()) == 0
    
    def test_build_single_node_graph(self):
        """Build graph with single node."""
        nodes = [DependencyNode("tool-A")]
        graph = build_dependency_graph(nodes)
        
        assert len(graph.nodes()) == 1
        assert "tool-A" in graph
        assert len(graph.edges()) == 0
    
    def test_build_linear_dependency_graph(self):
        """Build linear dependency: A → B → C."""
        nodes = [
            DependencyNode("tool-A"),
            DependencyNode("tool-B", precondition_ids=["tool-A"]),
            DependencyNode("tool-C", precondition_ids=["tool-B"]),
        ]
        graph = build_dependency_graph(nodes)
        
        assert len(graph.nodes()) == 3
        assert len(graph.edges()) == 2
        assert graph.has_edge("tool-A", "tool-B")
        assert graph.has_edge("tool-B", "tool-C")
    
    def test_build_complex_dependency_graph(self):
        """Build complex DAG with multiple paths."""
        nodes = [
            DependencyNode("tool-A"),
            DependencyNode("tool-B"),
            DependencyNode("tool-C", precondition_ids=["tool-A", "tool-B"]),
            DependencyNode("tool-D", precondition_ids=["tool-C"]),
            DependencyNode("tool-E", precondition_ids=["tool-B"]),
        ]
        graph = build_dependency_graph(nodes)
        
        assert len(graph.nodes()) == 5
        assert len(graph.edges()) == 4
        assert graph.has_edge("tool-A", "tool-C")
        assert graph.has_edge("tool-B", "tool-C")
        assert graph.has_edge("tool-B", "tool-E")


class TestCircularDependencyDetection:
    """Test circular dependency detection."""
    
    def test_no_circular_dependencies(self):
        """Detect that linear graph has no cycles."""
        nodes = [
            DependencyNode("tool-A"),
            DependencyNode("tool-B", precondition_ids=["tool-A"]),
        ]
        graph = build_dependency_graph(nodes)
        cycles = detect_circular_dependencies(graph)
        
        assert len(cycles) == 0
    
    def test_detect_self_cycle(self):
        """Detect self-referencing cycle."""
        nodes = [DependencyNode("tool-A", precondition_ids=["tool-A"])]
        graph = build_dependency_graph(nodes)
        cycles = detect_circular_dependencies(graph)
        
        # Self-cycle should be detected
        assert len(cycles) > 0
    
    def test_detect_circular_dependency_a_b_a(self):
        """Detect cycle: A → B → A."""
        graph = nx.DiGraph()
        graph.add_nodes_from(["tool-A", "tool-B"])
        graph.add_edges_from([("tool-A", "tool-B"), ("tool-B", "tool-A")])
        
        cycles = detect_circular_dependencies(graph)
        assert len(cycles) == 1
        assert len(cycles[0]) == 2  # 2-node cycle


class TestTopologicalSort:
    """Test topological sorting."""
    
    def test_sort_single_node(self):
        """Sort single node graph."""
        nodes = [DependencyNode("tool-A")]
        graph = build_dependency_graph(nodes)
        order = topological_sort(graph)
        
        assert len(order) == 1
        assert order[0] == "tool-A"
    
    def test_sort_linear_chain(self):
        """Sort linear dependency chain."""
        nodes = [
            DependencyNode("tool-A"),
            DependencyNode("tool-B", precondition_ids=["tool-A"]),
            DependencyNode("tool-C", precondition_ids=["tool-B"]),
        ]
        graph = build_dependency_graph(nodes)
        order = topological_sort(graph)
        
        assert len(order) == 3
        # A should come before B, B before C
        assert order.index("tool-A") < order.index("tool-B")
        assert order.index("tool-B") < order.index("tool-C")
    
    def test_sort_complex_dag(self):
        """Sort complex DAG correctly."""
        nodes = [
            DependencyNode("tool-A"),
            DependencyNode("tool-B"),
            DependencyNode("tool-C", precondition_ids=["tool-A", "tool-B"]),
            DependencyNode("tool-D", precondition_ids=["tool-C"]),
        ]
        graph = build_dependency_graph(nodes)
        order = topological_sort(graph)
        
        assert len(order) == 4
        # Verify dependencies are ordered correctly
        assert order.index("tool-A") < order.index("tool-C")
        assert order.index("tool-B") < order.index("tool-C")
        assert order.index("tool-C") < order.index("tool-D")


class TestAcceptanceCriteria:
    """Test acceptance criteria."""
    
    def test_ac1_preconditions_tracked(self):
        """AC1: Preconditions tracked for each capability."""
        node = DependencyNode("tool-B", precondition_ids=["tool-A"])
        assert "tool-A" in node.precondition_ids
    
    def test_ac2_transitive_dependencies(self):
        """AC2: Dependency chains resolved (transitive)."""
        nodes = [
            DependencyNode("tool-A"),
            DependencyNode("tool-B", precondition_ids=["tool-A"]),
            DependencyNode("tool-C", precondition_ids=["tool-B"]),
        ]
        graph = build_dependency_graph(nodes)
        
        # A transitively depends on C
        assert nx.has_path(graph, "tool-A", "tool-C")
    
    def test_ac3_circular_dependency_detection(self):
        """AC3: Circular dependencies detected."""
        graph = nx.DiGraph()
        graph.add_edges_from([("A", "B"), ("B", "C"), ("C", "A")])
        cycles = detect_circular_dependencies(graph)
        
        assert len(cycles) > 0
    
    def test_ac4_topological_sort(self):
        """AC4: Topological sort of tools by dependency order."""
        nodes = [
            DependencyNode("A"),
            DependencyNode("B", precondition_ids=["A"]),
            DependencyNode("C", precondition_ids=["A", "B"]),
        ]
        graph = build_dependency_graph(nodes)
        order = topological_sort(graph)
        
        assert order.index("A") < order.index("B")
        assert order.index("B") < order.index("C")
    
    def test_ac5_execution_sequence(self):
        """AC5: Recommended execution sequence returned."""
        nodes = [
            DependencyNode("ReconTool"),
            DependencyNode("ScanTool", precondition_ids=["ReconTool"]),
            DependencyNode("ExploitTool", precondition_ids=["ScanTool"]),
        ]
        graph = build_dependency_graph(nodes)
        sequence = topological_sort(graph)
        
        assert sequence == ["ReconTool", "ScanTool", "ExploitTool"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
