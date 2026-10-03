#!/usr/bin/env python3
"""
TASK-ORCH-05 Test Suite: Evidence Graph Building

Tests:
1. Evidence node creation (findings)
2. Dependency edges between findings (proof chains)
3. Maturity level tracking in graph
4. Graph serialization (JSON export)
5. Query evidence graph (find related findings)
"""

import pytest
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Set
import uuid


class EvidenceMaturity(str, Enum):
    """Evidence maturity levels."""
    OBSERVED = "observed"
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    EXPLOITED = "exploited"


@dataclass
class EvidenceNode:
    """Node in evidence graph (a finding)."""
    node_id: str
    finding_type: str  # SSRF, SSTI, IDOR, etc.
    maturity: EvidenceMaturity
    confidence: float  # 0.0-1.0
    description: str
    proof: Optional[str] = None
    timestamp: str = ""
    tool_used: str = ""


@dataclass
class EvidenceEdge:
    """Edge in evidence graph (proof chain)."""
    source_node_id: str
    target_node_id: str
    relationship: str  # "depends_on", "supports", "contradicts", etc.
    weight: float = 1.0


class EvidenceGraph:
    """Graph of evidence and findings."""
    
    def __init__(self):
        """Initialize evidence graph."""
        self.nodes: Dict[str, EvidenceNode] = {}
        self.edges: Dict[str, EvidenceEdge] = {}
        self.node_count = 0
        self.edge_count = 0
    
    def add_node(self, finding_type: str, maturity: EvidenceMaturity,
                confidence: float, description: str, proof: Optional[str] = None) -> EvidenceNode:
        """Add evidence node (finding) to graph."""
        node_id = f"evidence_{self.node_count}"
        self.node_count += 1
        
        node = EvidenceNode(
            node_id=node_id,
            finding_type=finding_type,
            maturity=maturity,
            confidence=confidence,
            description=description,
            proof=proof
        )
        
        self.nodes[node_id] = node
        return node
    
    def add_edge(self, source_id: str, target_id: str, relationship: str) -> EvidenceEdge:
        """Add dependency edge between findings."""
        if source_id not in self.nodes or target_id not in self.nodes:
            raise ValueError("Source or target node not found")
        
        edge_id = f"edge_{self.edge_count}"
        self.edge_count += 1
        
        edge = EvidenceEdge(
            source_node_id=source_id,
            target_node_id=target_id,
            relationship=relationship
        )
        
        self.edges[edge_id] = edge
        return edge
    
    def get_node_by_finding_type(self, finding_type: str) -> List[EvidenceNode]:
        """Find all nodes of a specific type."""
        return [n for n in self.nodes.values() if n.finding_type == finding_type]
    
    def get_highest_maturity_for_type(self, finding_type: str) -> Optional[EvidenceMaturity]:
        """Get highest maturity level for a finding type."""
        nodes = self.get_node_by_finding_type(finding_type)
        
        if not nodes:
            return None
        
        maturity_order = [EvidenceMaturity.OBSERVED, EvidenceMaturity.SUSPECTED,
                         EvidenceMaturity.CONFIRMED, EvidenceMaturity.EXPLOITED]
        
        highest_idx = 0
        for node in nodes:
            node_idx = maturity_order.index(node.maturity)
            if node_idx > highest_idx:
                highest_idx = node_idx
        
        return maturity_order[highest_idx]
    
    def get_related_findings(self, node_id: str) -> List[str]:
        """Get all related findings (connected nodes)."""
        related = set()
        
        for edge in self.edges.values():
            if edge.source_node_id == node_id:
                related.add(edge.target_node_id)
            elif edge.target_node_id == node_id:
                related.add(edge.source_node_id)
        
        return list(related)
    
    def to_dict(self) -> Dict:
        """Serialize graph to dictionary."""
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "findings": [
                {
                    "id": n.node_id,
                    "type": n.finding_type,
                    "maturity": n.maturity.value,
                    "confidence": n.confidence,
                    "description": n.description
                }
                for n in self.nodes.values()
            ],
            "relationships": [
                {
                    "source": e.source_node_id,
                    "target": e.target_node_id,
                    "relationship": e.relationship
                }
                for e in self.edges.values()
            ]
        }


class TestEvidenceNodeCreation:
    """Test evidence node creation."""
    
    def test_create_single_node(self):
        """Create single evidence node."""
        graph = EvidenceGraph()
        node = graph.add_node(
            "SSTI",
            EvidenceMaturity.CONFIRMED,
            0.95,
            "Template engine found"
        )
        
        assert node.finding_type == "SSTI"
        assert node.maturity == EvidenceMaturity.CONFIRMED
        assert len(graph.nodes) == 1
    
    def test_create_multiple_nodes(self):
        """Create multiple evidence nodes."""
        graph = EvidenceGraph()
        
        node1 = graph.add_node("SSRF", EvidenceMaturity.OBSERVED, 0.5, "Response diff detected")
        node2 = graph.add_node("SSRF", EvidenceMaturity.CONFIRMED, 0.9, "Metadata extracted")
        
        assert len(graph.nodes) == 2
        assert graph.nodes[node1.node_id].maturity == EvidenceMaturity.OBSERVED
        assert graph.nodes[node2.node_id].maturity == EvidenceMaturity.CONFIRMED


class TestEvidenceEdges:
    """Test evidence dependency edges."""
    
    def test_add_edge(self):
        """Add edge between nodes."""
        graph = EvidenceGraph()
        node1 = graph.add_node("SSRF", EvidenceMaturity.OBSERVED, 0.5, "Finding 1")
        node2 = graph.add_node("SSRF", EvidenceMaturity.CONFIRMED, 0.9, "Finding 2")
        
        edge = graph.add_edge(node1.node_id, node2.node_id, "supports")
        
        assert edge.source_node_id == node1.node_id
        assert edge.relationship == "supports"
    
    def test_add_edge_invalid_node(self):
        """Try to add edge with invalid node."""
        graph = EvidenceGraph()
        node = graph.add_node("SSRF", EvidenceMaturity.OBSERVED, 0.5, "Finding")
        
        with pytest.raises(ValueError):
            graph.add_edge(node.node_id, "invalid", "supports")


class TestEvidenceGraphQueries:
    """Test evidence graph queries."""
    
    def test_find_by_type(self):
        """Find all findings of a type."""
        graph = EvidenceGraph()
        
        graph.add_node("SSRF", EvidenceMaturity.OBSERVED, 0.5, "F1")
        graph.add_node("SSRF", EvidenceMaturity.CONFIRMED, 0.9, "F2")
        graph.add_node("XSS", EvidenceMaturity.OBSERVED, 0.6, "F3")
        
        ssrf_findings = graph.get_node_by_finding_type("SSRF")
        xss_findings = graph.get_node_by_finding_type("XSS")
        
        assert len(ssrf_findings) == 2
        assert len(xss_findings) == 1
    
    def test_highest_maturity(self):
        """Get highest maturity for finding type."""
        graph = EvidenceGraph()
        
        graph.add_node("SSTI", EvidenceMaturity.OBSERVED, 0.5, "F1")
        graph.add_node("SSTI", EvidenceMaturity.SUSPECTED, 0.7, "F2")
        graph.add_node("SSTI", EvidenceMaturity.CONFIRMED, 0.9, "F3")
        
        highest = graph.get_highest_maturity_for_type("SSTI")
        
        assert highest == EvidenceMaturity.CONFIRMED
    
    def test_related_findings(self):
        """Get related findings."""
        graph = EvidenceGraph()
        
        node1 = graph.add_node("SSRF", EvidenceMaturity.OBSERVED, 0.5, "F1")
        node2 = graph.add_node("SSRF", EvidenceMaturity.CONFIRMED, 0.9, "F2")
        node3 = graph.add_node("XSS", EvidenceMaturity.OBSERVED, 0.6, "F3")
        
        graph.add_edge(node1.node_id, node2.node_id, "supports")
        graph.add_edge(node2.node_id, node3.node_id, "related_to")
        
        related_to_node1 = graph.get_related_findings(node1.node_id)
        
        assert node2.node_id in related_to_node1


class TestEvidenceGraphSerialization:
    """Test evidence graph serialization."""
    
    def test_serialize_to_dict(self):
        """Serialize graph to dictionary."""
        graph = EvidenceGraph()
        
        node1 = graph.add_node("SSRF", EvidenceMaturity.OBSERVED, 0.5, "F1")
        node2 = graph.add_node("SSRF", EvidenceMaturity.CONFIRMED, 0.9, "F2")
        graph.add_edge(node1.node_id, node2.node_id, "supports")
        
        serialized = graph.to_dict()
        
        assert serialized["nodes"] == 2
        assert serialized["edges"] == 1
        assert len(serialized["findings"]) == 2
        assert len(serialized["relationships"]) == 1


class TestAcceptanceCriteria:
    """Test acceptance criteria."""
    
    def test_ac1_evidence_nodes(self):
        """AC1: Evidence node creation (findings)."""
        graph = EvidenceGraph()
        node = graph.add_node("SSRF", EvidenceMaturity.CONFIRMED, 0.9, "Finding")
        
        assert node.finding_type == "SSRF"
    
    def test_ac2_dependency_edges(self):
        """AC2: Dependency edges between findings."""
        graph = EvidenceGraph()
        n1 = graph.add_node("SSRF", EvidenceMaturity.OBSERVED, 0.5, "F1")
        n2 = graph.add_node("SSRF", EvidenceMaturity.CONFIRMED, 0.9, "F2")
        
        edge = graph.add_edge(n1.node_id, n2.node_id, "supports")
        assert edge.relationship == "supports"
    
    def test_ac3_maturity_tracking(self):
        """AC3: Maturity level tracking in graph."""
        graph = EvidenceGraph()
        graph.add_node("SSTI", EvidenceMaturity.CONFIRMED, 0.9, "Finding")
        
        highest = graph.get_highest_maturity_for_type("SSTI")
        assert highest == EvidenceMaturity.CONFIRMED
    
    def test_ac4_serialization(self):
        """AC4: Graph serialization (JSON export)."""
        graph = EvidenceGraph()
        graph.add_node("SSRF", EvidenceMaturity.OBSERVED, 0.5, "F1")
        
        serialized = graph.to_dict()
        assert isinstance(serialized, dict)
        assert "findings" in serialized
    
    def test_ac5_graph_query(self):
        """AC5: Query evidence graph."""
        graph = EvidenceGraph()
        n1 = graph.add_node("SSRF", EvidenceMaturity.OBSERVED, 0.5, "F1")
        n2 = graph.add_node("SSRF", EvidenceMaturity.CONFIRMED, 0.9, "F2")
        
        graph.add_edge(n1.node_id, n2.node_id, "supports")
        
        related = graph.get_related_findings(n1.node_id)
        assert n2.node_id in related


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
