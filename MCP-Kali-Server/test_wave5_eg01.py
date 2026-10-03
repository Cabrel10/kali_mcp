#!/usr/bin/env python3
"""
Test Suite for Wave 5 Evidence Graph Data Structures
=====================================================

Tests for EvidenceNode, EvidenceEdge, and EvidenceGraph classes.
Covers instantiation, data validation, graph operations, and freezing.

Tests:
1. EvidenceNode instantiation with all fields
2. EvidenceNode with different EvidenceType values
3. EvidenceNode confidence bounds (0.0-1.0)
4. EvidenceEdge instantiation
5. EvidenceEdge strength bounds
6. EvidenceGraph creation
7. add_node() functionality
8. add_edge() functionality
9. get_node() retrieval
10. get_edge() retrieval
11. incoming_edges() for a node
12. outgoing_edges() for a node
13. is_frozen() before/after freeze()
14. freeze() prevents add_node()
15. freeze() prevents add_edge()
16. Large graph with 50+ nodes and edges
17. Edge connecting non-existent nodes (should be allowed)
18. Graph with cycles allowed
"""

import pytest
import datetime
import uuid
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from kali_mcp_server import EvidenceType, EvidenceNode, EvidenceEdge, EvidenceGraph


class TestEvidenceNode:
    """Tests for EvidenceNode dataclass."""
    
    def test_evidence_node_instantiation_with_all_fields(self):
        """Test 1: EvidenceNode instantiation with all fields."""
        node_id = str(uuid.uuid4())
        finding_id = str(uuid.uuid4())
        timestamp = datetime.datetime.utcnow()
        data = {"status": "confirmed", "severity": "high"}
        metadata = {"source": "test", "version": "1.0"}
        
        node = EvidenceNode(
            node_id=node_id,
            evidence_type=EvidenceType.PROOF,
            source_tool="nuclei",
            finding_id=finding_id,
            data=data,
            timestamp=timestamp,
            confidence=0.95,
            metadata=metadata
        )
        
        assert node.node_id == node_id
        assert node.evidence_type == EvidenceType.PROOF
        assert node.source_tool == "nuclei"
        assert node.finding_id == finding_id
        assert node.data == data
        assert node.timestamp == timestamp
        assert node.confidence == 0.95
        assert node.metadata == metadata
    
    def test_evidence_node_direct_output_type(self):
        """Test 2a: EvidenceNode with DIRECT_OUTPUT type."""
        node = EvidenceNode(
            node_id=str(uuid.uuid4()),
            evidence_type=EvidenceType.DIRECT_OUTPUT,
            source_tool="nikto",
            finding_id=str(uuid.uuid4()),
            data={"raw_output": "server banner: Apache/2.4.41"},
            timestamp=datetime.datetime.utcnow(),
            confidence=0.5
        )
        assert node.evidence_type == EvidenceType.DIRECT_OUTPUT
    
    def test_evidence_node_signal_type(self):
        """Test 2b: EvidenceNode with SIGNAL type."""
        node = EvidenceNode(
            node_id=str(uuid.uuid4()),
            evidence_type=EvidenceType.SIGNAL,
            source_tool="sqlmap",
            finding_id=str(uuid.uuid4()),
            data={"response_time_ms": 5000},
            timestamp=datetime.datetime.utcnow(),
            confidence=0.6
        )
        assert node.evidence_type == EvidenceType.SIGNAL
    
    def test_evidence_node_proof_type(self):
        """Test 2c: EvidenceNode with PROOF type."""
        node = EvidenceNode(
            node_id=str(uuid.uuid4()),
            evidence_type=EvidenceType.PROOF,
            source_tool="burp",
            finding_id=str(uuid.uuid4()),
            data={"extracted_data": "admin_password"},
            timestamp=datetime.datetime.utcnow(),
            confidence=0.9
        )
        assert node.evidence_type == EvidenceType.PROOF
    
    def test_evidence_node_classification_type(self):
        """Test 2d: EvidenceNode with CLASSIFICATION type."""
        node = EvidenceNode(
            node_id=str(uuid.uuid4()),
            evidence_type=EvidenceType.CLASSIFICATION,
            source_tool="orchestrator",
            finding_id=str(uuid.uuid4()),
            data={"status": "CONFIRMED", "risk_level": "critical"},
            timestamp=datetime.datetime.utcnow(),
            confidence=0.99
        )
        assert node.evidence_type == EvidenceType.CLASSIFICATION
    
    def test_evidence_node_confidence_lower_bound(self):
        """Test 3a: EvidenceNode with confidence at 0.0 (lower bound)."""
        node = EvidenceNode(
            node_id=str(uuid.uuid4()),
            evidence_type=EvidenceType.SIGNAL,
            source_tool="test",
            finding_id=str(uuid.uuid4()),
            data={},
            timestamp=datetime.datetime.utcnow(),
            confidence=0.0
        )
        assert node.confidence == 0.0
    
    def test_evidence_node_confidence_upper_bound(self):
        """Test 3b: EvidenceNode with confidence at 1.0 (upper bound)."""
        node = EvidenceNode(
            node_id=str(uuid.uuid4()),
            evidence_type=EvidenceType.PROOF,
            source_tool="test",
            finding_id=str(uuid.uuid4()),
            data={},
            timestamp=datetime.datetime.utcnow(),
            confidence=1.0
        )
        assert node.confidence == 1.0
    
    def test_evidence_node_confidence_mid_range(self):
        """Test 3c: EvidenceNode with confidence in middle (0.5)."""
        node = EvidenceNode(
            node_id=str(uuid.uuid4()),
            evidence_type=EvidenceType.SIGNAL,
            source_tool="test",
            finding_id=str(uuid.uuid4()),
            data={},
            timestamp=datetime.datetime.utcnow(),
            confidence=0.5
        )
        assert node.confidence == 0.5
    
    def test_evidence_node_confidence_below_range_raises(self):
        """Test 3d: EvidenceNode with confidence below 0.0 raises ValueError."""
        with pytest.raises(ValueError, match="confidence must be in"):
            EvidenceNode(
                node_id=str(uuid.uuid4()),
                evidence_type=EvidenceType.SIGNAL,
                source_tool="test",
                finding_id=str(uuid.uuid4()),
                data={},
                timestamp=datetime.datetime.utcnow(),
                confidence=-0.1
            )
    
    def test_evidence_node_confidence_above_range_raises(self):
        """Test 3e: EvidenceNode with confidence above 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="confidence must be in"):
            EvidenceNode(
                node_id=str(uuid.uuid4()),
                evidence_type=EvidenceType.SIGNAL,
                source_tool="test",
                finding_id=str(uuid.uuid4()),
                data={},
                timestamp=datetime.datetime.utcnow(),
                confidence=1.1
            )
    
    def test_evidence_node_default_metadata(self):
        """Test 3f: EvidenceNode with default empty metadata."""
        node = EvidenceNode(
            node_id=str(uuid.uuid4()),
            evidence_type=EvidenceType.SIGNAL,
            source_tool="test",
            finding_id=str(uuid.uuid4()),
            data={},
            timestamp=datetime.datetime.utcnow(),
            confidence=0.5
        )
        assert node.metadata == {}


class TestEvidenceEdge:
    """Tests for EvidenceEdge dataclass."""
    
    def test_evidence_edge_instantiation(self):
        """Test 4: EvidenceEdge instantiation with all fields."""
        edge_id = str(uuid.uuid4())
        source_id = str(uuid.uuid4())
        target_id = str(uuid.uuid4())
        metadata = {"reason": "shared tool", "weight": 0.8}
        
        edge = EvidenceEdge(
            edge_id=edge_id,
            source_node_id=source_id,
            target_node_id=target_id,
            relationship="confirms",
            strength=0.85,
            metadata=metadata
        )
        
        assert edge.edge_id == edge_id
        assert edge.source_node_id == source_id
        assert edge.target_node_id == target_id
        assert edge.relationship == "confirms"
        assert edge.strength == 0.85
        assert edge.metadata == metadata
    
    def test_evidence_edge_strength_lower_bound(self):
        """Test 5a: EvidenceEdge with strength at 0.0 (lower bound)."""
        edge = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=str(uuid.uuid4()),
            target_node_id=str(uuid.uuid4()),
            relationship="weakens",
            strength=0.0
        )
        assert edge.strength == 0.0
    
    def test_evidence_edge_strength_upper_bound(self):
        """Test 5b: EvidenceEdge with strength at 1.0 (upper bound)."""
        edge = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=str(uuid.uuid4()),
            target_node_id=str(uuid.uuid4()),
            relationship="confirms",
            strength=1.0
        )
        assert edge.strength == 1.0
    
    def test_evidence_edge_strength_mid_range(self):
        """Test 5c: EvidenceEdge with strength in middle (0.5)."""
        edge = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=str(uuid.uuid4()),
            target_node_id=str(uuid.uuid4()),
            relationship="amplifies",
            strength=0.5
        )
        assert edge.strength == 0.5
    
    def test_evidence_edge_strength_below_range_raises(self):
        """Test 5d: EvidenceEdge with strength below 0.0 raises ValueError."""
        with pytest.raises(ValueError, match="strength must be in"):
            EvidenceEdge(
                edge_id=str(uuid.uuid4()),
                source_node_id=str(uuid.uuid4()),
                target_node_id=str(uuid.uuid4()),
                relationship="confirms",
                strength=-0.1
            )
    
    def test_evidence_edge_strength_above_range_raises(self):
        """Test 5e: EvidenceEdge with strength above 1.0 raises ValueError."""
        with pytest.raises(ValueError, match="strength must be in"):
            EvidenceEdge(
                edge_id=str(uuid.uuid4()),
                source_node_id=str(uuid.uuid4()),
                target_node_id=str(uuid.uuid4()),
                relationship="confirms",
                strength=1.5
            )
    
    def test_evidence_edge_default_metadata(self):
        """Test 5f: EvidenceEdge with default empty metadata."""
        edge = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=str(uuid.uuid4()),
            target_node_id=str(uuid.uuid4()),
            relationship="confirms",
            strength=0.5
        )
        assert edge.metadata == {}


class TestEvidenceGraph:
    """Tests for EvidenceGraph class."""
    
    def test_evidence_graph_creation(self):
        """Test 6: EvidenceGraph creation initializes properly."""
        graph = EvidenceGraph()
        
        assert isinstance(graph.graph_id, str)
        assert len(graph.graph_id) > 0  # UUID string should be non-empty
        assert graph.nodes == {}
        assert graph.edges == {}
        assert isinstance(graph.created_timestamp, datetime.datetime)
        assert graph.frozen_after is None
    
    def test_add_node_functionality(self):
        """Test 7: add_node() adds node to graph."""
        graph = EvidenceGraph()
        node = EvidenceNode(
            node_id=str(uuid.uuid4()),
            evidence_type=EvidenceType.PROOF,
            source_tool="test",
            finding_id=str(uuid.uuid4()),
            data={},
            timestamp=datetime.datetime.utcnow(),
            confidence=0.9
        )
        
        graph.add_node(node)
        assert node.node_id in graph.nodes
        assert graph.nodes[node.node_id] == node
    
    def test_add_node_duplicate_raises(self):
        """Test 7b: add_node() with duplicate node_id raises ValueError."""
        graph = EvidenceGraph()
        node_id = str(uuid.uuid4())
        node1 = EvidenceNode(
            node_id=node_id,
            evidence_type=EvidenceType.PROOF,
            source_tool="test",
            finding_id=str(uuid.uuid4()),
            data={},
            timestamp=datetime.datetime.utcnow(),
            confidence=0.9
        )
        node2 = EvidenceNode(
            node_id=node_id,
            evidence_type=EvidenceType.SIGNAL,
            source_tool="test",
            finding_id=str(uuid.uuid4()),
            data={},
            timestamp=datetime.datetime.utcnow(),
            confidence=0.5
        )
        
        graph.add_node(node1)
        with pytest.raises(ValueError, match="already exists"):
            graph.add_node(node2)
    
    def test_add_edge_functionality(self):
        """Test 8: add_edge() adds edge to graph."""
        graph = EvidenceGraph()
        edge = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=str(uuid.uuid4()),
            target_node_id=str(uuid.uuid4()),
            relationship="confirms",
            strength=0.8
        )
        
        graph.add_edge(edge)
        assert edge.edge_id in graph.edges
        assert graph.edges[edge.edge_id] == edge
    
    def test_add_edge_duplicate_raises(self):
        """Test 8b: add_edge() with duplicate edge_id raises ValueError."""
        graph = EvidenceGraph()
        edge_id = str(uuid.uuid4())
        source_id = str(uuid.uuid4())
        target_id = str(uuid.uuid4())
        
        edge1 = EvidenceEdge(
            edge_id=edge_id,
            source_node_id=source_id,
            target_node_id=target_id,
            relationship="confirms",
            strength=0.8
        )
        edge2 = EvidenceEdge(
            edge_id=edge_id,
            source_node_id=source_id,
            target_node_id=target_id,
            relationship="amplifies",
            strength=0.7
        )
        
        graph.add_edge(edge1)
        with pytest.raises(ValueError, match="already exists"):
            graph.add_edge(edge2)
    
    def test_add_edge_nonexistent_nodes_allowed(self):
        """Test 8c: add_edge() allows edges to non-existent nodes."""
        graph = EvidenceGraph()
        
        # Add edge with node IDs that don't exist in graph
        edge = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=str(uuid.uuid4()),
            target_node_id=str(uuid.uuid4()),
            relationship="confirms",
            strength=0.8
        )
        
        # Should not raise
        graph.add_edge(edge)
        assert edge.edge_id in graph.edges
    
    def test_get_node_retrieval(self):
        """Test 9: get_node() retrieves node by ID."""
        graph = EvidenceGraph()
        node = EvidenceNode(
            node_id=str(uuid.uuid4()),
            evidence_type=EvidenceType.PROOF,
            source_tool="test",
            finding_id=str(uuid.uuid4()),
            data={},
            timestamp=datetime.datetime.utcnow(),
            confidence=0.9
        )
        
        graph.add_node(node)
        retrieved = graph.get_node(node.node_id)
        
        assert retrieved is not None
        assert retrieved == node
        assert retrieved.evidence_type == EvidenceType.PROOF
    
    def test_get_node_not_found_returns_none(self):
        """Test 9b: get_node() returns None for non-existent node."""
        graph = EvidenceGraph()
        retrieved = graph.get_node(str(uuid.uuid4()))
        
        assert retrieved is None
    
    def test_get_edge_retrieval(self):
        """Test 10: get_edge() retrieves edge by ID."""
        graph = EvidenceGraph()
        edge = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=str(uuid.uuid4()),
            target_node_id=str(uuid.uuid4()),
            relationship="confirms",
            strength=0.8
        )
        
        graph.add_edge(edge)
        retrieved = graph.get_edge(edge.edge_id)
        
        assert retrieved is not None
        assert retrieved == edge
        assert retrieved.relationship == "confirms"
    
    def test_get_edge_not_found_returns_none(self):
        """Test 10b: get_edge() returns None for non-existent edge."""
        graph = EvidenceGraph()
        retrieved = graph.get_edge(str(uuid.uuid4()))
        
        assert retrieved is None
    
    def test_incoming_edges_for_node(self):
        """Test 11: incoming_edges() returns all edges targeting a node."""
        graph = EvidenceGraph()
        target_id = str(uuid.uuid4())
        source1_id = str(uuid.uuid4())
        source2_id = str(uuid.uuid4())
        
        edge1 = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=source1_id,
            target_node_id=target_id,
            relationship="confirms",
            strength=0.8
        )
        edge2 = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=source2_id,
            target_node_id=target_id,
            relationship="amplifies",
            strength=0.9
        )
        # This edge should not be included (different target)
        edge3 = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=source1_id,
            target_node_id=str(uuid.uuid4()),
            relationship="confirms",
            strength=0.7
        )
        
        graph.add_edge(edge1)
        graph.add_edge(edge2)
        graph.add_edge(edge3)
        
        incoming = graph.incoming_edges(target_id)
        
        assert len(incoming) == 2
        assert edge1 in incoming
        assert edge2 in incoming
        assert edge3 not in incoming
    
    def test_incoming_edges_empty_for_unconnected_node(self):
        """Test 11b: incoming_edges() returns empty list for unconnected node."""
        graph = EvidenceGraph()
        target_id = str(uuid.uuid4())
        
        incoming = graph.incoming_edges(target_id)
        
        assert incoming == []
    
    def test_outgoing_edges_for_node(self):
        """Test 12: outgoing_edges() returns all edges from a node."""
        graph = EvidenceGraph()
        source_id = str(uuid.uuid4())
        target1_id = str(uuid.uuid4())
        target2_id = str(uuid.uuid4())
        
        edge1 = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=source_id,
            target_node_id=target1_id,
            relationship="confirms",
            strength=0.8
        )
        edge2 = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=source_id,
            target_node_id=target2_id,
            relationship="amplifies",
            strength=0.9
        )
        # This edge should not be included (different source)
        edge3 = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=str(uuid.uuid4()),
            target_node_id=target1_id,
            relationship="confirms",
            strength=0.7
        )
        
        graph.add_edge(edge1)
        graph.add_edge(edge2)
        graph.add_edge(edge3)
        
        outgoing = graph.outgoing_edges(source_id)
        
        assert len(outgoing) == 2
        assert edge1 in outgoing
        assert edge2 in outgoing
        assert edge3 not in outgoing
    
    def test_outgoing_edges_empty_for_unconnected_node(self):
        """Test 12b: outgoing_edges() returns empty list for unconnected node."""
        graph = EvidenceGraph()
        source_id = str(uuid.uuid4())
        
        outgoing = graph.outgoing_edges(source_id)
        
        assert outgoing == []
    
    def test_is_frozen_before_freeze(self):
        """Test 13a: is_frozen() returns False before freeze()."""
        graph = EvidenceGraph()
        assert graph.is_frozen() is False
    
    def test_is_frozen_after_freeze(self):
        """Test 13b: is_frozen() returns True after freeze()."""
        graph = EvidenceGraph()
        graph.freeze()
        assert graph.is_frozen() is True
    
    def test_freeze_prevents_add_node(self):
        """Test 14: freeze() prevents add_node() with ValueError."""
        graph = EvidenceGraph()
        graph.freeze()
        
        node = EvidenceNode(
            node_id=str(uuid.uuid4()),
            evidence_type=EvidenceType.PROOF,
            source_tool="test",
            finding_id=str(uuid.uuid4()),
            data={},
            timestamp=datetime.datetime.utcnow(),
            confidence=0.9
        )
        
        with pytest.raises(ValueError, match="frozen"):
            graph.add_node(node)
    
    def test_freeze_prevents_add_edge(self):
        """Test 15: freeze() prevents add_edge() with ValueError."""
        graph = EvidenceGraph()
        graph.freeze()
        
        edge = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=str(uuid.uuid4()),
            target_node_id=str(uuid.uuid4()),
            relationship="confirms",
            strength=0.8
        )
        
        with pytest.raises(ValueError, match="frozen"):
            graph.add_edge(edge)
    
    def test_large_graph_with_50_plus_nodes_and_edges(self):
        """Test 16: Large graph with 50+ nodes and 100+ edges."""
        graph = EvidenceGraph()
        
        # Create 60 nodes
        nodes = []
        for i in range(60):
            node = EvidenceNode(
                node_id=str(uuid.uuid4()),
                evidence_type=EvidenceType.PROOF if i % 2 == 0 else EvidenceType.SIGNAL,
                source_tool=f"tool_{i % 5}",
                finding_id=str(uuid.uuid4()),
                data={"index": i},
                timestamp=datetime.datetime.utcnow(),
                confidence=0.5 + (i % 10) * 0.05
            )
            nodes.append(node)
            graph.add_node(node)
        
        # Create 120 edges connecting nodes
        edges = []
        for i in range(120):
            source_idx = i % 60
            target_idx = (i + 1) % 60
            edge = EvidenceEdge(
                edge_id=str(uuid.uuid4()),
                source_node_id=nodes[source_idx].node_id,
                target_node_id=nodes[target_idx].node_id,
                relationship=["confirms", "amplifies", "weakens", "contradicts"][i % 4],
                strength=0.1 + (i % 9) * 0.1
            )
            edges.append(edge)
            graph.add_edge(edge)
        
        assert len(graph.nodes) == 60
        assert len(graph.edges) == 120
        
        # Verify all nodes retrievable
        for node in nodes:
            assert graph.get_node(node.node_id) == node
        
        # Verify all edges retrievable
        for edge in edges:
            assert graph.get_edge(edge.edge_id) == edge
    
    def test_edge_connecting_nonexistent_nodes(self):
        """Test 17: Edge can connect to non-existent nodes (no validation)."""
        graph = EvidenceGraph()
        
        # Create edge with IDs that don't correspond to any nodes in graph
        fake_source = str(uuid.uuid4())
        fake_target = str(uuid.uuid4())
        
        edge = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=fake_source,
            target_node_id=fake_target,
            relationship="confirms",
            strength=0.8
        )
        
        # Should succeed without validation
        graph.add_edge(edge)
        
        # Edge should be retrievable
        assert graph.get_edge(edge.edge_id) == edge
        
        # Incoming/outgoing queries work even for non-existent nodes
        incoming = graph.incoming_edges(fake_target)
        outgoing = graph.outgoing_edges(fake_source)
        
        assert edge in incoming
        assert edge in outgoing
    
    def test_graph_with_cycles_allowed(self):
        """Test 18: Graph allows cycles (no DAG enforcement)."""
        graph = EvidenceGraph()
        
        # Create 3 nodes
        node1_id = str(uuid.uuid4())
        node2_id = str(uuid.uuid4())
        node3_id = str(uuid.uuid4())
        
        node1 = EvidenceNode(
            node_id=node1_id,
            evidence_type=EvidenceType.PROOF,
            source_tool="test",
            finding_id=str(uuid.uuid4()),
            data={},
            timestamp=datetime.datetime.utcnow(),
            confidence=0.9
        )
        node2 = EvidenceNode(
            node_id=node2_id,
            evidence_type=EvidenceType.PROOF,
            source_tool="test",
            finding_id=str(uuid.uuid4()),
            data={},
            timestamp=datetime.datetime.utcnow(),
            confidence=0.9
        )
        node3 = EvidenceNode(
            node_id=node3_id,
            evidence_type=EvidenceType.PROOF,
            source_tool="test",
            finding_id=str(uuid.uuid4()),
            data={},
            timestamp=datetime.datetime.utcnow(),
            confidence=0.9
        )
        
        graph.add_node(node1)
        graph.add_node(node2)
        graph.add_node(node3)
        
        # Create cycle: 1 -> 2 -> 3 -> 1
        edge1 = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=node1_id,
            target_node_id=node2_id,
            relationship="confirms",
            strength=0.8
        )
        edge2 = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=node2_id,
            target_node_id=node3_id,
            relationship="confirms",
            strength=0.8
        )
        edge3 = EvidenceEdge(
            edge_id=str(uuid.uuid4()),
            source_node_id=node3_id,
            target_node_id=node1_id,
            relationship="confirms",
            strength=0.8
        )
        
        # All edges should be added without error (cycles allowed)
        graph.add_edge(edge1)
        graph.add_edge(edge2)
        graph.add_edge(edge3)
        
        assert len(graph.edges) == 3
        
        # Verify cycle is present
        outgoing1 = graph.outgoing_edges(node1_id)
        outgoing2 = graph.outgoing_edges(node2_id)
        outgoing3 = graph.outgoing_edges(node3_id)
        
        assert len(outgoing1) == 1
        assert len(outgoing2) == 1
        assert len(outgoing3) == 1
        
        # Follow cycle: 1 -> 2 -> 3 -> 1
        assert outgoing1[0].target_node_id == node2_id
        assert outgoing2[0].target_node_id == node3_id
        assert outgoing3[0].target_node_id == node1_id


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
