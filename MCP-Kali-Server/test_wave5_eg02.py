#!/usr/bin/env python3
"""
test_wave5_eg02.py — Wave 5 Task 5.2 : EvidenceGraph.build()
==============================================================

Vérifie que build(finding, signals) construit correctement le graphe de
preuves conformément à la spec tasks.md §5.2.

Couverture :
 1.  Nœud hypothèse racine créé
 2.  root_hypothesis pointe vers ce nœud
 3.  finding_type propagé
 4.  Ajout de 3 signaux → 3 nœuds SIGNAL
 5.  Ajout de 2 preuves → 2 nœuds PROOF
 6.  Total nœuds : 1 hyp + 3 sig + 2 proof = 6
 7.  Arêtes signal → hypothèse présentes (relationship='confirms')
 8.  Arêtes proof → hypothèse présentes (relationship='proves')
 9.  confirmed_proofs contient les 2 nœuds PROOF
10.  unconfirmed_signals identifie les signaux sans preuve correspondante
11.  Graphe retourné non gelé
12.  evidence_status = CONFIRMED quand des preuves existent
13.  evidence_status = OBSERVED quand que des signaux, pas de preuves
14.  evidence_status = NOT_TESTED quand ni signaux ni preuves
15.  confidence_score = n_proofs / (n_proofs + n_signals)
16.  build() avec liste de signaux vide
17.  build() avec evidence vide
18.  Compatibilité 5.1 : les 39 tests de eg01 restent verts
"""

import datetime
import uuid
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from kali_mcp_server import (
    EvidenceGraph, EvidenceNode, EvidenceEdge, EvidenceType,
    StandardFinding, FindingStatus, Signal,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(finding_type="SSRF", status=FindingStatus.OBSERVED,
                 confidence=0.5, evidence=None):
    """Crée un StandardFinding minimal."""
    f = StandardFinding(finding_type=finding_type)
    f.status = status
    f.confidence = confidence
    f.evidence = evidence if evidence is not None else {}
    return f


def make_signal(sig_type="response_diff", confidence=0.6, source_tool="scanner"):
    """Crée un Signal minimal."""
    return Signal(
        type=sig_type,
        description=f"Signal of type {sig_type}",
        confidence=confidence,
        source_tool=source_tool,
        timestamp=datetime.datetime.utcnow(),
    )


# ---------------------------------------------------------------------------
# Test 1 — nœud hypothèse racine créé
# ---------------------------------------------------------------------------

def test_build_creates_hypothesis_root_node():
    finding = make_finding()
    graph = EvidenceGraph.build(finding, [])
    assert graph.root_hypothesis is not None
    hyp_node = graph.get_node(graph.root_hypothesis)
    assert hyp_node is not None, "root_hypothesis node_id doit exister dans le graphe"


# ---------------------------------------------------------------------------
# Test 2 — root_hypothesis pointe vers le bon nœud
# ---------------------------------------------------------------------------

def test_build_root_hypothesis_is_in_nodes():
    finding = make_finding(finding_type="SSTI")
    graph = EvidenceGraph.build(finding, [])
    node = graph.get_node(graph.root_hypothesis)
    assert node is not None
    # Le nœud doit contenir la classe d'hypothèse
    assert "SSTI" in str(node.data)


# ---------------------------------------------------------------------------
# Test 3 — finding_type propagé sur le graphe
# ---------------------------------------------------------------------------

def test_build_propagates_finding_type():
    finding = make_finding(finding_type="IDOR")
    graph = EvidenceGraph.build(finding, [])
    assert graph.finding_type == "IDOR"


# ---------------------------------------------------------------------------
# Test 4 — 3 signaux → 3 nœuds SIGNAL (hors nœud hypothèse)
# ---------------------------------------------------------------------------

def test_build_creates_signal_nodes():
    finding = make_finding()
    signals = [make_signal(f"sig_{i}") for i in range(3)]
    graph = EvidenceGraph.build(finding, signals)
    signal_nodes = [n for n in graph.nodes.values()
                    if n.evidence_type == EvidenceType.SIGNAL
                    and n.metadata.get("role") != "root_hypothesis"]
    assert len(signal_nodes) == 3


# ---------------------------------------------------------------------------
# Test 5 — 2 preuves dans evidence → 2 nœuds PROOF
# ---------------------------------------------------------------------------

def test_build_creates_proof_nodes():
    evidence = {
        "metadata_retrieved": {"tool_name": "ssrf_hunter", "confidence": 0.9},
        "ami_id_found":       {"tool_name": "ssrf_hunter", "confidence": 0.95},
    }
    finding = make_finding(evidence=evidence)
    graph = EvidenceGraph.build(finding, [])
    proof_nodes = [n for n in graph.nodes.values()
                   if n.evidence_type == EvidenceType.PROOF]
    assert len(proof_nodes) == 2


# ---------------------------------------------------------------------------
# Test 6 — total de nœuds (1 hyp + 3 sig + 2 proof = 6)
# ---------------------------------------------------------------------------

def test_build_node_count_ssrf_example():
    evidence = {
        "metadata_retrieved": {"tool_name": "ssrf_hunter", "confidence": 0.9},
        "ami_id_found":       {"tool_name": "ssrf_hunter", "confidence": 0.95},
    }
    finding = make_finding(evidence=evidence)
    signals = [make_signal() for _ in range(3)]
    graph = EvidenceGraph.build(finding, signals)
    assert len(graph.nodes) == 6, f"Attendu 6 nœuds, obtenu {len(graph.nodes)}"


# ---------------------------------------------------------------------------
# Test 7 — arêtes signal → hypothèse avec relationship='confirms'
# ---------------------------------------------------------------------------

def test_build_signal_edges_relationship_confirms():
    finding = make_finding()
    signals = [make_signal("timing_anomaly", confidence=0.7)]
    graph = EvidenceGraph.build(finding, signals)
    signal_nodes = [n for n in graph.nodes.values()
                    if n.evidence_type == EvidenceType.SIGNAL
                    and n.metadata.get("role") != "root_hypothesis"]
    assert signal_nodes, "Doit avoir au moins 1 nœud signal"
    sig_node = signal_nodes[0]
    out_edges = graph.outgoing_edges(sig_node.node_id)
    assert len(out_edges) == 1
    assert out_edges[0].relationship == "confirms"
    assert out_edges[0].target_node_id == graph.root_hypothesis


# ---------------------------------------------------------------------------
# Test 8 — arêtes proof → hypothèse avec relationship='proves'
# ---------------------------------------------------------------------------

def test_build_proof_edges_relationship_proves():
    evidence = {"ssrf_confirmed": {"tool_name": "t", "confidence": 0.9}}
    finding = make_finding(evidence=evidence)
    graph = EvidenceGraph.build(finding, [])
    proof_nodes = [n for n in graph.nodes.values()
                   if n.evidence_type == EvidenceType.PROOF]
    assert proof_nodes, "Doit avoir au moins 1 nœud proof"
    pn = proof_nodes[0]
    out_edges = graph.outgoing_edges(pn.node_id)
    assert len(out_edges) == 1
    assert out_edges[0].relationship == "proves"
    assert out_edges[0].target_node_id == graph.root_hypothesis


# ---------------------------------------------------------------------------
# Test 9 — confirmed_proofs contient les nœuds PROOF
# ---------------------------------------------------------------------------

def test_build_confirmed_proofs_populated():
    evidence = {
        "sqli_error_returned": {"tool_name": "sqlmap", "confidence": 1.0},
        "data_extracted":      {"tool_name": "sqlmap", "confidence": 1.0},
    }
    finding = make_finding(evidence=evidence)
    graph = EvidenceGraph.build(finding, [])
    assert len(graph.confirmed_proofs) == 2
    for proof_node in graph.confirmed_proofs:
        assert isinstance(proof_node, EvidenceNode)
        assert proof_node.evidence_type == EvidenceType.PROOF


# ---------------------------------------------------------------------------
# Test 10 — unconfirmed_signals : signaux sans preuve correspondante
# ---------------------------------------------------------------------------

def test_build_unconfirmed_signals_identified():
    # Proof key = "size_diff_detected", signal type = "timing_anomaly" → pas de match
    evidence = {"size_diff_detected": {"tool_name": "scanner", "confidence": 0.8}}
    finding = make_finding(evidence=evidence)
    signals = [
        make_signal("timing_anomaly"),   # type ne matche pas la clé proof
        make_signal("size_diff_detected"),  # type matche → confirmé
    ]
    graph = EvidenceGraph.build(finding, signals)
    unconfirmed_types = [n.data.get("type") for n in graph.unconfirmed_signals]
    assert "timing_anomaly" in unconfirmed_types
    assert "size_diff_detected" not in unconfirmed_types


# ---------------------------------------------------------------------------
# Test 11 — graphe non gelé après build()
# ---------------------------------------------------------------------------

def test_build_returns_non_frozen_graph():
    finding = make_finding()
    graph = EvidenceGraph.build(finding, [])
    assert not graph.is_frozen()


# ---------------------------------------------------------------------------
# Test 12 — evidence_status = CONFIRMED quand des preuves existent
# ---------------------------------------------------------------------------

def test_build_status_confirmed_with_proofs():
    evidence = {"xss_executed": {"tool_name": "burp", "confidence": 1.0}}
    finding = make_finding(evidence=evidence)
    graph = EvidenceGraph.build(finding, [make_signal()])
    assert graph.evidence_status == FindingStatus.CONFIRMED


# ---------------------------------------------------------------------------
# Test 13 — evidence_status = OBSERVED quand signaux seulement
# ---------------------------------------------------------------------------

def test_build_status_observed_signals_only():
    finding = make_finding(evidence={})
    graph = EvidenceGraph.build(finding, [make_signal()])
    assert graph.evidence_status == FindingStatus.OBSERVED


# ---------------------------------------------------------------------------
# Test 14 — evidence_status = NOT_TESTED quand ni signaux ni preuves
# ---------------------------------------------------------------------------

def test_build_status_not_tested_empty():
    finding = make_finding(evidence={})
    graph = EvidenceGraph.build(finding, [])
    assert graph.evidence_status == FindingStatus.NOT_TESTED


# ---------------------------------------------------------------------------
# Test 15 — confidence_score = n_proofs / (n_proofs + n_signals)
# ---------------------------------------------------------------------------

def test_build_confidence_score_formula():
    evidence = {"proof_a": {"confidence": 1.0}}   # 1 proof
    finding = make_finding(evidence=evidence)
    signals = [make_signal(), make_signal()]        # 2 signals
    graph = EvidenceGraph.build(finding, signals)
    expected = 1 / (1 + 2)
    assert abs(graph.confidence_score - expected) < 1e-9, \
        f"Attendu {expected}, obtenu {graph.confidence_score}"


# ---------------------------------------------------------------------------
# Test 16 — build() avec liste de signaux vide
# ---------------------------------------------------------------------------

def test_build_empty_signals():
    finding = make_finding()
    graph = EvidenceGraph.build(finding, [])
    # Doit avoir au moins le nœud hypothèse
    assert len(graph.nodes) >= 1
    assert graph.root_hypothesis is not None
    assert graph.unconfirmed_signals == []


# ---------------------------------------------------------------------------
# Test 17 — build() avec evidence vide
# ---------------------------------------------------------------------------

def test_build_empty_evidence():
    finding = make_finding(evidence={})
    signals = [make_signal("response_size_diff", confidence=0.55)]
    graph = EvidenceGraph.build(finding, signals)
    assert graph.confirmed_proofs == []
    proof_nodes = [n for n in graph.nodes.values()
                   if n.evidence_type == EvidenceType.PROOF]
    assert proof_nodes == []


# ---------------------------------------------------------------------------
# Test 18 — confidence_score = 0.0 quand rien du tout
# ---------------------------------------------------------------------------

def test_build_confidence_score_zero_when_empty():
    finding = make_finding(evidence={})
    graph = EvidenceGraph.build(finding, [])
    assert graph.confidence_score == 0.0


# ---------------------------------------------------------------------------
# Test 19 — proof confidence propagée dans le nœud
# ---------------------------------------------------------------------------

def test_build_proof_node_confidence_from_evidence():
    evidence = {"proof_key": {"tool_name": "t", "confidence": 0.88}}
    finding = make_finding(evidence=evidence)
    graph = EvidenceGraph.build(finding, [])
    proof_nodes = [n for n in graph.nodes.values()
                   if n.evidence_type == EvidenceType.PROOF]
    assert len(proof_nodes) == 1
    assert abs(proof_nodes[0].confidence - 0.88) < 1e-9


# ---------------------------------------------------------------------------
# Test 20 — signal weight dans l'arête = signal.confidence
# ---------------------------------------------------------------------------

def test_build_signal_edge_weight_equals_confidence():
    finding = make_finding()
    sig = make_signal("timing", confidence=0.73)
    graph = EvidenceGraph.build(finding, [sig])
    signal_nodes = [n for n in graph.nodes.values()
                    if n.evidence_type == EvidenceType.SIGNAL
                    and n.metadata.get("role") != "root_hypothesis"]
    assert signal_nodes
    edge = graph.outgoing_edges(signal_nodes[0].node_id)[0]
    assert abs(edge.strength - 0.73) < 1e-9


# ---------------------------------------------------------------------------
# Test 21 — proof edge weight = 1.0
# ---------------------------------------------------------------------------

def test_build_proof_edge_weight_is_one():
    evidence = {"direct_evidence": {"confidence": 0.5}}
    finding = make_finding(evidence=evidence)
    graph = EvidenceGraph.build(finding, [])
    proof_nodes = [n for n in graph.nodes.values()
                   if n.evidence_type == EvidenceType.PROOF]
    edge = graph.outgoing_edges(proof_nodes[0].node_id)[0]
    assert edge.strength == 1.0


# ---------------------------------------------------------------------------
# Test 22 — toutes les arêtes pointent vers le nœud hypothèse
# ---------------------------------------------------------------------------

def test_build_all_edges_point_to_hypothesis():
    evidence = {"p1": {"confidence": 1.0}}
    finding = make_finding(evidence=evidence)
    signals = [make_signal() for _ in range(2)]
    graph = EvidenceGraph.build(finding, signals)
    for edge in graph.edges.values():
        assert edge.target_node_id == graph.root_hypothesis, \
            f"Arête {edge.edge_id} ne pointe pas vers l'hypothèse"


# ---------------------------------------------------------------------------
# Test 23 — nombre correct d'arêtes
# ---------------------------------------------------------------------------

def test_build_edge_count():
    evidence = {"p1": {}, "p2": {}}   # 2 proofs
    finding = make_finding(evidence=evidence)
    signals = [make_signal() for _ in range(3)]  # 3 signals
    graph = EvidenceGraph.build(finding, signals)
    # 3 sig edges + 2 proof edges = 5
    assert len(graph.edges) == 5


# ---------------------------------------------------------------------------
# Test 24 — finding_type différents produisent des graphes distincts
# ---------------------------------------------------------------------------

def test_build_different_finding_types_different_graphs():
    g1 = EvidenceGraph.build(make_finding("SSRF"), [])
    g2 = EvidenceGraph.build(make_finding("SQLi"), [])
    assert g1.finding_type != g2.finding_type
    assert g1.graph_id != g2.graph_id
    assert g1.root_hypothesis != g2.root_hypothesis


# ---------------------------------------------------------------------------
# Test 25 — source_tool propagé depuis Signal vers EvidenceNode
# ---------------------------------------------------------------------------

def test_build_signal_source_tool_propagated():
    finding = make_finding()
    sig = Signal(type="anomaly", confidence=0.5, source_tool="nuclei")
    graph = EvidenceGraph.build(finding, [sig])
    signal_nodes = [n for n in graph.nodes.values()
                    if n.evidence_type == EvidenceType.SIGNAL
                    and n.metadata.get("role") != "root_hypothesis"]
    assert signal_nodes[0].source_tool == "nuclei"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
