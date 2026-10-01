#!/usr/bin/env python3
"""
test_wave5_7_precision.py
=========================
Tests pour les tâches qui rendent le MCP fin et précis :

  5.3  evidence_status_from_graph()
  7.1  validate_finding_status()           — pas de CONFIRMED sans preuve
  7.3  validate_evidence_consistency()     — invariants de cohérence
  7.4  update_finding_status() / get_status_history()  — monotonie
  7.5  signals_confirmed_by_proofs()       — corrélation signal-preuve
"""

import datetime
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from kali_mcp_server import (
    EvidenceGraph, EvidenceNode, EvidenceEdge, EvidenceType,
    StandardFinding, FindingStatus, Signal,
    evidence_status_from_graph,
    validate_finding_status,
    validate_evidence_consistency, EvidenceConsistencyError,
    update_finding_status, get_status_history, _STATUS_HISTORY,
    signals_confirmed_by_proofs,
)


# ---------------------------------------------------------------------------
# Helpers communs
# ---------------------------------------------------------------------------

def make_finding(ftype="SSRF", status=FindingStatus.OBSERVED, confidence=0.5, evidence=None):
    f = StandardFinding(finding_type=ftype)
    f.status = status
    f.confidence = confidence
    f.evidence = evidence or {}
    return f

def make_signal(stype="anomaly", conf=0.6):
    return Signal(type=stype, description="test", confidence=conf,
                  source_tool="scanner", timestamp=datetime.datetime.utcnow())

def fresh_id():
    import uuid; return str(uuid.uuid4())


# ============================================================
# 5.3  evidence_status_from_graph()
# ============================================================

class Test53StatusFromGraph:

    def test_confirmed_when_proofs_present(self):
        g = EvidenceGraph.build(
            make_finding(evidence={"proof_a": {"confidence": 1.0}}),
            [make_signal()]
        )
        assert evidence_status_from_graph(g) == FindingStatus.CONFIRMED

    def test_observed_when_signals_only(self):
        g = EvidenceGraph.build(make_finding(evidence={}), [make_signal()])
        assert evidence_status_from_graph(g) == FindingStatus.OBSERVED

    def test_not_tested_when_empty(self):
        g = EvidenceGraph.build(make_finding(evidence={}), [])
        assert evidence_status_from_graph(g) == FindingStatus.NOT_TESTED

    def test_confirmed_beats_signals(self):
        # 1 proof + 5 signals → CONFIRMED (proof wins)
        g = EvidenceGraph.build(
            make_finding(evidence={"p": {}}),
            [make_signal() for _ in range(5)]
        )
        assert evidence_status_from_graph(g) == FindingStatus.CONFIRMED

    def test_matches_graph_field(self):
        # evidence_status_from_graph doit coïncider avec graph.evidence_status
        g = EvidenceGraph.build(
            make_finding(evidence={"p": {}}),
            [make_signal()]
        )
        assert evidence_status_from_graph(g) == g.evidence_status

    def test_confidence_score_one_proof_two_signals(self):
        g = EvidenceGraph.build(
            make_finding(evidence={"p": {}}),
            [make_signal(), make_signal()]
        )
        # n_proofs=1, n_signals=2 → confidence = 1/3
        assert abs(g.confidence_score - 1/3) < 1e-9

    def test_confidence_zero_signals_no_proofs(self):
        g = EvidenceGraph.build(make_finding(evidence={}), [make_signal()])
        assert g.confidence_score == 0.0


# ============================================================
# 7.1  validate_finding_status()
# ============================================================

class Test71StatusValidation:

    def test_confirmed_with_proof_unchanged(self):
        evidence = {"p": {"confidence": 1.0}}
        g = EvidenceGraph.build(make_finding(evidence=evidence), [])
        f = make_finding(status=FindingStatus.CONFIRMED, evidence=evidence)
        result = validate_finding_status(f, g)
        assert result.status == FindingStatus.CONFIRMED

    def test_confirmed_without_proof_capped_to_observed(self):
        g = EvidenceGraph.build(make_finding(evidence={}), [make_signal()])
        f = make_finding(status=FindingStatus.CONFIRMED, evidence={})
        result = validate_finding_status(f, g)
        assert result.status == FindingStatus.OBSERVED

    def test_exploited_no_poc_capped_to_confirmed(self):
        evidence = {"p": {"confidence": 1.0}}
        g = EvidenceGraph.build(make_finding(evidence=evidence), [])
        f = make_finding(status=FindingStatus.EXPLOITED, evidence=evidence)
        # proof_of_concept absent → cap
        result = validate_finding_status(f, g)
        assert result.status == FindingStatus.CONFIRMED

    def test_exploited_no_poc_no_proof_capped_to_observed(self):
        g = EvidenceGraph.build(make_finding(evidence={}), [make_signal()])
        f = make_finding(status=FindingStatus.EXPLOITED, evidence={})
        result = validate_finding_status(f, g)
        assert result.status == FindingStatus.OBSERVED

    def test_observed_unchanged(self):
        g = EvidenceGraph.build(make_finding(evidence={}), [make_signal()])
        f = make_finding(status=FindingStatus.OBSERVED)
        result = validate_finding_status(f, g)
        assert result.status == FindingStatus.OBSERVED

    def test_returns_same_finding_object(self):
        g = EvidenceGraph.build(make_finding(evidence={}), [make_signal()])
        f = make_finding(status=FindingStatus.CONFIRMED)
        result = validate_finding_status(f, g)
        assert result is f  # modifié en place


# ============================================================
# 7.3  validate_evidence_consistency()
# ============================================================

class Test73Consistency:

    def test_confirmed_with_proof_valid(self):
        evidence = {"p": {}}
        g = EvidenceGraph.build(make_finding(evidence=evidence), [])
        f = make_finding(status=FindingStatus.CONFIRMED, evidence=evidence)
        assert validate_evidence_consistency(f, g) is True

    def test_confirmed_no_proof_raises(self):
        g = EvidenceGraph.build(make_finding(evidence={}), [make_signal()])
        f = make_finding(status=FindingStatus.CONFIRMED, evidence={})
        with pytest.raises(EvidenceConsistencyError, match="CONFIRMED"):
            validate_evidence_consistency(f, g)

    def test_observed_signals_no_proof_valid(self):
        g = EvidenceGraph.build(make_finding(evidence={}), [make_signal()])
        f = make_finding(status=FindingStatus.OBSERVED, evidence={})
        assert validate_evidence_consistency(f, g) is True

    def test_observed_with_proof_raises(self):
        # OBSERVED + preuves présentes = incohérent (devrait être CONFIRMED)
        evidence = {"p": {}}
        g = EvidenceGraph.build(make_finding(evidence=evidence), [])
        f = make_finding(status=FindingStatus.OBSERVED, evidence=evidence)
        with pytest.raises(EvidenceConsistencyError, match="OBSERVED"):
            validate_evidence_consistency(f, g)

    def test_observed_no_signals_no_proof_raises(self):
        # OBSERVED sans signaux ni preuves = incohérent
        g = EvidenceGraph.build(make_finding(evidence={}), [])
        f = make_finding(status=FindingStatus.OBSERVED, evidence={})
        with pytest.raises(EvidenceConsistencyError, match="OBSERVED"):
            validate_evidence_consistency(f, g)

    def test_not_tested_empty_graph_valid(self):
        g = EvidenceGraph.build(make_finding(evidence={}), [])
        f = make_finding(status=FindingStatus.NOT_TESTED)
        assert validate_evidence_consistency(f, g) is True


# ============================================================
# 7.4  update_finding_status() / get_status_history()
# ============================================================

class Test74StatusHistory:

    def setup_method(self):
        # Nettoyer le registre global avant chaque test
        _STATUS_HISTORY.clear()

    def test_initial_promotion_accepted(self):
        fid = fresh_id()
        result = update_finding_status(fid, FindingStatus.OBSERVED)
        assert result == FindingStatus.OBSERVED

    def test_monotonic_progression_accepted(self):
        fid = fresh_id()
        update_finding_status(fid, FindingStatus.OBSERVED)
        update_finding_status(fid, FindingStatus.SUSPECTED)
        result = update_finding_status(fid, FindingStatus.CONFIRMED)
        assert result == FindingStatus.CONFIRMED

    def test_regression_rejected(self):
        fid = fresh_id()
        update_finding_status(fid, FindingStatus.CONFIRMED)
        result = update_finding_status(fid, FindingStatus.OBSERVED)
        assert result == FindingStatus.CONFIRMED  # regression rejetée

    def test_regression_keeps_current_not_proposed(self):
        fid = fresh_id()
        update_finding_status(fid, FindingStatus.SUSPECTED)
        result = update_finding_status(fid, FindingStatus.NOT_TESTED)
        assert result == FindingStatus.SUSPECTED

    def test_history_recorded(self):
        fid = fresh_id()
        update_finding_status(fid, FindingStatus.OBSERVED)
        update_finding_status(fid, FindingStatus.CONFIRMED)
        hist = get_status_history(fid)
        assert FindingStatus.OBSERVED in hist
        assert FindingStatus.CONFIRMED in hist

    def test_history_default_not_tested(self):
        fid = fresh_id()
        hist = get_status_history(fid)
        assert hist == [FindingStatus.NOT_TESTED]

    def test_confirmed_cannot_downgrade_to_observed(self):
        fid = fresh_id()
        update_finding_status(fid, FindingStatus.CONFIRMED)
        update_finding_status(fid, FindingStatus.OBSERVED)   # rejeté
        hist = get_status_history(fid)
        # Dernier statut accepté doit rester CONFIRMED
        accepted = [s for s in hist if s != FindingStatus.NOT_TESTED]
        assert accepted[-1] == FindingStatus.CONFIRMED

    def test_exploited_highest_rank(self):
        fid = fresh_id()
        update_finding_status(fid, FindingStatus.EXPLOITED)
        result = update_finding_status(fid, FindingStatus.CONFIRMED)
        assert result == FindingStatus.EXPLOITED


# ============================================================
# 7.5  signals_confirmed_by_proofs()
# ============================================================

class Test75SignalProofCorrelation:

    def test_no_signals_returns_empty(self):
        g = EvidenceGraph.build(make_finding(evidence={}), [])
        assert signals_confirmed_by_proofs(g) == []

    def test_signal_without_matching_proof_not_confirmed(self):
        # signal type "timing" n'a pas de clé proof correspondante
        g = EvidenceGraph.build(make_finding(evidence={}), [make_signal("timing")])
        confirmed = signals_confirmed_by_proofs(g)
        assert confirmed == []

    def test_signal_matching_proof_key_is_confirmed(self):
        # signal type == clé proof → confirmé
        g = EvidenceGraph.build(
            make_finding(evidence={"timing": {"confidence": 1.0}}),
            [make_signal("timing")]
        )
        confirmed = signals_confirmed_by_proofs(g)
        assert len(confirmed) == 1
        assert confirmed[0].data["type"] == "timing"

    def test_mixed_confirmed_and_unconfirmed(self):
        evidence = {"size_diff": {}}   # proof pour "size_diff" seulement
        signals = [make_signal("size_diff"), make_signal("timing")]
        g = EvidenceGraph.build(make_finding(evidence=evidence), signals)
        confirmed = signals_confirmed_by_proofs(g)
        confirmed_types = [n.data["type"] for n in confirmed]
        assert "size_diff" in confirmed_types
        assert "timing" not in confirmed_types

    def test_10_signals_1_proof_status_confirmed(self):
        # Spec §7.5 : 10 signals, 1 proof → CONFIRMED (proof drives it)
        evidence = {"xss_proof": {}}
        signals = [make_signal(f"sig_{i}") for i in range(10)]
        g = EvidenceGraph.build(make_finding(evidence=evidence), signals)
        assert evidence_status_from_graph(g) == FindingStatus.CONFIRMED

    def test_signals_alone_never_confirmed_status(self):
        # 100 signaux sans preuves → OBSERVED, jamais CONFIRMED
        signals = [make_signal(f"s{i}") for i in range(100)]
        g = EvidenceGraph.build(make_finding(evidence={}), signals)
        assert evidence_status_from_graph(g) == FindingStatus.OBSERVED
        assert evidence_status_from_graph(g) != FindingStatus.CONFIRMED

    def test_unconfirmed_signals_list_updated(self):
        evidence = {"matching_key": {}}
        signals = [make_signal("matching_key"), make_signal("other")]
        g = EvidenceGraph.build(make_finding(evidence=evidence), signals)
        unconf_types = [n.data["type"] for n in g.unconfirmed_signals]
        assert "other" in unconf_types
        assert "matching_key" not in unconf_types


# ============================================================
# Intégration rapide : pipeline validate → consistency → history
# ============================================================

class TestPrecisionPipeline:

    def setup_method(self):
        _STATUS_HISTORY.clear()

    def test_full_precision_pipeline_confirmed(self):
        """SSRF confirmé : build → status_from_graph → validate → consistency."""
        evidence = {"aws_metadata": {"tool_name": "ssrf_hunter", "confidence": 1.0}}
        finding = make_finding("SSRF", status=FindingStatus.CONFIRMED,
                               confidence=1.0, evidence=evidence)
        g = EvidenceGraph.build(finding, [make_signal("response_diff")])

        # 5.3
        assert evidence_status_from_graph(g) == FindingStatus.CONFIRMED
        # 7.1
        validated = validate_finding_status(finding, g)
        assert validated.status == FindingStatus.CONFIRMED
        # 7.3
        assert validate_evidence_consistency(finding, g) is True
        # 7.4
        fid = "ssrf-finding-001"
        update_finding_status(fid, FindingStatus.CONFIRMED)
        assert get_status_history(fid)[-1] == FindingStatus.CONFIRMED

    def test_full_precision_pipeline_false_positive_blocked(self):
        """Faux positif : statut CONFIRMED sans preuve → bloqué à OBSERVED."""
        finding = make_finding("SSRF", status=FindingStatus.CONFIRMED, evidence={})
        g = EvidenceGraph.build(finding, [make_signal("size_diff", conf=0.9)])

        # 5.3
        assert evidence_status_from_graph(g) == FindingStatus.OBSERVED
        # 7.1 — bloque la promotion
        validated = validate_finding_status(finding, g)
        assert validated.status == FindingStatus.OBSERVED
        # 7.3 — lève une erreur si on essaie quand même de marquer CONFIRMED
        finding.status = FindingStatus.CONFIRMED  # tentative manuelle
        with pytest.raises(EvidenceConsistencyError):
            validate_evidence_consistency(finding, g)
        # 7.4 — pas de régression possible depuis OBSERVED
        fid = "ssrf-fp-001"
        update_finding_status(fid, FindingStatus.OBSERVED)
        rejected = update_finding_status(fid, FindingStatus.NOT_TESTED)
        assert rejected == FindingStatus.OBSERVED  # regression bloquée


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
