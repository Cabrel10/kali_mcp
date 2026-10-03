#!/usr/bin/env python3
"""
test_killchain_precision.py
===========================
Tests pour l'intégration Kill Chain × Evidence Graph.

Couvre :
  1.  advance_phase() avec evidence_status=CONFIRMED → completed
  2.  advance_phase() avec OBSERVED → in_progress seulement
  3.  confirmed_count incrémenté seulement sur CONFIRMED
  4.  advance_from_finding() auto-mappe finding_type → phase
  5.  Phase non mappée ignorée (pas d'erreur)
  6.  Phase unlockée quand prérequis confirmé
  7.  _suggest_next_phase() priorise les phases unlockées
  8.  get_progress() expose confirmed_findings_total
  9.  attack_narrative construit depuis les phases complétées
 10.  sync_kill_chain_from_graph() couple EvidenceGraph → KillChain
 11.  Signal seul (OBSERVED) n'avance jamais une phase à completed
 12.  CONFIRMED avance la phase à completed via sync
 13.  evidence_graph_id stocké dans la phase
 14.  Narratif vide si aucune phase confirmée
 15.  Progression complète : recon → delivery → exploitation
"""

import sys
import datetime
import pytest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent))

from kali_mcp_server import (
    KillChainPhase, KillChainTracker, PentestMemory,
    EvidenceGraph, StandardFinding, FindingStatus, Signal,
    sync_kill_chain_from_graph,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_tracker():
    mem = MagicMock(spec=PentestMemory)
    mem.get_context.return_value = {"finding_types": [], "findings": []}
    return KillChainTracker(mem)

def make_finding(ftype="SSRF", evidence=None):
    f = StandardFinding(finding_type=ftype)
    f.status = FindingStatus.OBSERVED
    f.confidence = 0.5
    f.evidence = evidence or {}
    return f

def make_signal(conf=0.6):
    return Signal(type="anomaly", description="test", confidence=conf,
                  source_tool="scanner", timestamp=datetime.datetime.utcnow())

TARGET = "http://example.com"


# ---------------------------------------------------------------------------
# 1. advance_phase CONFIRMED → completed
# ---------------------------------------------------------------------------

def test_advance_phase_confirmed_sets_completed():
    t = make_tracker()
    t.advance_phase(TARGET, KillChainPhase.EXPLOITATION, "injection_matrix",
                    ["sqli:param_id"], evidence_status="CONFIRMED")
    p = t._progress[TARGET][KillChainPhase.EXPLOITATION.value]
    assert p["status"] == "completed"


# ---------------------------------------------------------------------------
# 2. advance_phase OBSERVED → in_progress, not completed
# ---------------------------------------------------------------------------

def test_advance_phase_observed_stays_in_progress():
    t = make_tracker()
    t.advance_phase(TARGET, KillChainPhase.EXPLOITATION, "scanner",
                    ["size_diff"], evidence_status="OBSERVED")
    p = t._progress[TARGET][KillChainPhase.EXPLOITATION.value]
    assert p["status"] == "in_progress"
    assert p["status"] != "completed"


# ---------------------------------------------------------------------------
# 3. confirmed_count incrémenté seulement sur CONFIRMED
# ---------------------------------------------------------------------------

def test_confirmed_count_only_for_confirmed():
    t = make_tracker()
    t.advance_phase(TARGET, KillChainPhase.EXPLOITATION, "tool",
                    ["f1", "f2"], evidence_status="CONFIRMED")
    t.advance_phase(TARGET, KillChainPhase.EXPLOITATION, "tool",
                    ["f3"], evidence_status="OBSERVED")
    p = t._progress[TARGET][KillChainPhase.EXPLOITATION.value]
    assert p["confirmed_count"] == 2   # seulement les 2 CONFIRMED


# ---------------------------------------------------------------------------
# 4. advance_from_finding auto-mappe finding_type → phase correcte
# ---------------------------------------------------------------------------

def test_advance_from_finding_ssrf_maps_to_exploitation():
    t = make_tracker()
    t.advance_from_finding(TARGET, "SSRF", "ssrf_hunter", "CONFIRMED")
    p = t._progress[TARGET][KillChainPhase.EXPLOITATION.value]
    assert p["status"] == "completed"

def test_advance_from_finding_xss_maps_to_delivery():
    t = make_tracker()
    t.advance_from_finding(TARGET, "XSS", "injection_matrix", "CONFIRMED")
    p = t._progress[TARGET][KillChainPhase.DELIVERY.value]
    assert p["status"] == "completed"

def test_advance_from_finding_port_scan_maps_to_recon():
    t = make_tracker()
    t.advance_from_finding(TARGET, "port_scan", "recon_engine", "CONFIRMED")
    p = t._progress[TARGET][KillChainPhase.RECONNAISSANCE.value]
    assert p["status"] == "completed"


# ---------------------------------------------------------------------------
# 5. Finding non mappé ignoré sans erreur
# ---------------------------------------------------------------------------

def test_advance_from_finding_unknown_type_no_error():
    t = make_tracker()
    t.advance_from_finding(TARGET, "UNKNOWN_VULN_XYZ", "tool", "CONFIRMED")
    # Aucune phase ne doit être complétée
    for phase in KillChainPhase:
        p = t._progress[TARGET][phase.value]
        assert p["status"] in ("not_started",)


# ---------------------------------------------------------------------------
# 6. Phase unlockée par prérequis confirmé
# ---------------------------------------------------------------------------

def test_phase_unlocked_when_prereq_confirmed():
    t = make_tracker()
    # XSS confirmé → EXPLOITATION doit être unlockée
    t.advance_from_finding(TARGET, "XSS", "scanner", "CONFIRMED")
    p = t._progress[TARGET][KillChainPhase.EXPLOITATION.value]
    assert p["status"] in ("completed", "unlocked")


# ---------------------------------------------------------------------------
# 7. _suggest_next_phase priorise les phases unlockées
# ---------------------------------------------------------------------------

def test_suggest_prioritizes_unlocked_phase():
    t = make_tracker()
    # Manuellement mettre DELIVERY en unlocked
    t._progress[TARGET][KillChainPhase.DELIVERY.value]["status"] = "unlocked"
    suggestion = t._suggest_next_phase(TARGET)
    assert suggestion["phase"] == KillChainPhase.DELIVERY.value
    assert "HIGH" in suggestion["priority"]


# ---------------------------------------------------------------------------
# 8. get_progress expose confirmed_findings_total
# ---------------------------------------------------------------------------

def test_get_progress_confirmed_findings_total():
    t = make_tracker()
    t.advance_phase(TARGET, KillChainPhase.RECONNAISSANCE, "recon", ["p1"], evidence_status="CONFIRMED")
    t.advance_phase(TARGET, KillChainPhase.EXPLOITATION, "inj", ["p2", "p3"], evidence_status="CONFIRMED")
    prog = t.get_progress(TARGET)
    assert prog["confirmed_findings_total"] == 3


# ---------------------------------------------------------------------------
# 9. attack_narrative depuis les phases complétées
# ---------------------------------------------------------------------------

def test_attack_narrative_built_from_confirmed_phases():
    t = make_tracker()
    t.advance_phase(TARGET, KillChainPhase.RECONNAISSANCE, "recon_engine",
                    ["ports:22,80,443"], evidence_status="CONFIRMED")
    t.advance_phase(TARGET, KillChainPhase.EXPLOITATION, "injection_matrix",
                    ["sqli:id"], evidence_status="CONFIRMED")
    prog = t.get_progress(TARGET)
    narrative = prog["attack_narrative"]
    assert len(narrative) >= 1
    phases_in_narrative = " ".join(narrative).lower()
    assert "reconnaissance" in phases_in_narrative or "exploitation" in phases_in_narrative


# ---------------------------------------------------------------------------
# 10. sync_kill_chain_from_graph couple EvidenceGraph → KillChain
# ---------------------------------------------------------------------------

def test_sync_kill_chain_from_graph_confirmed():
    t = make_tracker()
    evidence = {"aws_metadata": {"tool_name": "ssrf_hunter", "confidence": 1.0}}
    finding = make_finding("SSRF", evidence=evidence)
    g = EvidenceGraph.build(finding, [make_signal()])

    status = sync_kill_chain_from_graph(t, TARGET, "SSRF", "ssrf_hunter", g)

    assert status == "CONFIRMED"
    p = t._progress[TARGET][KillChainPhase.EXPLOITATION.value]
    assert p["status"] == "completed"
    assert p["confirmed_count"] >= 1


# ---------------------------------------------------------------------------
# 11. Signal seul (OBSERVED) n'avance pas la phase à completed
# ---------------------------------------------------------------------------

def test_sync_signal_only_no_completed():
    t = make_tracker()
    finding = make_finding("SSRF", evidence={})   # pas de preuves
    g = EvidenceGraph.build(finding, [make_signal(conf=0.9)])

    status = sync_kill_chain_from_graph(t, TARGET, "SSRF", "ssrf_hunter", g)

    assert status == "OBSERVED"
    p = t._progress[TARGET][KillChainPhase.EXPLOITATION.value]
    assert p["status"] != "completed"
    assert p["confirmed_count"] == 0


# ---------------------------------------------------------------------------
# 12. CONFIRMED via sync avance bien la phase
# ---------------------------------------------------------------------------

def test_sync_confirmed_completes_phase():
    t = make_tracker()
    evidence = {"sqli_error": {"tool_name": "sqlmap", "confidence": 1.0}}
    finding = make_finding("SQLi", evidence=evidence)
    g = EvidenceGraph.build(finding, [make_signal()])

    sync_kill_chain_from_graph(t, TARGET, "SQLi", "sqlmap", g)
    p = t._progress[TARGET][KillChainPhase.EXPLOITATION.value]
    assert p["status"] == "completed"


# ---------------------------------------------------------------------------
# 13. evidence_graph_id stocké dans la phase après CONFIRMED
# ---------------------------------------------------------------------------

def test_evidence_graph_id_stored_in_phase():
    t = make_tracker()
    evidence = {"proof": {"confidence": 1.0}}
    finding = make_finding("SSRF", evidence=evidence)
    g = EvidenceGraph.build(finding, [])

    sync_kill_chain_from_graph(t, TARGET, "SSRF", "ssrf_hunter", g)
    p = t._progress[TARGET][KillChainPhase.EXPLOITATION.value]
    assert g.graph_id in p["evidence_graph_ids"]


# ---------------------------------------------------------------------------
# 14. Narratif vide si aucune phase confirmée
# ---------------------------------------------------------------------------

def test_attack_narrative_empty_when_no_confirmed():
    t = make_tracker()
    prog = t.get_progress(TARGET)
    assert prog["attack_narrative"] == []


# ---------------------------------------------------------------------------
# 15. Pipeline complet recon → delivery → exploitation
# ---------------------------------------------------------------------------

def test_full_kill_chain_progression():
    t = make_tracker()

    # Recon
    t.advance_from_finding(TARGET, "port_scan", "recon_engine", "CONFIRMED")
    # XSS delivery
    xss_finding = make_finding("XSS", evidence={"xss_executed": {}})
    xss_graph = EvidenceGraph.build(xss_finding, [make_signal()])
    sync_kill_chain_from_graph(t, TARGET, "XSS", "injection_matrix", xss_graph)
    # SSRF exploitation
    ssrf_finding = make_finding("SSRF", evidence={"metadata": {"confidence": 1.0}})
    ssrf_graph = EvidenceGraph.build(ssrf_finding, [make_signal()])
    sync_kill_chain_from_graph(t, TARGET, "SSRF", "ssrf_hunter", ssrf_graph)

    prog = t.get_progress(TARGET)
    assert prog["confirmed_findings_total"] >= 3
    completed_phases = [
        k for k, v in prog["phases"].items()
        if v["status"] == "completed"
    ]
    assert KillChainPhase.RECONNAISSANCE.value in completed_phases
    assert KillChainPhase.DELIVERY.value in completed_phases
    assert KillChainPhase.EXPLOITATION.value in completed_phases
    assert len(prog["attack_narrative"]) >= 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
