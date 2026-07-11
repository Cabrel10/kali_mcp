#!/usr/bin/env python3
"""
Kali MCP Server v6 — Comprehensive Test Suite
Tests ALL 20 mega-modules + 11 core/intelligence classes + async execution
Validates: imports, signatures, CVSS scoring, correlation, kill chain, deep parsing, parallel exec
"""

import asyncio
import inspect
import json
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kali_mcp_server as srv

# ──────────────────────── Framework ────────────────────────

RESULTS = []
PASS = FAIL = 0


def record(name: str, passed: bool, detail: str = ""):
    global PASS, FAIL
    if passed:
        PASS += 1
    else:
        FAIL += 1
    RESULTS.append(("PASS" if passed else "FAIL", name, detail))


# ══════════════════════════════════════════════════════════════
# SECTION 1: Core Infrastructure (6 classes)
# ══════════════════════════════════════════════════════════════

def test_scan_depth():
    try:
        assert len(srv.ScanDepth) == 4
        assert srv.ScanDepth.STEALTH.value == "stealth"
        assert srv.ScanDepth.AGGRESSIVE.value == "aggressive"
        record("ScanDepth enum", True)
    except Exception as e:
        record("ScanDepth enum", False, str(e))


def test_pentest_memory():
    try:
        mem = srv.PentestMemory()
        mem.store_finding("T", "nmap", "port", {"port": 22})
        mem.store_finding("T", "nmap", "port", {"port": 80})
        mem.store_finding("T", "nikto", "vuln", {"id": "X"})
        ctx = mem.get_context("T")
        assert ctx["total_findings"] == 3
        assert "port" in ctx["finding_types"]
        ports = mem.get_findings("T", "port")
        assert len(ports) == 2
        all_f = mem.get_findings("T")
        assert len(all_f) == 3
        mem.store_tech("T", {"framework": "django"})
        assert mem.get_tech("T")["framework"] == "django"
        assert mem.has_finding("T", "port")
        mem.decide("T", "scan_deep", "many ports open")
        record("PentestMemory", True)
    except Exception as e:
        record("PentestMemory", False, str(e))


def test_rate_limit_detector():
    try:
        rl = srv.RateLimitDetector()
        rl.detect_from_response("T", 429, {})
        d1 = rl.get_delay("T")
        assert d1 > 0
        rl.detect_from_response("T", 429, {})
        d2 = rl.get_delay("T")
        assert d2 >= d1, f"Backoff: {d2} >= {d1}"
        # WAF detection
        waf = rl.detect_from_response("W", 403, {"server": "cloudflare"})
        assert waf.get("waf_detected") is True
        rl.reset("T")
        # After reset, defaultdict gives default 0.1
        d3 = rl.get_delay("T")
        assert d3 <= 0.2, f"After reset: {d3}"
        record("RateLimitDetector", True)
    except Exception as e:
        record("RateLimitDetector", False, str(e))


def test_orchestrator():
    try:
        mem = srv.PentestMemory()
        rl = srv.RateLimitDetector()
        orch = srv.IntelligentOrchestrator(mem, rl)
        # 403 bypass
        recs = orch.analyze_response_code("T", "/admin", 403, {})
        assert any(r["action"] == "auth_bypass" for r in recs)
        # 405 method enum
        recs2 = orch.analyze_response_code("T", "/api", 405, {})
        assert any(r["action"] == "method_enumeration" for r in recs2)
        # 422 param fuzz
        recs3 = orch.analyze_response_code("T", "/api", 422, {})
        assert any(r["action"] == "parameter_fuzzing" for r in recs3)
        # 500 error exploit
        recs4 = orch.analyze_response_code("T", "/err", 500, {})
        assert any(r["action"] == "error_exploitation" for r in recs4)
        # Cloud header detection
        recs5 = orch.analyze_response_code("T", "/", 200, {"x-amz-request-id": "abc123"})
        assert any(r["action"] == "cloud_enumeration" for r in recs5)
        # Stack configs
        assert len(orch.STACK_CONFIGS) >= 7
        for stack in ["spring", "django", "express", "flask", "php", "go", "aspnet"]:
            assert stack in orch.STACK_CONFIGS
        # adapt_to_stack
        mem.store_tech("S", {"framework": "spring"})
        adapted = orch.adapt_to_stack("S")
        assert adapted["adapted"] is True
        assert "/actuator" in adapted["config"]["endpoints"]
        # recommend_next_tools
        recs6 = orch.recommend_next_tools("EMPTY")
        assert any(r["module"] == "recon_engine" for r in recs6)
        record("IntelligentOrchestrator", True)
    except Exception as e:
        record("IntelligentOrchestrator", False, str(e))


def test_session_manager():
    try:
        sm = srv.SessionManager()
        sid = sm.create_session("test")
        assert len(sid) > 10
        ex = sm.start_execution("recon_engine", "10.0.0.1", {"depth": "deep"})
        assert ex.tool_name == "recon_engine"
        sm.complete_execution(ex, {"ports": [22, 80]})
        assert ex.status == "completed"
        record("SessionManager", True)
    except Exception as e:
        record("SessionManager", False, str(e))


def test_input_validator():
    try:
        iv = srv.InputValidator()
        assert iv.sanitize_target("192.168.1.1") == "192.168.1.1"
        assert iv.sanitize_target("example.com") == "example.com"
        assert iv.sanitize_target("10.0.0.0/24") == "10.0.0.0/24"
        blocked = 0
        for bad in ["192.168.1.1; rm -rf /", "$(whoami)", "`cat /etc/passwd`"]:
            try:
                iv.sanitize_target(bad)
            except ValueError:
                blocked += 1
        assert blocked >= 2, f"Blocked {blocked} of 3"
        assert iv.validate_timeout(300) == 300
        assert iv.validate_port(8080) == 8080
        record("InputValidator", True)
    except Exception as e:
        record("InputValidator", False, str(e))


# ══════════════════════════════════════════════════════════════
# SECTION 2: Intelligence Engine (5 classes)
# ══════════════════════════════════════════════════════════════

def test_cvss_calculator():
    try:
        # RCE: should be 10.0
        s1, v1 = srv.CVSSCalculator.calculate(
            av="network", ac="low", pr="none", ui="none",
            scope="changed", conf="high", integ="high", avail="high")
        assert s1 == 10.0, f"RCE should be 10.0, got {s1}"
        assert "CVSS:3.1" in v1
        # Info only: should be low
        s2, v2 = srv.CVSSCalculator.calculate(
            av="network", ac="low", pr="none", ui="none",
            scope="unchanged", conf="low", integ="none", avail="none")
        assert 4.0 <= s2 <= 6.0, f"Info should be medium, got {s2}"
        # Severity labels
        assert srv.CVSSCalculator.severity_from_score(9.5) == "critical"
        assert srv.CVSSCalculator.severity_from_score(7.5) == "high"
        assert srv.CVSSCalculator.severity_from_score(5.0) == "medium"
        assert srv.CVSSCalculator.severity_from_score(2.0) == "low"
        assert srv.CVSSCalculator.severity_from_score(0.0) == "info"
        # Vuln type presets
        for vt in ["rce", "sqli", "xss_stored", "lfi", "ssrf", "ssti", "cmdi", "log4shell",
                    "default_credentials", "kerberoast", "jwt_none_alg"]:
            s, v, sev = srv.CVSSCalculator.score_for_vuln_type(vt)
            assert s > 0, f"{vt} score should be > 0"
            assert sev in ["critical", "high", "medium", "low", "info"]
        # Context boost
        s_boost, _, _ = srv.CVSSCalculator.score_for_vuln_type(
            "info_disclosure", {"internet_facing": True, "no_auth": True})
        s_no_boost, _, _ = srv.CVSSCalculator.score_for_vuln_type("info_disclosure")
        assert s_boost > s_no_boost
        record("CVSSCalculator", True)
    except Exception as e:
        record("CVSSCalculator", False, str(e))


def test_vuln_correlator():
    try:
        mem = srv.PentestMemory()
        vc = srv.VulnCorrelator(mem)
        # Add findings to trigger SSRF→Cloud chain
        mem.store_finding("C", "ssrf_hunter", "ssrf", {"url": "http://169.254.169.254"})
        mem.store_finding("C", "orchestrator", "cloud_detected", {"provider": "aws"})
        vc.add_vulnerability(srv.VulnFinding(
            vuln_id="ssrf_1", title="SSRF in /api/proxy", severity="high",
            cvss_score=8.5, cvss_vector="", target="C", port=443, exploitable=True,
            mitre_techniques=["T1190"]))
        corr = vc.correlate("C")
        assert corr["total_vulns"] >= 1
        assert len(corr["exploit_chains"]) >= 1  # SSRF+cloud chain
        assert corr["attack_surface_score"] > 0
        assert corr["risk_rating"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
        assert len(corr["mitre_coverage"]) > 0
        # Service checks
        smb_checks = vc.get_service_checks("smb")
        assert "eternalblue" in smb_checks["checks"]
        assert "CVE-2017-0144" in smb_checks["common_cves"]
        ssh_checks = vc.get_service_checks("ssh")
        assert "weak_creds" in ssh_checks["checks"]
        # Verify chain detection: SSTI → RCE chain (single requirement)
        mem2 = srv.PentestMemory()
        vc2 = srv.VulnCorrelator(mem2)
        vc2.add_vulnerability(srv.VulnFinding(
            vuln_id="ssti_1", title="SSTI Jinja2", severity="critical",
            cvss_score=10.0, cvss_vector="", target="D"))
        mem2.store_finding("D", "injection", "ssti", {"engine": "jinja2"})
        corr2 = vc2.correlate("D")
        assert any("SSTI" in c["chain"] for c in corr2["exploit_chains"])
        record("VulnCorrelator", True)
    except Exception as e:
        record("VulnCorrelator", False, str(e))


def test_kill_chain_tracker():
    try:
        mem = srv.PentestMemory()
        kc = srv.KillChainTracker(mem)
        kc.advance_phase("K", srv.KillChainPhase.RECONNAISSANCE, "recon_engine", ["ports:22,80"])
        kc.advance_phase("K", srv.KillChainPhase.EXPLOITATION, "injection_matrix", ["sqli_found"])
        kc.advance_phase("K", srv.KillChainPhase.INSTALLATION, "post_exploit_ops", ["backdoor"])
        prog = kc.get_progress("K")
        assert prog["completion"] == "3/7"
        assert prog["completion_pct"] == round(3/7 * 100, 1)
        assert prog["next_phase"]["phase"] == "weaponization"
        # MITRE mapping exists for all phases
        assert len(srv.KillChainTracker.MITRE_MAPPING) == 7
        for phase in srv.KillChainPhase:
            assert phase in srv.KillChainTracker.MITRE_MAPPING
        record("KillChainTracker", True)
    except Exception as e:
        record("KillChainTracker", False, str(e))


def test_deep_output_parser():
    try:
        dp = srv.DeepOutputParser()
        # Credential extraction
        hydra_out = "[22][ssh] host: 10.0.0.1 login: admin password: P@ssw0rd123\n[22][ssh] host: 10.0.0.1 login: root password: toor"
        creds = dp.extract_credentials_from_output(hydra_out)
        assert len(creds) == 2
        assert creds[0]["username"] == "admin"
        assert creds[0]["password"] == "P@ssw0rd123"
        # Hashcat format (hash:password)
        hc_out = "5f4dcc3b5aa765d61d8327deb882cf99:password123"
        hc_creds = dp.extract_credentials_from_output(hc_out)
        assert len(hc_creds) >= 1
        assert hc_creds[0]["password"] == "password123"
        # Error page parsing
        html = """<html><body>
        Traceback (most recent call last):
          File "app.py", line 42
        ValueError: invalid literal
        PHPSESSID=abc123
        password = "admin123"
        jdbc:mysql://db.internal:3306/mydb
        </body></html>"""
        ep = dp.parse_error_page(html)
        assert ep["debug_mode"] is True
        assert len(ep["stack_traces"]) > 0
        assert len(ep["info_leaks"]) > 0
        assert any(t["tech"] == "php" for t in ep["technologies"])
        # Nuclei output parsing
        nuclei_out = "[critical] [CVE-2021-44228] [http] http://target.com/api [log4j]\n[high] [exposed-panel] [http] http://target.com/admin"
        nf = dp.parse_nuclei_output(nuclei_out)
        assert len(nf) == 2
        assert nf[0]["severity"] == "critical"
        assert "CVE-2021-44228" in nf[0]["cves"]
        record("DeepOutputParser", True)
    except Exception as e:
        record("DeepOutputParser", False, str(e))


async def test_parallel_executor():
    try:
        async def fast_task():
            await asyncio.sleep(0.1)
            return "fast_done"

        async def slow_task():
            await asyncio.sleep(0.2)
            return "slow_done"

        tasks = [
            {"name": "fast", "coro": fast_task(), "timeout": 5},
            {"name": "slow", "coro": slow_task(), "timeout": 5},
        ]
        results = await srv.ParallelExecutor.run_parallel(tasks, max_concurrent=2)
        assert len(results) == 2
        assert all(r["status"] == "success" for r in results)
        # Timeout test
        async def forever():
            await asyncio.sleep(100)
        timeout_tasks = [{"name": "infinite", "coro": forever(), "timeout": 0.5}]
        t_results = await srv.ParallelExecutor.run_parallel(timeout_tasks)
        assert t_results[0]["status"] == "timeout"
        record("ParallelExecutor", True)
    except Exception as e:
        record("ParallelExecutor", False, str(e))


# ══════════════════════════════════════════════════════════════
# SECTION 3: Module Existence & Signatures (20 tools)
# ══════════════════════════════════════════════════════════════

TOOL_SIGNATURES = {
    "session_ops": ["action"],
    "recon_engine": ["target", "depth"],
    "web_assault": ["target", "depth"],
    "injection_matrix": ["target", "depth"],
    "credential_cracker": ["target", "entropy_limit"],
    "network_dominator": ["target", "depth"],
    "wireless_audit": ["interface"],
    "cloud_siege": ["target", "depth"],
    "ad_annihilator": ["target", "domain"],
    "api_breaker": ["target", "depth"],
    "vuln_scanner_ultra": ["target", "depth"],
    "exploit_engine": ["target", "exploit_type"],
    "auth_destroyer": ["target", "depth"],
    "ssrf_hunter": ["target", "param"],
    "crypto_forensics": ["target", "depth"],
    "osint_harvester": ["target", "depth"],
    "post_exploit_ops": ["target", "depth"],
    "reporting_engine": ["target", "report_type"],
    "autopilot_commander": ["target", "depth", "scope", "aggressive"],
    "payload_factory": ["action", "target"],
}


def test_module_signatures():
    for name, required_params in TOOL_SIGNATURES.items():
        try:
            fn = getattr(srv, name, None)
            assert fn is not None, f"not found"
            assert callable(fn), f"not callable"
            assert inspect.iscoroutinefunction(fn), f"not async"
            params = list(inspect.signature(fn).parameters.keys())
            for rp in required_params:
                assert rp in params, f"missing '{rp}', has {params}"
            record(f"sig:{name}", True)
        except Exception as e:
            record(f"sig:{name}", False, str(e))


# ══════════════════════════════════════════════════════════════
# SECTION 4: Async Tool Execution (safe targets)
# ══════════════════════════════════════════════════════════════

async def test_exec_session_ops():
    try:
        r = await srv.session_ops(action="health")
        d = json.loads(r) if isinstance(r, str) else r
        assert isinstance(d, dict)
        record("exec:session_ops", True)
    except Exception as e:
        record("exec:session_ops", False, str(e))


async def test_exec_recon():
    try:
        r = await srv.recon_engine(target="127.0.0.1", depth="stealth", timeout=30)
        d = json.loads(r) if isinstance(r, str) else r
        assert isinstance(d, dict)
        # Check intelligence fields exist
        if "intelligence_summary" in d:
            assert "risk_rating" in d["intelligence_summary"]
        record("exec:recon_engine", True)
    except Exception as e:
        record("exec:recon_engine", False, str(e))


async def test_exec_credential_cracker():
    try:
        r = await srv.credential_cracker(
            target="127.0.0.1", hash_value="5f4dcc3b5aa765d61d8327deb882cf99",
            hash_type="md5", technique="auto", timeout=15)
        d = json.loads(r) if isinstance(r, str) else r
        assert "hash_analysis" in d
        assert d["hash_analysis"]["hash_type"] in ["md5", "ntlm"]
        assert d["hash_analysis"]["estimated_entropy"] > 0
        assert "estimated_time" in d["hash_analysis"]
        record("exec:credential_cracker", True)
    except Exception as e:
        record("exec:credential_cracker", False, str(e))


async def test_exec_reporting():
    try:
        r = await srv.reporting_engine(target="127.0.0.1", report_type="headers", timeout=15)
        d = json.loads(r) if isinstance(r, str) else r
        assert isinstance(d, dict)
        record("exec:reporting_engine", True)
    except Exception as e:
        record("exec:reporting_engine", False, str(e))


async def test_exec_payload_factory():
    try:
        r = await srv.payload_factory(action="generate", target="127.0.0.1", payload_type="xss")
        d = json.loads(r) if isinstance(r, str) else r
        assert "payloads" in d
        assert len(d["payloads"]) > 0
        record("exec:payload_factory", True)
    except Exception as e:
        record("exec:payload_factory", False, str(e))


async def test_exec_osint():
    try:
        r = await srv.osint_harvester(target="example.com", depth="stealth", timeout=15)
        d = json.loads(r) if isinstance(r, str) else r
        assert isinstance(d, dict)
        record("exec:osint_harvester", True)
    except Exception as e:
        record("exec:osint_harvester", False, str(e))


# ══════════════════════════════════════════════════════════════
# SECTION 5: Integration Test — Full Correlation Pipeline
# ══════════════════════════════════════════════════════════════

def test_full_correlation_pipeline():
    """End-to-end: simulate a pentest with findings, verify correlation output"""
    try:
        mem = srv.PentestMemory()
        rl = srv.RateLimitDetector()
        orch = srv.IntelligentOrchestrator(mem, rl)
        vc = srv.VulnCorrelator(mem)
        kc = srv.KillChainTracker(mem)

        target = "10.10.10.100"

        # Phase 1: Recon findings
        mem.store_finding(target, "recon", "open_ports", {"ports": [22, 80, 443, 445, 3389]})
        mem.store_tech(target, {"framework": "spring-boot", "server": "nginx"})
        kc.advance_phase(target, srv.KillChainPhase.RECONNAISSANCE, "recon_engine", ["5_ports"])

        # Phase 2: Web vulns
        mem.store_finding(target, "web_assault", "web_vulns", {"nikto": ["CVE-2021-44228"]})
        mem.store_finding(target, "web_assault", "directories", {"count": 42})

        # Phase 3: SQLi found
        mem.store_finding(target, "injection_matrix", "sqli_found", {"param": "id"})
        s, v, sev = srv.CVSSCalculator.score_for_vuln_type("sqli")
        vc.add_vulnerability(srv.VulnFinding(
            vuln_id="sqli_id", title="SQLi in /api/users?id=", severity=sev,
            cvss_score=s, cvss_vector=v, target=target, port=443,
            exploitable=True, mitre_techniques=["T1190"]))
        kc.advance_phase(target, srv.KillChainPhase.EXPLOITATION, "injection_matrix", ["sqli"])

        # Phase 4: Default creds found
        mem.store_finding(target, "credential_cracker", "credentials", {"source": "hydra"})
        s2, v2, sev2 = srv.CVSSCalculator.score_for_vuln_type("default_credentials")
        vc.add_vulnerability(srv.VulnFinding(
            vuln_id="default_creds_ssh", title="Default SSH credentials",
            severity=sev2, cvss_score=s2, cvss_vector=v2, target=target, port=22,
            exploitable=True, mitre_techniques=["T1110.001"]))

        # Phase 5: SSRF + Cloud
        mem.store_finding(target, "ssrf_hunter", "ssrf", {"url": "http://169.254.169.254"})
        mem.store_finding(target, "orchestrator", "cloud_detected", {"provider": "aws"})
        s3, v3, sev3 = srv.CVSSCalculator.score_for_vuln_type("ssrf")
        vc.add_vulnerability(srv.VulnFinding(
            vuln_id="ssrf_proxy", title="SSRF via /api/proxy", severity=sev3,
            cvss_score=s3, cvss_vector=v3, target=target, port=443,
            exploitable=True, mitre_techniques=["T1190", "T1552.005"]))

        # Full correlation
        corr = vc.correlate(target)
        assert corr["risk_rating"] in ["CRITICAL", "HIGH"]
        assert corr["total_vulns"] >= 3
        assert corr["attack_surface_score"] >= 50
        assert len(corr["exploit_chains"]) >= 1  # SSRF→Cloud chain minimum
        assert len(corr["mitre_coverage"]) >= 2
        assert len(corr["recommended_attack_path"]) >= 1

        # Orchestrator recommendations
        recs = orch.recommend_next_tools(target)
        assert len(recs) > 0

        # Spring stack adaptation
        adapted = orch.adapt_to_stack(target)
        assert adapted["adapted"] is True
        assert adapted["stack"] == "spring"

        # Kill chain progress
        prog = kc.get_progress(target)
        assert prog["completion_pct"] > 0

        record("full_correlation_pipeline", True)
    except Exception as e:
        record("full_correlation_pipeline", False, str(e))


# ══════════════════════════════════════════════════════════════
# Runner
# ══════════════════════════════════════════════════════════════

async def run_all():
    print("=" * 72)
    print("  Kali MCP Server v6 — Comprehensive Test Suite")
    print("  20 Mega-Modules | 11 Classes | Intelligence Engine")
    print("=" * 72)
    t0 = time.time()

    print("\n--- Core Infrastructure (6 classes) ---")
    test_scan_depth()
    test_pentest_memory()
    test_rate_limit_detector()
    test_orchestrator()
    test_session_manager()
    test_input_validator()

    print("\n--- Intelligence Engine (5 classes) ---")
    test_cvss_calculator()
    test_vuln_correlator()
    test_kill_chain_tracker()
    test_deep_output_parser()
    await test_parallel_executor()

    print("\n--- Module Signatures (20 tools) ---")
    test_module_signatures()

    print("\n--- Async Execution Tests ---")
    await test_exec_session_ops()
    await test_exec_recon()
    await test_exec_credential_cracker()
    await test_exec_reporting()
    await test_exec_payload_factory()
    await test_exec_osint()

    print("\n--- Integration: Full Correlation Pipeline ---")
    test_full_correlation_pipeline()

    elapsed = time.time() - t0
    print("\n" + "=" * 72)
    print(f"  RESULTS: {PASS} passed | {FAIL} failed | {PASS + FAIL} total | {elapsed:.1f}s")
    print("=" * 72 + "\n")
    for status, name, detail in RESULTS:
        icon = "+" if status == "PASS" else "X"
        line = f"  [{icon}] {name}"
        if detail:
            line += f"  ({detail})"
        print(line)

    print()
    if FAIL == 0:
        print("  ALL TESTS PASSED — v6 Mythos-tier READY")
    else:
        print(f"  {FAIL} test(s) failed")
    return FAIL == 0


if __name__ == "__main__":
    success = asyncio.run(run_all())
    sys.exit(0 if success else 1)
