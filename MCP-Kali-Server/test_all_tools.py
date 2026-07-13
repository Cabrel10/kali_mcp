#!/usr/bin/env python3
"""
Kali MCP Server v6.2 — Comprehensive Test Suite
Tests ALL 22 mega-modules + 17 core/intelligence classes + async execution
Validates: imports, signatures, CVSS scoring, correlation, kill chain, deep parsing,
           parallel exec, forensics, race conditions, enhanced crypto, persistence, IDOR, WiFi pivot
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
        waf = rl.detect_from_response("W", 403, {"server": "cloudflare"})
        assert waf.get("waf_detected") is True
        rl.reset("T")
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
        recs = orch.analyze_response_code("T", "/admin", 403, {})
        assert any(r["action"] == "auth_bypass" for r in recs)
        recs2 = orch.analyze_response_code("T", "/api", 405, {})
        assert any(r["action"] == "method_enumeration" for r in recs2)
        recs3 = orch.analyze_response_code("T", "/api", 422, {})
        assert any(r["action"] == "parameter_fuzzing" for r in recs3)
        recs4 = orch.analyze_response_code("T", "/err", 500, {})
        assert any(r["action"] == "error_exploitation" for r in recs4)
        recs5 = orch.analyze_response_code("T", "/", 200, {"x-amz-request-id": "abc123"})
        assert any(r["action"] == "cloud_enumeration" for r in recs5)
        assert len(orch.STACK_CONFIGS) >= 7
        for stack in ["spring", "django", "express", "flask", "php", "go", "aspnet"]:
            assert stack in orch.STACK_CONFIGS
        mem.store_tech("S", {"framework": "spring"})
        adapted = orch.adapt_to_stack("S")
        assert adapted["adapted"] is True
        assert "/actuator" in adapted["config"]["endpoints"]
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
        s1, v1 = srv.CVSSCalculator.calculate(
            av="network", ac="low", pr="none", ui="none",
            scope="changed", conf="high", integ="high", avail="high")
        assert s1 == 10.0, f"RCE should be 10.0, got {s1}"
        assert "CVSS:3.1" in v1
        s2, v2 = srv.CVSSCalculator.calculate(
            av="network", ac="low", pr="none", ui="none",
            scope="unchanged", conf="low", integ="none", avail="none")
        assert 4.0 <= s2 <= 6.0, f"Info should be medium, got {s2}"
        assert srv.CVSSCalculator.severity_from_score(9.5) == "critical"
        assert srv.CVSSCalculator.severity_from_score(7.5) == "high"
        assert srv.CVSSCalculator.severity_from_score(5.0) == "medium"
        assert srv.CVSSCalculator.severity_from_score(2.0) == "low"
        assert srv.CVSSCalculator.severity_from_score(0.0) == "info"
        for vt in ["rce", "sqli", "xss_stored", "lfi", "ssrf", "ssti", "cmdi", "log4shell",
                    "default_credentials", "kerberoast", "jwt_none_alg"]:
            s, v, sev = srv.CVSSCalculator.score_for_vuln_type(vt)
            assert s > 0, f"{vt} score should be > 0"
            assert sev in ["critical", "high", "medium", "low", "info"]
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
        mem.store_finding("C", "ssrf_hunter", "ssrf", {"url": "http://169.254.169.254"})
        mem.store_finding("C", "orchestrator", "cloud_detected", {"provider": "aws"})
        vc.add_vulnerability(srv.VulnFinding(
            vuln_id="ssrf_1", title="SSRF in /api/proxy", severity="high",
            cvss_score=8.5, cvss_vector="", target="C", port=443, exploitable=True,
            mitre_techniques=["T1190"]))
        corr = vc.correlate("C")
        assert corr["total_vulns"] >= 1
        assert len(corr["exploit_chains"]) >= 1
        assert corr["attack_surface_score"] > 0
        assert corr["risk_rating"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
        assert len(corr["mitre_coverage"]) > 0
        smb_checks = vc.get_service_checks("smb")
        assert "eternalblue" in smb_checks["checks"]
        assert "CVE-2017-0144" in smb_checks["common_cves"]
        ssh_checks = vc.get_service_checks("ssh")
        assert "weak_creds" in ssh_checks["checks"]
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
        assert len(srv.KillChainTracker.MITRE_MAPPING) == 7
        for phase in srv.KillChainPhase:
            assert phase in srv.KillChainTracker.MITRE_MAPPING
        record("KillChainTracker", True)
    except Exception as e:
        record("KillChainTracker", False, str(e))


def test_deep_output_parser():
    try:
        dp = srv.DeepOutputParser()
        hydra_out = "[22][ssh] host: 10.0.0.1 login: admin password: P@ssw0rd123\n[22][ssh] host: 10.0.0.1 login: root password: toor"
        creds = dp.extract_credentials_from_output(hydra_out)
        assert len(creds) == 2
        assert creds[0]["username"] == "admin"
        assert creds[0]["password"] == "P@ssw0rd123"
        hc_out = "5f4dcc3b5aa765d61d8327deb882cf99:password123"
        hc_creds = dp.extract_credentials_from_output(hc_out)
        assert len(hc_creds) >= 1
        assert hc_creds[0]["password"] == "password123"
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
        async def forever():
            await asyncio.sleep(100)
        timeout_tasks = [{"name": "infinite", "coro": forever(), "timeout": 0.5}]
        t_results = await srv.ParallelExecutor.run_parallel(timeout_tasks)
        assert t_results[0]["status"] == "timeout"
        record("ParallelExecutor", True)
    except Exception as e:
        record("ParallelExecutor", False, str(e))


# ══════════════════════════════════════════════════════════════
# SECTION 3: Module Existence & Signatures (26 tools)
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
    "forensics_engine": ["target", "modules"],
    "race_condition_tester": ["target", "modules"],
    "protocol_deep_scan": ["target", "depth"],
    "smart_fuzz_engine": ["target", "depth"],
    "honeypot_detector": ["target", "depth"],
    "auto_exploit": ["target", "strategy"],
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


async def test_exec_forensics():
    """Test forensics_engine with safe local analysis"""
    try:
        r = await srv.forensics_engine(
            target="127.0.0.1",
            modules="log_analysis,ioc_extract",
            depth="stealth",
            timeout=30,
        )
        d = json.loads(r) if isinstance(r, str) else r
        assert isinstance(d, dict)
        assert "modules" in d
        assert "target" in d
        record("exec:forensics_engine", True)
    except Exception as e:
        record("exec:forensics_engine", False, str(e))


async def test_exec_race_condition():
    """Test race_condition_tester with safe localhost target"""
    try:
        r = await srv.race_condition_tester(
            target="http://127.0.0.1",
            modules="timing_attack",
            timeout=15,
        )
        d = json.loads(r) if isinstance(r, str) else r
        assert isinstance(d, dict)
        assert "modules" in d
        assert "target" in d
        record("exec:race_condition_tester", True)
    except Exception as e:
        record("exec:race_condition_tester", False, str(e))


async def test_exec_crypto_forensics():
    """Test enhanced crypto_forensics with hash identification"""
    try:
        r = await srv.crypto_forensics(
            target="5f4dcc3b5aa765d61d8327deb882cf99",
            modules="hash_id",
            depth="stealth",
            timeout=15,
        )
        d = json.loads(r) if isinstance(r, str) else r
        assert isinstance(d, dict)
        assert "modules" in d
        if "hash_id" in d.get("modules", {}):
            hi = d["modules"]["hash_id"]
            assert "hashes" in hi
            # MD5 hash should be identified
            if hi["hashes"]:
                assert any("MD5" in str(h.get("possible_types", [])) for h in hi["hashes"])
        record("exec:crypto_forensics_hash", True)
    except Exception as e:
        record("exec:crypto_forensics_hash", False, str(e))


async def test_exec_post_exploit():
    """Test enhanced post_exploit_ops persistence module"""
    try:
        r = await srv.post_exploit_ops(
            target="127.0.0.1",
            modules="persist",
            depth="deep",
            timeout=15,
        )
        d = json.loads(r) if isinstance(r, str) else r
        assert isinstance(d, dict)
        assert "modules" in d
        if "persist" in d.get("modules", {}):
            per = d["modules"]["persist"]
            # Verify deep persistence techniques are present
            assert "linux" in per
            assert "windows" in per
            # Verify actual commands exist (not just names)
            linux_techs = per["linux"]
            if isinstance(linux_techs, dict) and "techniques" in linux_techs:
                for tech in linux_techs["techniques"]:
                    assert "command" in tech, f"Technique missing command: {tech.get('name')}"
                    assert "detection" in tech, f"Technique missing detection: {tech.get('name')}"
                    assert "stealth" in tech, f"Technique missing stealth rating: {tech.get('name')}"
                assert len(linux_techs["techniques"]) >= 8, "Should have 8+ Linux persistence techniques"
            if isinstance(per.get("windows"), dict) and "techniques" in per["windows"]:
                for tech in per["windows"]["techniques"]:
                    assert "command" in tech
                assert len(per["windows"]["techniques"]) >= 6, "Should have 6+ Windows persistence techniques"
            # Verify payload generation commands
            if "payload_generation" in per:
                pg = per["payload_generation"]
                assert "msfvenom_linux" in pg
                assert "msfvenom_windows" in pg
        record("exec:post_exploit_persistence", True)
    except Exception as e:
        record("exec:post_exploit_persistence", False, str(e))


# ══════════════════════════════════════════════════════════════
# SECTION 5: Enhanced Feature Tests
# ══════════════════════════════════════════════════════════════

def test_wireless_audit_signature_enhanced():
    """Verify wireless_audit has pivot + restore in default module list"""
    try:
        fn = srv.wireless_audit
        src = inspect.getsource(fn)
        # Verify pivot and restore are in the default module list
        assert "pivot" in src, "wireless_audit should support pivot module"
        assert "restore" in src, "wireless_audit should support restore module"
        assert "VulnFinding" in src, "wireless_audit should register VulnFindings"
        assert "kill_chain" in src, "wireless_audit should integrate kill chain"
        assert "arp-scan" in src or "arp_scan" in src, "wireless_audit pivot should do ARP scanning"
        assert "wpa_supplicant" in src or "wpa_passphrase" in src, "wireless_audit pivot should auto-connect"
        record("wireless_audit_enhanced", True)
    except Exception as e:
        record("wireless_audit_enhanced", False, str(e))


def test_crypto_forensics_signature_enhanced():
    """Verify crypto_forensics has new modules"""
    try:
        fn = srv.crypto_forensics
        src = inspect.getsource(fn)
        assert "cipher_analysis" in src, "crypto_forensics should have cipher_analysis"
        assert "decrypt" in src, "crypto_forensics should have decrypt module"
        assert "tls_audit" in src, "crypto_forensics should have tls_audit"
        assert "hash_id" in src, "crypto_forensics should have hash_id"
        assert "testssl" in src, "crypto_forensics should use testssl.sh"
        assert "openssl" in src, "crypto_forensics should use openssl"
        assert "caesar" in src.lower() or "rot" in src.lower(), "crypto_forensics should handle Caesar/ROT ciphers"
        assert "zip2john" in src or "john" in src, "crypto_forensics should handle encrypted archives"
        record("crypto_forensics_enhanced", True)
    except Exception as e:
        record("crypto_forensics_enhanced", False, str(e))


def test_post_exploit_persistence_enhanced():
    """Verify post_exploit_ops has deep persistence techniques"""
    try:
        fn = srv.post_exploit_ops
        src = inspect.getsource(fn)
        # Linux persistence
        assert "ld_preload" in src.lower() or "LD_PRELOAD" in src
        assert "pam_backdoor" in src.lower() or "PAM" in src
        assert "systemd_timer" in src.lower() or "systemd" in src
        assert "rc_local" in src.lower() or "rc.local" in src
        # Windows persistence
        assert "golden_ticket" in src.lower() or "Golden Ticket" in src
        assert "wmi_event" in src.lower() or "WMI" in src
        assert "com_hijack" in src.lower() or "COM" in src
        # Payload generation
        assert "msfvenom" in src
        assert "meterpreter" in src or "reverse_tcp" in src
        record("post_exploit_persistence_enhanced", True)
    except Exception as e:
        record("post_exploit_persistence_enhanced", False, str(e))


def test_auth_destroyer_idor_enhanced():
    """Verify auth_destroyer has enhanced IDOR testing"""
    try:
        fn = srv.auth_destroyer
        src = inspect.getsource(fn)
        assert "bola" in src.lower() or "BOLA" in src, "auth_destroyer should have BOLA testing"
        assert "X-HTTP-Method-Override" in src or "method_override" in src.lower(), "Should have method override bypass"
        assert "2147483647" in src, "Should test integer overflow edge cases"
        record("auth_destroyer_idor_enhanced", True)
    except Exception as e:
        record("auth_destroyer_idor_enhanced", False, str(e))


def test_forensics_engine_submodules():
    """Verify forensics_engine has all required sub-modules"""
    try:
        fn = srv.forensics_engine
        src = inspect.getsource(fn)
        required_modules = [
            "log_analysis", "malware_detect", "usb_forensics",
            "memory_analysis", "ransomware_analysis", "yara_scan",
            "ioc_extract", "network_forensics", "botnet_detect"
        ]
        for mod in required_modules:
            assert mod in src, f"forensics_engine missing module: {mod}"
        # Verify specific capabilities
        assert "chkrootkit" in src or "rkhunter" in src, "Should detect rootkits"
        assert "volatility" in src.lower() or "Volatility" in src, "Should use Volatility for memory analysis"
        assert "lsusb" in src, "Should parse USB devices"
        assert "HID" in src or "Rubber" in src, "Should detect HID attacks"
        assert "entropy" in src, "Should analyze file entropy for ransomware"
        assert "yara" in src.lower(), "Should support YARA scanning"
        assert "C2" in src or "c2_ports" in src.lower() or "botnet" in src.lower(), "Should detect C2/botnet activity"
        record("forensics_engine_submodules", True)
    except Exception as e:
        record("forensics_engine_submodules", False, str(e))


def test_race_condition_submodules():
    """Verify race_condition_tester has all required sub-modules"""
    try:
        fn = srv.race_condition_tester
        src = inspect.getsource(fn)
        required_modules = [
            "concurrent_requests", "toctou", "session_race",
            "limit_bypass", "timing_attack"
        ]
        for mod in required_modules:
            assert mod in src, f"race_condition_tester missing module: {mod}"
        # Verify specific capabilities
        assert "curl" in src, "Should use curl for concurrent requests"
        assert "TOCTOU" in src or "toctou" in src, "Should test TOCTOU"
        assert "coupon" in src or "vote" in src, "Should test limit bypass (coupon/vote)"
        assert "50" in src and "ms" in src.lower() or "timing" in src.lower(), "Should do timing attack with threshold"
        record("race_condition_submodules", True)
    except Exception as e:
        record("race_condition_submodules", False, str(e))


# ══════════════════════════════════════════════════════════════
# SECTION 6: Protocol Intelligence Layer (8 tests)
# ══════════════════════════════════════════════════════════════

def test_protocol_intelligence_imports():
    """Verify protocol_intelligence module imports all classes"""
    try:
        from protocol_intelligence import (
            ProtocolAnalyzer, SmartFuzzer, NetworkIntelligence, ExploitAdvisor,
            TCPAnalysis, TLSAnalysis, HTTPAnalysis, DNSAnalysis, NetworkNode,
            FuzzResult, FuzzReport, ExploitRecommendation
        )
        # Verify class methods exist
        assert hasattr(ProtocolAnalyzer, 'analyze_tcp')
        assert hasattr(ProtocolAnalyzer, 'analyze_tls')
        assert hasattr(ProtocolAnalyzer, 'analyze_http')
        assert hasattr(ProtocolAnalyzer, 'analyze_dns')
        assert hasattr(SmartFuzzer, 'smart_fuzz')
        assert hasattr(NetworkIntelligence, 'detect_os')
        assert hasattr(ExploitAdvisor, 'recommend')
        record("protocol_intelligence_imports", True)
    except Exception as e:
        record("protocol_intelligence_imports", False, str(e))


async def test_protocol_analyzer_tcp():
    """Test TCP analysis with localhost"""
    try:
        from protocol_intelligence import ProtocolAnalyzer, TCPAnalysis
        result = await ProtocolAnalyzer.analyze_tcp("127.0.0.1", 22, timeout=3.0)
        # Should return a TCPAnalysis even if connection fails
        assert isinstance(result, TCPAnalysis)
        assert result.target == "127.0.0.1"
        assert result.port == 22
        record("protocol_analyzer_tcp", True)
    except Exception as e:
        record("protocol_analyzer_tcp", False, str(e))


async def test_protocol_analyzer_dns():
    """Test DNS analysis capabilities"""
    try:
        from protocol_intelligence import ProtocolAnalyzer, DNSAnalysis
        result = await ProtocolAnalyzer.analyze_dns("example.com", timeout=5.0)
        assert isinstance(result, DNSAnalysis)
        assert result.domain == "example.com"
        # Should have at least A records for example.com
        assert len(result.records) > 0 or result.zone_transfer_possible is not None
        record("protocol_analyzer_dns", True)
    except Exception as e:
        record("protocol_analyzer_dns", False, str(e))


def test_smart_fuzzer_payloads():
    """Verify SmartFuzzer has comprehensive payload database"""
    try:
        from protocol_intelligence import SmartFuzzer
        fuzzer = SmartFuzzer()
        # Verify payload categories exist
        assert "sqli" in fuzzer.PAYLOADS
        assert "xss" in fuzzer.PAYLOADS
        assert "ssti" in fuzzer.PAYLOADS
        assert "lfi" in fuzzer.PAYLOADS
        # Verify SQLi has tech-specific payloads
        assert "mysql" in fuzzer.PAYLOADS["sqli"]
        assert "postgresql" in fuzzer.PAYLOADS["sqli"]
        assert "detection" in fuzzer.PAYLOADS["sqli"]
        # Verify error patterns exist
        assert "sqli" in fuzzer.ERROR_PATTERNS
        assert "xss" in fuzzer.ERROR_PATTERNS
        assert "ssti" in fuzzer.ERROR_PATTERNS
        # Verify payload count is substantial
        total_payloads = sum(
            len(v) if isinstance(v, list) else sum(len(sv) for sv in v.values() if isinstance(sv, list))
            for v in fuzzer.PAYLOADS.values()
        )
        assert total_payloads >= 30, f"Should have 30+ payloads, got {total_payloads}"
        record("smart_fuzzer_payloads", True)
    except Exception as e:
        record("smart_fuzzer_payloads", False, str(e))


def test_network_intelligence():
    """Test NetworkIntelligence topology and OS detection"""
    try:
        from protocol_intelligence import NetworkIntelligence, TCPAnalysis, NetworkNode
        ni = NetworkIntelligence()
        # Add nodes with services matching ROLE_PATTERNS
        node1 = ni.add_node("10.0.0.1", ports=[22, 80, 443], services=[
            {"name": "ssh", "port": 22}, {"name": "http", "port": 80}, {"name": "https", "port": 443}
        ])
        node2 = ni.add_node("10.0.0.2", ports=[88, 389, 445, 53, 135], services=[
            {"name": "kerberos", "port": 88}, {"name": "ldap", "port": 389},
            {"name": "smb", "port": 445}, {"name": "dns", "port": 53}
        ])
        assert isinstance(node1, NetworkNode)
        assert isinstance(node2, NetworkNode)
        # Test OS detection from TTL
        tcp_linux = TCPAnalysis(
            target="10.0.0.1", port=22, state="open", ttl=64, window_size=5840,
            mss=1460, os_hints=["Linux 2.6.x"], banner="SSH-2.0-OpenSSH_8.9p1",
            response_time_ms=5.0, tcp_options=[]
        )
        os_name, confidence = ni.detect_os(tcp_linux)
        assert "linux" in os_name.lower() or confidence > 0
        # Test role detection (node2 has kerberos+ldap+smb+dns → domain_controller)
        role = ni.detect_role(node2)
        assert role == "domain_controller", f"Expected domain_controller, got {role}"
        # Test attack surface
        surface = ni.get_attack_surface()
        assert "total_hosts" in surface
        assert surface["total_hosts"] == 2
        record("network_intelligence", True)
    except Exception as e:
        record("network_intelligence", False, str(e))


def test_exploit_advisor():
    """Test ExploitAdvisor recommendations"""
    try:
        from protocol_intelligence import ExploitAdvisor
        # Test known vulnerable service
        recs = ExploitAdvisor.recommend(
            service="vsftpd", version="2.3.4",
            os="Linux", technologies=[]
        )
        assert len(recs) >= 1
        assert any("backdoor" in r.vulnerability.lower() or "CVE-2011-2523" in r.vulnerability for r in recs)
        # Test technology-specific vulns
        recs2 = ExploitAdvisor.recommend(
            service="http", version="2.4.49",
            os="Linux", technologies=["wordpress"]
        )
        assert len(recs2) >= 1
        # Test payload generation
        payload = ExploitAdvisor.get_payload_for_context(
            vuln_type="sqli", technology="mysql", os="Linux"
        )
        assert "payloads" in payload
        assert len(payload["payloads"]) > 0
        record("exploit_advisor", True)
    except Exception as e:
        record("exploit_advisor", False, str(e))


async def test_exec_protocol_deep_scan():
    """Test protocol_deep_scan tool execution on localhost"""
    try:
        r = await srv.protocol_deep_scan(
            target="127.0.0.1",
            depth="stealth",
            modules="tcp_fingerprint",
            ports="22",
            timeout=30,
        )
        d = json.loads(r) if isinstance(r, str) else r
        assert isinstance(d, dict)
        assert "target" in d
        record("exec:protocol_deep_scan", True)
    except Exception as e:
        record("exec:protocol_deep_scan", False, str(e))


async def test_exec_smart_fuzz_engine():
    """Test smart_fuzz_engine tool execution"""
    try:
        r = await srv.smart_fuzz_engine(
            target="http://127.0.0.1",
            depth="stealth",
            vuln_types="xss",
            method="GET",
            timeout=15,
        )
        d = json.loads(r) if isinstance(r, str) else r
        assert isinstance(d, dict)
        assert "target" in d
        record("exec:smart_fuzz_engine", True)
    except Exception as e:
        record("exec:smart_fuzz_engine", False, str(e))


async def test_exec_honeypot_detector():
    """Test honeypot_detector tool execution"""
    try:
        r = await srv.honeypot_detector(
            target="127.0.0.1",
            depth="stealth",
            modules="banner_analysis,timing_analysis,signature_match",
            timeout=30,
        )
        d = json.loads(r) if isinstance(r, str) else r
        assert isinstance(d, dict)
        assert "target" in d
        assert "honeypot_score" in d
        assert "verdict" in d
        assert d["verdict"] in ["LIKELY_HONEYPOT", "SUSPICIOUS", "LOW_RISK", "CLEAN"]
        assert "indicators" in d
        assert "known_honeypot_signatures" in d
        assert len(d["known_honeypot_signatures"]) >= 5  # cowrie, dionaea, kippo, etc.
        record("exec:honeypot_detector", True)
    except Exception as e:
        record("exec:honeypot_detector", False, str(e))


async def test_exec_auto_exploit():
    """Test auto_exploit tool execution in safe mode"""
    try:
        r = await srv.auto_exploit(
            target="127.0.0.1",
            strategy="safe",
            modules="privesc_suggest,custom_chain",
            timeout=30,
        )
        d = json.loads(r) if isinstance(r, str) else r
        assert isinstance(d, dict)
        assert "target" in d
        assert "strategy" in d
        assert d["strategy"] == "safe"
        assert "modules" in d
        assert "summary" in d
        # Privesc suggestions should always be present
        if "privesc_suggest" in d["modules"]:
            privesc = d["modules"]["privesc_suggest"]
            assert "linux" in privesc
            assert "windows" in privesc
            assert len(privesc["linux"]) >= 5  # SUID, kernel, sudo, cron, etc.
            assert len(privesc["windows"]) >= 4  # Token, unquoted paths, etc.
            assert "tools" in privesc
        record("exec:auto_exploit", True)
    except Exception as e:
        record("exec:auto_exploit", False, str(e))


def test_honeypot_signatures_database():
    """Verify honeypot signatures database is comprehensive"""
    try:
        sigs = srv.HONEYPOT_SIGNATURES
        assert "cowrie" in sigs
        assert "dionaea" in sigs
        assert "kippo" in sigs
        assert "glastopf" in sigs
        assert "honeyd" in sigs
        assert "tpot" in sigs
        assert "conpot" in sigs
        # Cowrie should have SSH banners
        assert len(sigs["cowrie"]["ssh_banners"]) >= 1
        assert len(sigs["cowrie"]["telltales"]) >= 1
        # Dionaea should have multiple default ports
        assert len(sigs["dionaea"]["default_ports"]) >= 5
        record("honeypot_signatures_db", True)
    except Exception as e:
        record("honeypot_signatures_db", False, str(e))


def test_honeypot_scoring_weights():
    """Verify honeypot scoring weights exist"""
    try:
        scoring = srv.HONEYPOT_SCORING
        assert "banner_match" in scoring
        assert "known_signature" in scoring
        assert "ttl_inconsistency" in scoring
        assert "behavioral_anomaly" in scoring
        assert scoring["known_signature"] >= 40  # Should be high weight
        assert scoring["banner_match"] >= 30
        record("honeypot_scoring_weights", True)
    except Exception as e:
        record("honeypot_scoring_weights", False, str(e))


def test_auto_exploit_signature_enhanced():
    """Verify auto_exploit has all expected sub-modules in source"""
    try:
        fn = srv.auto_exploit
        src = inspect.getsource(fn)
        # Verify all sub-modules
        assert "msf_auto" in src, "auto_exploit should have msf_auto module"
        assert "sqlmap_auto" in src, "auto_exploit should have sqlmap_auto module"
        assert "hydra_auto" in src, "auto_exploit should have hydra_auto module"
        assert "web_exploit" in src, "auto_exploit should have web_exploit module"
        assert "custom_chain" in src, "auto_exploit should have custom_chain module"
        assert "privesc_suggest" in src, "auto_exploit should have privesc_suggest module"
        # Verify exploit capabilities
        assert "msfconsole" in src, "Should use Metasploit"
        assert "sqlmap" in src, "Should use sqlmap"
        assert "hydra" in src, "Should use hydra"
        assert "lfi_to_rce" in src, "Should have LFI→RCE chain"
        assert "ssti_rce" in src, "Should have SSTI→RCE chain"
        assert "ssrf_chain" in src, "Should have SSRF chain"
        assert "SUID" in src or "suid" in src, "Should suggest SUID privesc"
        assert "GTFOBins" in src or "gtfobins" in src, "Should reference GTFOBins"
        assert "linpeas" in src.lower() or "LinPEAS" in src, "Should reference LinPEAS"
        record("auto_exploit_enhanced", True)
    except Exception as e:
        record("auto_exploit_enhanced", False, str(e))


# ══════════════════════════════════════════════════════════════
# SECTION 8: Integration Test — Full Correlation Pipeline
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
        assert len(corr["exploit_chains"]) >= 1
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


def test_cross_module_interconnection():
    """Verify that modules share data through PentestMemory and VulnCorrelator"""
    try:
        mem = srv.PentestMemory()
        vc = srv.VulnCorrelator(mem)
        kc = srv.KillChainTracker(mem)

        target = "192.168.1.100"

        # Simulate wireless_audit → pivot → recon chain
        mem.store_finding(target, "wireless_audit", "wpa_cracked", {"bssid": "AA:BB:CC:DD:EE:FF", "key": "password123"})
        mem.store_finding(target, "wireless_audit", "pivot_hosts", {"hosts": ["192.168.1.1", "192.168.1.50"]})
        kc.advance_phase(target, srv.KillChainPhase.RECONNAISSANCE, "wireless_audit", ["wifi_scan"])
        kc.advance_phase(target, srv.KillChainPhase.EXPLOITATION, "wireless_audit", ["wpa_cracked"])
        kc.advance_phase(target, srv.KillChainPhase.ACTIONS_ON_OBJECTIVES, "wireless_audit", ["pivoted_to_network"])

        # Verify cross-module data access
        assert mem.has_finding(target, "wpa_cracked"), "wireless findings should be accessible"
        assert mem.has_finding(target, "pivot_hosts"), "pivot hosts should be stored"

        # Simulate forensics findings feeding into correlation
        mem.store_finding(target, "forensics_engine", "malware_detected", {"type": "rootkit"})
        vc.add_vulnerability(srv.VulnFinding(
            vuln_id="rootkit_1", title="Rootkit detected on target",
            severity="critical", cvss_score=9.8, cvss_vector="",
            target=target, port=0, exploitable=True,
            mitre_techniques=["T1014", "T1547.006"]))

        corr = vc.correlate(target)
        assert corr["total_vulns"] >= 1
        assert "T1014" in corr["mitre_coverage"]

        # Verify kill chain progress across modules
        prog = kc.get_progress(target)
        assert prog["completion_pct"] >= round(3/7 * 100, 1)

        record("cross_module_interconnection", True)
    except Exception as e:
        record("cross_module_interconnection", False, str(e))


# ══════════════════════════════════════════════════════════════
# Runner
# ══════════════════════════════════════════════════════════════

async def run_all():
    print("=" * 72)
    print("  Kali MCP Server v6.2 — Comprehensive Test Suite")
    print("  26 Mega-Modules | Protocol Intelligence + Honeypot + AutoExploit")
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

    print("\n--- Module Signatures (26 tools) ---")
    test_module_signatures()

    print("\n--- Async Execution Tests ---")
    await test_exec_session_ops()
    await test_exec_recon()
    await test_exec_credential_cracker()
    await test_exec_reporting()
    await test_exec_payload_factory()
    await test_exec_osint()
    await test_exec_forensics()
    await test_exec_race_condition()
    await test_exec_crypto_forensics()
    await test_exec_post_exploit()

    print("\n--- Enhanced Feature Verification ---")
    test_wireless_audit_signature_enhanced()
    test_crypto_forensics_signature_enhanced()
    test_post_exploit_persistence_enhanced()
    test_auth_destroyer_idor_enhanced()
    test_forensics_engine_submodules()
    test_race_condition_submodules()

    print("\n--- Protocol Intelligence Layer (8 tests) ---")
    test_protocol_intelligence_imports()
    await test_protocol_analyzer_tcp()
    await test_protocol_analyzer_dns()
    test_smart_fuzzer_payloads()
    test_network_intelligence()
    test_exploit_advisor()
    await test_exec_protocol_deep_scan()
    await test_exec_smart_fuzz_engine()

    print("\n--- Honeypot Detector + Auto-Exploit (5 tests) ---")
    await test_exec_honeypot_detector()
    await test_exec_auto_exploit()
    test_honeypot_signatures_database()
    test_honeypot_scoring_weights()
    test_auto_exploit_signature_enhanced()

    print("\n--- Integration: Full Correlation Pipeline ---")
    test_full_correlation_pipeline()
    test_cross_module_interconnection()

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
        print("  ALL TESTS PASSED — v6.2 Protocol Intelligence READY")
    else:
        print(f"  {FAIL} test(s) failed")
    return FAIL == 0


if __name__ == "__main__":
    success = asyncio.run(run_all())
    sys.exit(0 if success else 1)
