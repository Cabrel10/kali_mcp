"""Safety contracts for bounded, detection-only Nuclei execution."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from src.modules.vulnerability_scanner import VulnerabilityScanner


class FakeConfig:
    NUCLEI_ALLOWED_TARGETS = {"scanme.nmap.org"}
    NUCLEI_ALLOWED_INTENSITIES = frozenset({"fast", "deep", "full"})
    NUCLEI_ALLOWED_SEVERITIES = frozenset(
        {"info", "low", "medium", "high", "critical"}
    )
    NUCLEI_TEMPLATES = [
        "cves",
        "cves/2024",
        "exposed-panels",
        "exposures",
        "misconfiguration",
        "vulnerabilities",
        "all",
    ]
    NUCLEI_TIMEOUT_MAX = 45
    NUCLEI_OUTPUT_DIR = Path(".")

    @staticmethod
    def get_tool_path(tool_name):
        return f"/usr/local/bin/{tool_name}"


class FakeExecutor:
    def __init__(self, stdout=""):
        self.stdout = stdout
        self.calls = []

    async def check_tool_available(self, tool_name):
        return tool_name == "/usr/local/bin/nuclei"

    async def run_exec(self, arguments, timeout=None, **kwargs):
        self.calls.append({"arguments": list(arguments), "timeout": timeout})
        return self.stdout, "", 0


class FakeDatabase:
    def __init__(self):
        self.vulnerabilities = []
        self.cached = []

    def get_cached_result(self, target, key):
        return None

    def store_vulnerability(self, target, finding):
        self.vulnerabilities.append((target, finding))

    def cache_scan_result(self, target, key, result, **metadata):
        self.cached.append((target, key, json.loads(result), metadata))


class NucleiSafetyTests(unittest.TestCase):
    def make_scanner(self, output_dir, stdout=""):
        config = type(
            "TestConfig",
            (FakeConfig,),
            {"NUCLEI_OUTPUT_DIR": Path(output_dir)},
        )
        scanner = object.__new__(VulnerabilityScanner)
        scanner.config = config
        scanner.executor = FakeExecutor(stdout)
        scanner.db = FakeDatabase()
        return scanner

    def test_localhost_is_allowed_without_external_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanner = self.make_scanner(tmp)
            result = asyncio.run(
                scanner.smart_nuclei_scan("http://127.0.0.1:8000", use_cache=False)
            )
        self.assertEqual(result["mode"], "detection-only")
        self.assertEqual(result["total_vulns"], 0)

    def test_external_target_is_denied_without_exact_scope_and_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanner = self.make_scanner(tmp)
            with self.assertRaises(PermissionError):
                asyncio.run(
                    scanner.smart_nuclei_scan("https://example.com", use_cache=False)
                )
            with self.assertRaises(PermissionError):
                asyncio.run(
                    scanner.smart_nuclei_scan(
                        "https://scanme.nmap.org",
                        use_cache=False,
                        authorization_reference="",
                    )
                )

    def test_exact_allowlisted_target_requires_and_accepts_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanner = self.make_scanner(tmp)
            result = asyncio.run(
                scanner.smart_nuclei_scan(
                    "https://scanme.nmap.org",
                    use_cache=False,
                    authorization_reference="scope-ticket-123",
                )
            )
        self.assertEqual(result["target"], "https://scanme.nmap.org")

    def test_shell_injection_and_invalid_templates_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanner = self.make_scanner(tmp)
            for target in ("localhost;id", "http://localhost/ bad", "file:///etc/passwd"):
                with self.subTest(target=target), self.assertRaises(ValueError):
                    asyncio.run(scanner.smart_nuclei_scan(target, use_cache=False))
            with self.assertRaises(ValueError):
                asyncio.run(
                    scanner.smart_nuclei_scan(
                        "localhost",
                        templates=["../../custom-template"],
                        use_cache=False,
                    )
                )

    def test_command_is_argument_vector_jsonl_and_timeout_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            scanner = self.make_scanner(tmp)
            asyncio.run(
                scanner.smart_nuclei_scan(
                    "localhost",
                    intensity="full",
                    use_cache=False,
                )
            )
        call = scanner.executor.calls[0]
        self.assertEqual(call["timeout"], 45)
        self.assertIn("-jsonl", call["arguments"])
        self.assertNotIn("-json", call["arguments"])
        joined = " ".join(call["arguments"]).lower()
        self.assertNotIn("auto-exploit", joined)
        self.assertIn("dos,fuzz,intrusive,bruteforce", joined)
        self.assertIn("-exclude-type", call["arguments"])
        self.assertIn("code,headless", joined)
        self.assertNotIn("default-logins", joined)
        self.assertEqual(call["arguments"][0], "/usr/local/bin/nuclei")

    def test_valid_jsonl_is_persisted_and_invalid_jsonl_fails_closed(self):
        record = {
            "template-id": "CVE-2024-TEST",
            "type": "http",
            "matched-at": "http://localhost",
            "info": {"name": "Test finding", "severity": "high"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            scanner = self.make_scanner(tmp, json.dumps(record) + "\n")
            result = asyncio.run(
                scanner.smart_nuclei_scan("localhost", use_cache=False)
            )
            output = Path(result["jsonl_output"])
            self.assertTrue(output.is_file())
            self.assertEqual(json.loads(output.read_text()), record)
            self.assertEqual(result["total_vulns"], 1)

            invalid_scanner = self.make_scanner(tmp, "not-json\n")
            with self.assertRaisesRegex(ValueError, "line 1"):
                asyncio.run(
                    invalid_scanner.smart_nuclei_scan("localhost", use_cache=False)
                )


if __name__ == "__main__":
    unittest.main()
