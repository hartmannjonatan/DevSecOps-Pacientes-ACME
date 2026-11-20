"""Exercise actual Semgrep, corrections, coverage and fail-closed decisions."""
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/security"))
from demo import fixture
from sast import OperationalError, decide, scan, snapshot, validate_report
from sast_demo import BEFORE, AFTER, demonstrate


class SastTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="acme-sast-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        fixture(self.repo)
        self.policy = json.loads((ROOT / "security/sast-policy.json").read_text())

    def run_scan(self, name):
        output = self.root / name
        code = scan(self.repo, output)
        return code, json.loads((output / "result.json").read_text())

    def test_real_php_jsx_detection_correction_and_suppression_resistance(self):
        # These paths are normally ignored by Semgrep's built-in defaults.
        (self.repo / "tests").mkdir()
        for name, source in BEFORE.items():
            (self.repo / "tests" / name).write_text(source)
        (self.repo / ".semgrepignore").write_text("*\n")
        php = self.repo / "tests/example.php"
        php.write_text(php.read_text().replace('    return $db', '    // nosemgrep\n    return $db'))
        code, before = self.run_scan("before")
        self.assertEqual(code, 1)
        self.assertEqual(before["source_count"], 2)
        self.assertEqual(before["blocking_findings"], 2)
        self.assertEqual({f["path"] for f in before["findings"]}, {"tests/example.php", "tests/Example.jsx"})
        self.assertTrue(before["analysis_valid"])
        for name, source in AFTER.items():
            (self.repo / "tests" / name).write_text(source)
        code, after = self.run_scan("after")
        self.assertEqual(code, 0)
        self.assertEqual(after["findings"], [])
        for field in ("rules_sha256", "policy_sha256", "scanner_image", "rule_count", "source_count"):
            self.assertEqual(before[field], after[field])
        evidence = ROOT / "artifacts/security/controls/sast"
        evidence.mkdir(parents=True, exist_ok=True)
        for name in ("before", "after"):
            shutil.copytree(self.root / name, evidence / name, dirs_exist_ok=True)

    def test_real_parse_failure_is_operational_error(self):
        output = ROOT / "artifacts/security/controls/sast/operational"
        self.assertEqual(demonstrate("sast-operational-failure", output), 2)
        result = json.loads((output / "result.json").read_text())
        self.assertFalse(result["analysis_valid"])
        self.assertEqual(result["status"], "operational_error")
        self.assertTrue(json.loads((output / "semgrep.json").read_text())["errors"])

    def test_report_rejects_incomplete_or_inconsistent_analysis(self):
        report = {"version": "1", "results": [], "errors": [], "paths": {"scanned": ["a.php"]},
                  "engine_requested": "OSS", "skipped_rules": []}
        inventory = [{"path": "a.php"}]
        self.assertEqual(validate_report(report, 0, inventory, "1", {}), [])
        for field, value in [("version", "2"), ("errors", [{}]), ("paths", {"scanned": []}),
                             ("results", None), ("engine_requested", "PRO"), ("skipped_rules", [{}])]:
            bad = copy.deepcopy(report)
            bad[field] = value
            with self.assertRaises(OperationalError):
                validate_report(bad, 0, inventory, "1", {})
        for code in (1, 2, 7, 124):
            with self.assertRaises(OperationalError):
                validate_report(report, code, inventory, "1", {})
        bad = copy.deepcopy(report)
        bad["results"] = [{"check_id": "not-in-rules"}]
        with self.assertRaises(OperationalError):
            validate_report(bad, 1, inventory, "1", {})

    def test_policy_confidence_severity_unknown_and_no_blanket_exception(self):
        row = {"check_id": "r", "path": "file.php", "start": {"line": 1}}
        rule = {"severity": "WARNING", "metadata": {"confidence": "LOW"}, "message": "Synthetic rule"}
        for severity, confidence, expected in [("WARNING", "LOW", "review"), ("ERROR", "LOW", "review"),
                                                ("WARNING", "MEDIUM", "block"), ("ERROR", "HIGH", "block"),
                                                ("INFO", "HIGH", "review"), ("WARNING", "UNKNOWN", "block")]:
            rule["severity"] = severity
            rule["metadata"]["confidence"] = confidence
            self.assertEqual(decide([row], {"r": rule}, self.policy)[0]["decision"], expected)
        self.policy["exceptions"] = [{"path": "*"}]
        with self.assertRaises(OperationalError):
            decide([], {}, self.policy)

    def test_empty_source_and_symlinks_fail(self):
        with self.assertRaises(OperationalError):
            snapshot(self.repo, self.root / "empty")
        (self.repo / "a.php").symlink_to(ROOT / "public/index.php")
        with self.assertRaises(OperationalError):
            snapshot(self.repo, self.root / "symlink")

    def test_unavailable_runtime_records_error(self):
        output = self.root / "unavailable"
        self.assertEqual(scan(self.repo, output, docker="/nonexistent/acme-docker"), 2)
        self.assertFalse(json.loads((output / "result.json").read_text())["analysis_valid"])

    def test_modified_rule_cache_blocks(self):
        cache = self.root / "cache"
        cache.mkdir()
        (cache / "rules.json").write_text('{"rules": []}\n')
        output = self.root / "changed-rules"
        self.assertEqual(scan(self.repo, output, cache=cache), 2)
        self.assertIn("Cached rules changed", json.loads((output / "result.json").read_text())["error"])
