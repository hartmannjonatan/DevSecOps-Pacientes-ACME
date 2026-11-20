"""Real Checkov tests: actual Dockerfile, isolated regressions and fail-closed policy."""
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
from iac import OperationalError, REQUIRED_CHECKS, decide, scan, validate_report
from iac_demo import demonstrate, sources


class IacTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="acme-iac-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        fixture(self.repo)
        self.dockerfile = (ROOT / "Dockerfile").read_text()
        (self.repo / "Dockerfile").write_text(self.dockerfile)
        shutil.copyfile(ROOT / "compose.yaml", self.repo / "compose.yaml")
        self.policy = json.loads((ROOT / "security/iac-policy.json").read_text())

    def run_scan(self, name, config=ROOT / "security"):
        output = self.root / name
        code = scan(self.repo, output, config)
        return code, json.loads((output / "result.json").read_text())

    def test_detect_block_correct_same_checks_and_policy(self):
        before, after = sources()
        (self.repo / "Dockerfile").write_text(before)
        code, blocked = self.run_scan("before")
        self.assertEqual(code, 1)
        ids = {f["rule_id"] for f in blocked["findings"] if f["decision"] == "block"}
        self.assertTrue({"CKV_DOCKER_8", "CKV_ACME_DOCKER_1", "CKV_ACME_DOCKER_2"} <= ids)
        self.assertTrue(blocked["analysis_valid"])
        (self.repo / "Dockerfile").write_text(after)
        code, corrected = self.run_scan("after")
        self.assertEqual(code, 0)
        self.assertEqual(corrected["findings"], [])
        for name in ("policy_sha256", "local_checks_sha256", "scanner_image", "executed_checks"):
            self.assertEqual(blocked[name], corrected[name])
        evidence = ROOT / "artifacts/security/controls/iac"
        for name in ("before", "after"):
            shutil.copytree(self.root / name, evidence / name, dirs_exist_ok=True)

    def test_numeric_root_disabled_health_and_unpinned_image_block(self):
        bad = self.dockerfile.replace("USER www-data", "USER 0:0")
        bad = "\n".join("HEALTHCHECK NONE" if s.startswith("HEALTHCHECK ") else s for s in bad.splitlines()) + "\n"
        import re
        bad = re.sub(r"(FROM node:[^@]+)@sha256:[a-f0-9]{64}", r"\1", bad)
        (self.repo / "Dockerfile").write_text(bad)
        code, result = self.run_scan("numeric-root")
        self.assertEqual(code, 1)
        self.assertTrue({"CKV_ACME_DOCKER_1", "CKV_ACME_DOCKER_2", "CKV_ACME_DOCKER_3"}
                        <= {f["rule_id"] for f in result["findings"]})

    def test_build_stage_does_not_supply_runtime_user_or_health(self):
        lines = self.dockerfile.splitlines(True)
        health = next(line for line in lines if line.startswith("HEALTHCHECK "))
        bad = self.dockerfile.replace("USER www-data\n", "").replace(health, "")
        bad = bad.replace("FROM php-base AS app", "USER www-data\n" + health + "\nFROM php-base AS app")
        (self.repo / "Dockerfile").write_text(bad)
        code, result = self.run_scan("build-stage")
        self.assertEqual(code, 1)
        self.assertTrue({"CKV_ACME_DOCKER_1", "CKV_ACME_DOCKER_2"} <= {f["rule_id"] for f in result["findings"]})

    def test_suppressions_and_config_cannot_bypass(self):
        bad, _ = sources()
        (self.repo / "Dockerfile").write_text("# checkov:skip=CKV_ACME_DOCKER_1:synthetic bypass attempt\n" + bad)
        (self.repo / ".checkov.yaml").write_text("soft-fail: true\nskip-check: [CKV_ACME_DOCKER_1]\n")
        code, result = self.run_scan("suppressed")
        self.assertEqual(code, 2)
        self.assertFalse(result["analysis_valid"])
        self.assertIn("suppressed", result["error"])

    def test_real_invalid_target_is_operational_error(self):
        output = ROOT / "artifacts/security/controls/iac/operational"
        self.assertEqual(demonstrate("iac-operational-failure", output), 2)
        result = json.loads((output / "result.json").read_text())
        self.assertFalse(result["analysis_valid"])
        self.assertTrue((output / "checkov.json").exists())

    def test_missing_custom_rules_and_different_compose_target_fail(self):
        config = self.root / "security"
        shutil.copytree(ROOT / "security", config)
        (config / "checkov/__init__.py").unlink()
        code, result = self.run_scan("missing-checks", config)
        self.assertEqual(code, 2)
        self.assertIn("not executed", result["error"])
        compose = self.repo / "compose.yaml"
        compose.write_text(compose.read_text().replace("target: app", "target: assets"))
        self.assertEqual(self.run_scan("wrong-target")[0], 2)

    def test_missing_file_and_runtime_fail(self):
        self.assertEqual(scan(self.repo, self.root / "no-runtime", docker="/nonexistent/acme-docker"), 2)
        (self.repo / "Dockerfile").unlink()
        self.assertEqual(self.run_scan("missing-file")[0], 2)

    def test_report_consistency_and_coverage(self):
        rows = [{"check_id": rule, "check_name": "Synthetic check", "file_path": "/src/Dockerfile",
                 "check_result": {"result": "PASSED"}} for rule in REQUIRED_CHECKS]
        report = {"check_type": "dockerfile", "results": {"passed_checks": rows, "failed_checks": [],
                  "skipped_checks": [], "parsing_errors": []}, "summary": {"checkov_version": "test",
                  "resource_count": 1, "passed": len(rows), "failed": 0, "skipped": 0, "parsing_errors": 0}}
        self.assertEqual(validate_report(report, 0, "test")[0], [])
        for field, value in [("resource_count", 0), ("checkov_version", "other"), ("passed", 0), ("parsing_errors", 1)]:
            bad = copy.deepcopy(report)
            bad["summary"][field] = value
            with self.assertRaises(OperationalError):
                validate_report(bad, 0, "test")
        for code in (1, 2, 124):
            with self.assertRaises(OperationalError):
                validate_report(report, code, "test")
        bad = copy.deepcopy(report)
        bad["results"]["passed_checks"].pop()
        bad["summary"]["passed"] -= 1
        with self.assertRaises(OperationalError):
            validate_report(bad, 0, "test")

    def test_review_unknown_and_core_controls(self):
        row = {"check_id": "CKV_DOCKER_6", "check_name": "Synthetic MAINTAINER", "file_line_range": [1, 1]}
        self.assertEqual(decide([row], self.policy)[0]["decision"], "review")
        row["check_id"] = "UNRECOGNIZED_RULE"
        self.assertEqual(decide([row], self.policy)[0]["decision"], "block")
        self.policy["checks"]["CKV_ACME_DOCKER_1"]["decision"] = "review"
        with self.assertRaises(OperationalError):
            decide([], self.policy)
