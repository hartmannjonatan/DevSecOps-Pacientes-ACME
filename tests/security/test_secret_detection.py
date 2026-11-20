"""Behavior tests using the pinned real scanner, plus report/exception failure cases."""
import datetime as dt
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/security"))
from scan import OperationalError, command, exceptions_from, scan, validate_report
from demo import commit, demonstrate, fake_secret, fixture


class SecretDetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="acme-security-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        fixture(self.repo)
        self.config = self.root / "security"
        shutil.copytree(ROOT / "security", self.config)
        self.exceptions([])

    def exceptions(self, entries):
        (self.config / "secret-exceptions.json").write_text(json.dumps({
            "schema_version": 1, "exceptions": entries,
        }))

    def run_scan(self, name):
        output = self.root / name
        code = scan(self.repo, output, self.config)
        return code, json.loads((output / "result.json").read_text())

    def test_detect_block_correct_revalidate_same_rules(self):
        code, clean = self.run_scan("clean")
        self.assertEqual(code, 0)
        secret = fake_secret(self.repo)
        # Inline suppression and ignore files must not bypass the policy.
        path = self.repo / "demo.env"
        path.write_text(path.read_text().rstrip() + " # gitleaks:allow\n")
        code, blocked = self.run_scan("blocked")
        self.assertEqual(code, 1)
        self.assertEqual(blocked["status"], "policy_violation")
        self.assertTrue(any(f["RuleID"] == "symfony-app-secret" for f in blocked["findings"]))
        self.assertNotIn(secret, json.dumps(blocked))
        (self.repo / ".gitleaksignore").write_text("\n".join(f["Fingerprint"] for f in blocked["findings"]))
        self.assertEqual(self.run_scan("ignored-attempt")[0], 1)
        (self.repo / ".gitleaksignore").unlink()
        (self.repo / "demo.env").unlink()
        code, corrected = self.run_scan("corrected")
        self.assertEqual(code, 0)
        self.assertEqual(blocked["configuration_sha256"], corrected["configuration_sha256"])
        evidence = ROOT / "artifacts/security/controls"
        evidence.mkdir(parents=True, exist_ok=True)
        for name, result in (("clean", clean), ("blocked", blocked), ("corrected", corrected)):
            (evidence / (name + ".json")).write_text(json.dumps(result, indent=2) + "\n")

    def test_removed_secret_still_blocks_history_and_exception_is_specific(self):
        secret = fake_secret(self.repo)
        commit(self.repo, "Intentionally commit a fictional token in the isolated test")
        (self.repo / "demo.env").unlink()
        commit(self.repo, "Remove the fictional token; historical scan must still detect it")
        code, result = self.run_scan("history")
        self.assertEqual(code, 1)
        self.assertTrue(result["findings"])
        self.assertTrue(all(f["scope"] == "history" for f in result["findings"]))
        entries = [{
            "scope": "history", "fingerprint": f["Fingerprint"],
            "classification": "synthetic_test", "reason": "Intentionally fictional token",
            "remaining_risk": "No service accepts this test token", "compensating_controls": "Isolated temporary repository",
            "review_condition": "End of this test", "owner": "test suite",
            "expires_on": (dt.date.today() + dt.timedelta(days=1)).isoformat(),
        } for f in result["findings"]]
        self.exceptions(entries)
        code, accepted = self.run_scan("accepted")
        self.assertEqual(code, 0)
        self.assertGreater(accepted["accepted_findings"], 0)
        self.assertNotIn(secret, json.dumps(accepted))
        fake_secret(self.repo)
        code, new = self.run_scan("new")
        self.assertEqual(code, 1)
        self.assertTrue(any(f["scope"] == "files" and f["decision"] == "block" for f in new["findings"]))

    def test_real_scanner_configuration_failure_is_not_clean(self):
        output = ROOT / "artifacts/security/controls/operational"
        code = demonstrate("operational-failure", output)
        result = json.loads((output / "result.json").read_text())
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "operational_error")
        self.assertNotEqual(result.get("blocking_findings"), 0)

    def test_unavailable_runtime_is_operational_error(self):
        output = self.root / "unavailable"
        self.assertEqual(scan(self.repo, output, self.config, docker="/nonexistent/acme-docker"), 2)

    def test_shallow_history_is_not_accepted(self):
        (self.repo / "second.txt").write_text("Second revision\n")
        commit(self.repo, "Second revision")
        shallow = self.root / "shallow"
        result = command(["git", "clone", "--depth=1", self.repo.as_uri(), str(shallow)])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(scan(shallow, self.root / "shallow-result", self.config), 2)

    def test_reports_must_exist_parse_and_agree_with_exit_code(self):
        path = self.root / "report.json"
        with self.assertRaises(OperationalError):
            validate_report(path, 0)
        for text, code in (("not json", 0), ("{}", 0), ("[{}]", 42), ("[]", 42), ("[]", 1)):
            with self.subTest(text=text, code=code):
                path.write_text(text)
                with self.assertRaises(OperationalError):
                    validate_report(path, code)

    def test_expired_or_incomplete_exceptions_fail_closed(self):
        path = self.config / "secret-exceptions.json"
        self.exceptions([{"fingerprint": "missing fields"}])
        with self.assertRaises(OperationalError):
            exceptions_from(path, dt.date.today())
        entry = {key: "synthetic test" for key in ("classification", "reason", "remaining_risk",
                 "compensating_controls", "review_condition", "owner")}
        entry.update(scope="history", fingerprint="a" * 40 + ":demo.env:rule:1", expires_on="2000-01-01")
        self.exceptions([entry])
        with self.assertRaises(OperationalError):
            exceptions_from(path, dt.date.today())


if __name__ == "__main__":
    unittest.main(verbosity=2)
