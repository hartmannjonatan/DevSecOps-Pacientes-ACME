"""Contract/policy tests; captured audit responses are fixtures, never CI scan results."""
import copy
import datetime as dt
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/security"))
from sca import OperationalError, decide, inventory, parse_composer, parse_npm


class ScaTests(unittest.TestCase):
    def setUp(self):
        folder = Path(__file__).parent / "fixtures"
        self.report = json.loads((folder / "npm-audit-before.json").read_text())
        self.policy = json.loads((ROOT / "security/sca-policy.json").read_text())
        # These versions correspond to the real report captured before remediation.
        self.packages = [{"name": name, "version": "6.30.6", "path": "node_modules/" + name,
                          "scope": "runtime", "direct": name.endswith("-dom"), "source": "npm-registry"}
                         for name in ("react-router", "react-router-dom")]
        # Include all other captured lock entries in this reduced test inventory.
        # They have no findings; their only role here is validating coverage counts.
        self.packages += [{"name": f"unaffected-{i}", "version": "1.0.0", "path": f"node_modules/unaffected-{i}",
                           "scope": "development", "source": "synthetic-unit-test", "direct": False}
                          for i in range(self.report["metadata"]["dependencies"]["total"] - len(self.packages))]

    def test_real_npm_findings_resolve_versions_and_metavulnerabilities(self):
        findings = parse_npm(self.report, 1, self.packages)
        self.assertEqual(len(findings), 2)
        self.assertEqual({a["id"] for a in findings[1]["advisories"]},
                         {"GHSA-wrjc-x8rr-h8h6", "GHSA-337j-9hxr-rhxg"})
        self.assertEqual(findings[1]["via_packages"], ["react-router"])
        self.assertEqual(decide(findings, self.policy, "npm"), 1)
        self.assertTrue(all(f["decision"] == "block" for f in findings))

    def test_development_scope_changes_threshold_but_does_not_hide_findings(self):
        packages = copy.deepcopy(self.packages)
        for package in packages:
            package["scope"] = "development"
        findings = parse_npm(self.report, 1, packages)
        self.assertEqual(decide(findings, self.policy, "npm"), 0)
        self.assertTrue(all(f["decision"] == "review" for f in findings))
        findings[0]["severity"] = "high"
        self.assertEqual(decide(findings, self.policy, "npm"), 1)

    def test_unknown_severity_fails_policy(self):
        findings = parse_npm(self.report, 1, self.packages)
        findings[0]["severity"] = "unknown"
        self.assertEqual(decide(findings, self.policy, "npm"), 1)

    def test_npm_operational_and_inconsistent_reports_never_pass(self):
        cases = [(None, 1), ({"error": {"code": "ENOTFOUND"}}, 1), ({}, 0), (self.report, 0)]
        bad = copy.deepcopy(self.report)
        bad["metadata"]["vulnerabilities"]["total"] = 0
        cases.append((bad, 1))
        bad_coverage = copy.deepcopy(self.report)
        bad_coverage["metadata"]["dependencies"]["total"] = 0
        cases.append((bad_coverage, 1))
        for report, status in cases:
            with self.subTest(report=report, status=status), self.assertRaises(OperationalError):
                parse_npm(report, status, self.packages)
        with self.assertRaises(OperationalError):
            parse_npm(self.report, 1, [])

    def test_missing_advisory_reference_is_an_error(self):
        report = copy.deepcopy(self.report)
        report["vulnerabilities"]["react-router-dom"]["via"] = ["missing-package"]
        with self.assertRaises(OperationalError):
            parse_npm(report, 1, self.packages)

    def test_composer_clean_report_and_synthetic_advisory(self):
        clean = json.loads((Path(__file__).parent / "fixtures/composer-audit-clean.json").read_text())
        self.assertEqual(parse_composer(clean, 0, []), [])
        report = {"advisories": {"example/package": [{
            "advisoryId": "SYNTHETIC-UNIT-TEST", "packageName": "example/package",
            "title": "Synthetic unit-test advisory, not a discovered vulnerability", "severity": "high",
        }]}, "abandoned": []}
        package = {"name": "example/package", "version": "1.0.0", "scope": "development"}
        findings = parse_composer(report, 1, [package])
        self.assertEqual(decide(findings, self.policy, "composer"), 1)
        with self.assertRaises(OperationalError):
            parse_composer(report, 0, [package])
        for invalid in ({"error": "unavailable"}, {"advisories": [], "abandoned": [], "new_policy": ["issue"]}):
            with self.assertRaises(OperationalError):
                parse_composer(invalid, 1, [])

    def test_abandoned_is_reviewed_not_silently_omitted(self):
        package = {"name": "example/package", "version": "1.0.0", "scope": "development"}
        findings = parse_composer({"advisories": [], "abandoned": {"example/package": None}}, 0, [package])
        self.assertEqual(decide(findings, self.policy, "composer"), 0)
        self.assertEqual(findings[0]["decision"], "review")

    def test_exception_requires_exact_advisories_versions_and_review_date(self):
        findings = parse_npm(self.report, 1, self.packages)
        entry = {key: "Synthetic test justification" for key in ("classification", "reason", "remaining_risk",
                 "compensating_controls", "review_condition", "owner")}
        entry.update(ecosystem="npm", package="react-router", version="6.30.6",
                     expires_on=(dt.date.today() + dt.timedelta(days=1)).isoformat())
        self.policy["exceptions"] = [dict(entry, advisory_id=a["id"]) for a in findings[0]["advisories"]]
        self.assertEqual(decide(findings, self.policy, "npm"), 1)  # Parent package is not excepted.
        self.assertEqual(findings[0]["decision"], "accepted_exception")
        findings[0]["instances"][0]["version"] = "6.30.5"
        decide(findings, self.policy, "npm")
        self.assertEqual(findings[0]["decision"], "block")
        self.policy["exceptions"][0]["expires_on"] = "2000-01-01"
        with self.assertRaises(OperationalError):
            decide([], self.policy, "npm")

    def test_inventory_includes_development_and_local_packages(self):
        for ecosystem, manifest, lock in (("composer", "composer.json", "composer.lock"),
                                          ("npm", "package.json", "package-lock.json")):
            packages = inventory(ecosystem, json.loads((ROOT / manifest).read_text()), json.loads((ROOT / lock).read_text()))
            self.assertTrue(any(p["scope"] == "development" for p in packages))
            self.assertTrue(any(p["scope"] == "runtime" for p in packages))
            self.assertTrue(all(p["version"] for p in packages))
            if ecosystem == "npm":
                self.assertTrue(any(p["name"] == "@symfony/ux-react" and p["source"] == "local-file" for p in packages))


if __name__ == "__main__":
    unittest.main(verbosity=2)
