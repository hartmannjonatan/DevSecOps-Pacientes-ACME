"""Integrator contract tests; real ZAP before/after controls run in the DAST job."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts/security'))
from dast import ROOT, OperationalError, decide, validate_coverage


class DastPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / 'security/dast-policy.json').read_text())
        self.spec = json.loads((ROOT / 'docs/openapi.json').read_text())
        self.version = json.loads((ROOT / 'security/tools.json').read_text())['zap_version']
        self.coverage = {'completed': True, 'zap_version': self.version, 'active_status': '100',
                         'scan_progress': {'scanProgress': ['http://app:8080', {'HostProcess': [{'Plugin': ['rule', str(i), 'release', 'Complete', '5', '20', '0']} for i in self.policy['active_rule_ids']]}]},
                         'passive_remaining': 0, 'frontend_assets': ['a', 'b', 'c'],
                         'active_scanners': [{'id': i, 'enabled': 'true', 'allDependenciesAvailable': 'true', 'attackStrength': 'LOW', 'alertThreshold': 'MEDIUM'} for i in self.policy['active_rule_ids']],
                         'passive_scanners': [{'id': i, 'enabled': 'true'} for i in ['10020', '10038']],
                         'operations': [{'operation': method.upper() + ' ' + path, 'status': 200, 'expected_status': 200}
                                        for path, methods in self.spec['paths'].items() for method in methods],
                         'active_messages': [{'method': 'POST', 'path': p, 'status': 422}
                                             for p in ['/api/create', '/api/searchName/', '/api/edit/1']]}

    def test_contextual_risk_and_confidence(self):
        alerts = [{'pluginId': '10038', 'alert': 'Header missing', 'url': 'http://app:8080/', 'risk': str(r), 'confidence': str(c)}
                  for r, c in [(2, 2), (3, 3), (2, 1), (1, 3), (0, 2)]]
        self.assertEqual([x['decision'] for x in decide(alerts, self.policy)], ['block', 'block', 'review', 'review', 'review'])

    def test_invalid_classification_and_suppression_fail(self):
        for risk, confidence, url in [('4', '2', 'http://app:8080/'), ('2', '0', 'http://app:8080/'), ('2', '2', 'http://example.org/')]:
            with self.assertRaises(OperationalError):
                decide([{'pluginId': '1', 'alert': 'fixture', 'url': url, 'risk': risk, 'confidence': confidence}], self.policy)

    def test_valid_complete_coverage(self):
        validate_coverage(self.coverage, self.spec, self.policy, self.version)

    def test_incomplete_passive_active_or_rule_inventory(self):
        for key, value in [('completed', False), ('active_status', '99'), ('passive_remaining', 1),
                           ('zap_version', '0'), ('scan_progress', {}), ('active_messages', []), ('active_scanners', []), ('frontend_assets', [])]:
            c = copy.deepcopy(self.coverage); c[key] = value
            with self.subTest(key=key), self.assertRaises(OperationalError):
                validate_coverage(c, self.spec, self.policy, self.version)

    def test_missing_or_failed_operation_is_not_coverage(self):
        for missing in (True, False):
            c = copy.deepcopy(self.coverage)
            if missing:
                c['operations'].pop()
            else:
                c['operations'][0]['status'] = 404
            with self.assertRaises(OperationalError):
                validate_coverage(c, self.spec, self.policy, self.version)

    def test_unsupported_exception_or_relaxed_threshold(self):
        for key, value in [('exceptions', [{'rule': '10038'}]), ('minimum_blocking_risk', 3)]:
            p = copy.deepcopy(self.policy); p[key] = value
            with self.assertRaises(OperationalError):
                decide([], p)
