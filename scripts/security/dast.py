#!/usr/bin/env python3
"""Build, scan and remove an isolated disposable application; fail closed."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import uuid

from scan import ROOT, OperationalError, command, digest, git


def validate_coverage(coverage, spec, policy, version):
    if (coverage.get('completed') is not True or coverage.get('zap_version') != version
            or coverage.get('active_status') != '100' or coverage.get('passive_remaining') != 0):
        raise OperationalError('Incomplete scan, unexpected ZAP version or pending passive analysis')
    expected = {method.upper() + ' ' + path for path, methods in spec['paths'].items()
                for method in methods if method in {'get', 'post', 'delete', 'put', 'patch'}}
    operations = coverage.get('operations', [])
    if {row['operation'] for row in operations} != expected or len(operations) != len(expected):
        raise OperationalError('Successful HTTP coverage does not match OpenAPI operations')
    if any(row['status'] != row['expected_status'] or row['status'] not in (200, 201) for row in operations):
        raise OperationalError('Relevant endpoint failed during functional preflight through ZAP')
    enabled = {int(row['id']) for row in coverage['active_scanners'] if str(row['enabled']).lower() == 'true'}
    if enabled != set(policy['active_rule_ids']) or not coverage.get('passive_scanners'):
        raise OperationalError('Scanner rule inventory differs from policy')
    for row in coverage['active_scanners']:
        if int(row['id']) in enabled and (row.get('allDependenciesAvailable') != 'true'
                or row.get('attackStrength') != policy['attack_strength']
                or row.get('alertThreshold') != policy['alert_threshold']):
            raise OperationalError('Active scanner unavailable or incorrectly configured')
    passive = {str(row['id']) for row in coverage['passive_scanners'] if str(row['enabled']).lower() == 'true'}
    if not {'10020', '10038'} <= passive:
        raise OperationalError('Required passive header scanners disabled')
    progress = coverage.get('scan_progress', {}).get('scanProgress', [])
    if len(progress) != 2 or progress[0] != 'http://app:8080':
        raise OperationalError('Missing per-rule completion evidence')
    completed = set()
    for item in progress[1].get('HostProcess', []):
        plugin = item['Plugin']
        if plugin[3] != 'Complete' or int(plugin[5]) <= 0:
            raise OperationalError('Active rule skipped, timed out or sent no requests')
        completed.add(int(plugin[1]))
    if completed != enabled:
        raise OperationalError('Incomplete active rule execution')
    messages = coverage.get('active_messages', [])
    # Parameter-bearing form endpoints must have real attack traffic, not just a successful preflight.
    for path in ('/api/create', '/api/searchName/', '/api/edit/'):
        if not any(m['method'] == 'POST' and m['path'].startswith(path) and m['status'] > 0 for m in messages):
            raise OperationalError(f'Active requests missing for {path}')
    if len(coverage.get('frontend_assets', [])) < 3:
        raise OperationalError('Frontend was not reached')


def decide(alerts, policy):
    if (policy.get('schema_version') != 1 or policy.get('exceptions') != []
            or policy.get('minimum_blocking_risk') != 2 or policy.get('minimum_blocking_confidence') != 2
            or policy.get('active_rule_ids') != [40012, 40018, 40003]
            or policy.get('attack_strength') != 'LOW' or policy.get('alert_threshold') != 'MEDIUM'):
        raise OperationalError('Unsupported DAST policy; review integration and controls')
    if not isinstance(alerts, list):
        raise OperationalError('Malformed ZAP alerts')
    result = []
    for row in alerts:
        risk = {'Informational': 0, 'Low': 1, 'Medium': 2, 'High': 3}.get(row['risk'], row['risk'])
        confidence = {'False Positive': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Confirmed': 4}.get(row['confidence'], row['confidence'])
        risk, confidence = int(risk), int(confidence)
        if risk not in range(4) or confidence not in range(1, 5) or not row['url'].startswith('http://app:8080/'):
            raise OperationalError('Unknown/suppressed classification or out-of-scope alert')
        result.append({'rule_id': row['pluginId'], 'name': row['alert'], 'url': row['url'],
                       'risk': risk, 'confidence': confidence,
                       'decision': 'block' if risk >= 2 and confidence >= 2 else 'review'})
    return result


def scan(scenario, output):
    output.mkdir(parents=True, exist_ok=True)
    # A unique report directory avoids presenting stale reports as this run's evidence.
    if any(output.iterdir()):
        raise OperationalError(f'Output directory is not empty: {output}. Use a new --output path.')
    project = 'acme-dast-' + uuid.uuid4().hex[:12]
    result = {'schema_version': 1, 'category': 'dast', 'scenario': scenario, 'project': project,
              'run_id': str(uuid.uuid4()), 'timestamp_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
              'analysis_valid': False, 'status': 'operational_error', 'findings': []}
    code = 2
    dc = ['docker', 'compose', '--project-directory', str(ROOT), '--env-file', str(ROOT / 'tests/compose.env'),
          '-p', project, '-f', str(ROOT / 'compose.yaml'), '-f', str(ROOT / 'security/zap/compose.yaml')]
    cleanup_dc = dc.copy()
    try:
        tools = json.loads((ROOT / 'security/tools.json').read_text())
        policy = json.loads((ROOT / 'security/dast-policy.json').read_text())
        decide([], policy)
        image = tools['zap_image']
        if '@sha256:' not in image:
            raise OperationalError('ZAP image must be pinned by digest')
        result.update(commit=git(ROOT, 'rev-parse', 'HEAD').decode().strip(),
                      working_tree_dirty=bool(git(ROOT, 'status', '--porcelain')),
                      scanner_image=image, scanner_version=tools['zap_version'],
                      policy_sha256=digest(ROOT / 'security/dast-policy.json'),
                      runner_sha256=digest(ROOT / 'scripts/security/zap_runner.py'),
                      openapi_sha256=digest(ROOT / 'docs/openapi.json'),
                      dockerfile_sha256=digest(ROOT / 'Dockerfile'))
        with tempfile.TemporaryDirectory(prefix='acme-dast-config-') as tmp:
            config = Path(tmp)
            for source, target in [('security/dast-policy.json', 'dast-policy.json'),
                                   ('docs/openapi.json', 'openapi.json'),
                                   ('scripts/security/zap_runner.py', 'runner.py')]:
                (config / target).write_bytes((ROOT / source).read_bytes())
            if scenario == 'dast-fixture':
                fixture = ROOT / 'tests/security/fixtures/dast-no-headers.conf'
                override = config / 'fixture.json'
                override.write_text(json.dumps({'services': {'app': {'volumes': [
                    f'{fixture}:/etc/apache2/sites-available/000-default.conf:ro']}}}))
                dc.extend(['-f', str(override)])
                result['fixture_sha256'] = digest(fixture)
            def run(args, log, timeout=240):
                p = command(args, timeout=timeout)
                (output / log).write_bytes(p.stdout + p.stderr)
                if p.returncode:
                    raise OperationalError(f'Command failed ({p.returncode}); see {log}')
                return p
            run([*dc, 'build'], 'build.log', 900)
            run([*dc, 'up', '-d', '--wait', '--wait-timeout', '180'], 'startup.log', 210)
            image_id = run([*dc, 'images', '-q', 'app'], 'app-image.txt').stdout.decode().strip()
            result['app_image_id'] = image_id
            run([*dc, 'exec', '-T', 'app', 'php', 'tests/functional.php'], 'functional.log')
            if scenario == 'dast-operational-failure':
                run([*dc, 'stop', 'app'], 'intentional-stop.log')
            p = command(['docker', 'run', '--rm', '--name', project + '-zap', '--network', project + '_default',
                         '--init', '--no-healthcheck', '--cap-drop=ALL', '--security-opt', 'no-new-privileges', '--user', f'{os.getuid()}:{os.getgid()}',
                         '-e', 'HOME=/tmp', '-e', 'PYTHONDONTWRITEBYTECODE=1',
                         '-v', f'{config}:/config:ro', '-v', f'{output}:/out',
                         '--entrypoint', 'python3', image, '/config/runner.py'], timeout=1000)
            (output / 'scanner.log').write_bytes(p.stdout + p.stderr)
            result['scanner_exit_code'] = p.returncode
            if p.returncode:
                raise OperationalError('ZAP runner failed; see scanner.log and coverage.json')
            coverage = json.loads((output / 'coverage.json').read_text())
            validate_coverage(coverage, json.loads((ROOT / 'docs/openapi.json').read_text()), policy, tools['zap_version'])
            result['findings'] = decide(json.loads((output / 'alerts.json').read_text()), policy)
            result['blocking_findings'] = sum(f['decision'] == 'block' for f in result['findings'])
            result['review_findings'] = sum(f['decision'] == 'review' for f in result['findings'])
            result['successful_operations'] = len(coverage['operations'])
            result['active_requests'] = len(coverage['active_messages'])
            code = int(result['blocking_findings'] > 0)
            result.update(analysis_valid=True, status='policy_violation' if code else 'pass')
    except (OperationalError, OSError, ValueError, KeyError, TypeError) as exc:
        result['error'] = str(exc)
    finally:
        # Only this invocation's random project/container; never local/test or global prune.
        # Drop the temporary fixture override, which may no longer exist.
        try:
            logs = command([*cleanup_dc, 'logs', '--no-color', '--timestamps'], timeout=30)
            (output / 'services.log').write_bytes(logs.stdout + logs.stderr)
            probe = command(['docker', 'ps', '-aq', '--filter', 'name=^/' + project + '-zap$'])
            if probe.returncode:
                raise OperationalError('Cannot inspect remaining ZAP container')
            if probe.stdout.strip():
                removal = command(['docker', 'rm', '-f', project + '-zap'])
                if removal.returncode:
                    raise OperationalError('Failed to remove this run ZAP container')
            cleanup = command([*cleanup_dc, 'down', '--volumes', '--remove-orphans', '--rmi', 'local'], timeout=90)
            (output / 'cleanup.log').write_bytes(cleanup.stdout + cleanup.stderr)
            if cleanup.returncode:
                raise OperationalError('Failed to clean this disposable project')
            result['cleanup_success'] = True
        except (OperationalError, OSError) as exc:
            result.update(cleanup_success=False, error=str(exc), status='operational_error', analysis_valid=False)
            code = 2
    result['exit_code'] = code
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f"DAST: {result['status']} (exit {code}); report: {output / 'result.json'}")
    return code


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', choices=['normal', 'dast-fixture', 'dast-corrected', 'dast-operational-failure'], default='normal')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    output = args.output or ROOT / 'artifacts/security' / ('dast-' + dt.datetime.now().strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:6])
    try:
        raise SystemExit(scan(args.scenario, output.resolve()))
    except OperationalError as exc:
        print(f'DAST: operational_error: {exc}')
        raise SystemExit(2)
