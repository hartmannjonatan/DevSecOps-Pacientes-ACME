#!/usr/bin/env python3
"""Runs inside the pinned ZAP image; only targets the disposable app:8080."""
import json
from pathlib import Path
import re
import subprocess
import time
import traceback
from urllib.parse import urlsplit

import requests

OUT = Path('/out')
TARGET = 'http://app:8080'
API = 'http://127.0.0.1:8090'
http = requests.Session()
http.trust_env = False
coverage = {'operations': [], 'active_messages': [], 'completed': False}


def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2) + '\n')


def api(component, kind, name, **params):
    r = http.get(f'{API}/JSON/{component}/{kind}/{name}/', params=params, timeout=180)
    if not r.ok:
        raise RuntimeError(f'ZAP API {component}/{name}: HTTP {r.status_code}: {r.text}')
    data = r.json()
    if 'code' in data:
        raise RuntimeError(f'ZAP API {component}/{name}: {data}')
    return data


def wait(probe, timeout, label):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(1)
    raise RuntimeError(f'Timeout waiting for {label}; analysis incomplete')


def request(method, path, data=None, expected=200, operation=None):
    r = http.request(method, TARGET + path, data=data, timeout=20, allow_redirects=False,
                     proxies={'http': API, 'https': API})
    if operation:
        coverage['operations'].append({'operation': operation, 'method': method, 'path': path,
                                       'expected_status': expected, 'status': r.status_code})
    if r.status_code != expected:
        raise RuntimeError(f'{method} {path}: expected {expected}, received {r.status_code}')
    return r


def form(n):
    return {'nome': f'Paciente Ficticio ZAP {n}', 'cpf': f'{70000000000 + n}',
            'sexo': 'Outro', 'dataNasc': '1995-05-20', 'endereco': 'Rua Ficticia 123'}


def main():
    policy = json.loads(Path('/config/dast-policy.json').read_text())
    with (OUT / 'zap-daemon.log').open('w') as log:
        daemon = subprocess.Popen(['/zap/zap.sh', '-daemon', '-host', '127.0.0.1', '-port', '8090',
                                   '-dir', '/tmp/zap-acme', '-config', 'api.disablekey=true',
                                   '-config', 'start.checkForUpdates=false', '-config', 'callhome.tel.enabled=false',
                                   '-config', 'start.installAddonUpdates=false',
                                   '-config', 'start.checkAddonUpdates=false', '-config', 'connection.timeoutInSecs=5'], stdout=log, stderr=subprocess.STDOUT)
        try:
            def ready():
                if daemon.poll() is not None:
                    raise RuntimeError('ZAP daemon terminated during startup')
                try:
                    return http.get(API + '/JSON/core/view/version/', timeout=2).status_code == 200
                except requests.RequestException:
                    return False
            wait(ready, 120, 'ZAP API')
            coverage['zap_version'] = api('core', 'view', 'version')['version']
            save('addons.json', api('autoupdate', 'view', 'installedAddons'))
            # Application access goes THROUGH ZAP, including observable CRUD assertions.
            health = request('GET', '/health', operation='GET /health').json()
            assert health == {'status': 'ok'}, 'Database health not confirmed'
            html = request('GET', '/').text
            assert 'id="app"' in html, 'React root missing'
            assets = sorted(set(re.findall(r'(?:src|href)="(/build/[^"?]+)', html)))
            assert len(assets) >= 3, 'Compiled assets missing'
            for asset in assets:
                assert request('GET', asset).content, 'Empty frontend asset'
            coverage['frontend_assets'] = assets
            p = request('POST', '/api/create', form(1), 201, 'POST /api/create').json()
            patient_id = p['id']
            found = request('GET', f'/api/show/{patient_id}', operation='GET /api/show/{id}').json()
            assert found == p, 'Readback failed'
            assert any(x['id'] == patient_id for x in request('GET', '/api/', operation='GET /api/').json())
            changed = form(1); changed['nome'] = 'Paciente Ficticio ZAP Editado'
            request('POST', f'/api/edit/{patient_id}', changed, operation='POST /api/edit/{id}')
            assert request('GET', f'/api/show/{patient_id}').json()['nome'] == changed['nome']
            matches = request('POST', '/api/searchName/', {'input': changed['nome']}, operation='POST /api/searchName/').json()
            assert any(x['id'] == patient_id for x in matches), 'Search failed'
            assert request('GET', '/api/validyCPF/' + form(1)['cpf'], operation='GET /api/validyCPF/{cpf}').json() is False
            assert request('POST', f'/api/changeStatus/{patient_id}', operation='POST /api/changeStatus/{id}').json()['status'] is False
            request('DELETE', f'/api/delete/{patient_id}', operation='DELETE /api/delete/{id}')
            request('GET', f'/api/show/{patient_id}', expected=404)
            request('POST', '/api/create', {'nome': ''}, expected=422)
            history = api('core', 'view', 'messages', baseurl=TARGET, start=0, count=1000)['messages']
            save('preflight-http.json', [{'id': m['id'], 'request': m['requestHeader'], 'response': m['responseHeader']} for m in history])
            # Fresh, distinct records survive the preflight DELETE. They seed OpenAPI path/body examples.
            fixtures = {name: request('POST', '/api/create', form(n), 201).json()
                        for n, name in enumerate(['consulta', 'edicao', 'exclusao'], 10)}
            save('fixtures.json', fixtures)
            spec = json.loads(Path('/config/openapi.json').read_text())
            spec['servers'] = [{'url': TARGET}]
            for path, purpose in [('/api/show/{id}', 'consulta'), ('/api/edit/{id}', 'edicao'),
                                  ('/api/changeStatus/{id}', 'edicao'), ('/api/delete/{id}', 'exclusao')]:
                for op in spec['paths'][path].values():
                    for param in op.get('parameters', []):
                        if param['name'] == 'id':
                            param['example'] = fixtures[purpose]['id']
            spec['paths']['/api/validyCPF/{cpf}']['get']['parameters'][0]['example'] = fixtures['consulta']['cpf']
            # Resolve request-body refs so edit keeps its OWN CPF, create uses a fresh one.
            for path, values in [('/api/create', form(20)), ('/api/edit/{id}', form(11))]:
                content = spec['paths'][path]['post']['requestBody']['content']
                for media in content.values():
                    schema = json.loads(json.dumps(spec['components']['schemas']['PatientForm']))
                    for name, value in values.items():
                        schema['properties'][name]['example'] = value
                    media['schema'] = schema
            save('openapi-seeded.json', spec)
            context = api('context', 'action', 'newContext', contextName='acme')['contextId']
            api('context', 'action', 'includeInContext', contextName='acme', regex=r'http://app:8080/.*')
            imported = api('openapi', 'action', 'importFile', file='/out/openapi-seeded.json', target=TARGET, contextId=context)
            save('openapi-import.json', imported)
            if imported != {'importFile': []}:
                raise RuntimeError(f'OpenAPI import did not succeed: {imported}')
            # Explicit bounded rule set: reflected XSS, SQL injection and CRLF injection.
            api('ascan', 'action', 'disableAllScanners')
            ids = ','.join(map(str, policy['active_rule_ids']))
            api('ascan', 'action', 'enableScanners', ids=ids)
            for rule in policy['active_rule_ids']:
                api('ascan', 'action', 'setScannerAttackStrength', id=rule, attackStrength=policy['attack_strength'])
                api('ascan', 'action', 'setScannerAlertThreshold', id=rule, alertThreshold=policy['alert_threshold'])
            coverage['active_scanners'] = api('ascan', 'view', 'scanners')['scanners']
            coverage['passive_scanners'] = api('pscan', 'view', 'scanners')['scanners']
            api('ascan', 'action', 'setOptionThreadPerHost', Integer=2)
            scan_id = api('ascan', 'action', 'scan', url=TARGET + '/', recurse='true', inScopeOnly='true', contextId=context)['scan']
            coverage['scan_id'] = scan_id
            wait(lambda: api('ascan', 'view', 'status', scanId=scan_id)['status'] == '100', 600, 'active scan completion')
            coverage['active_status'] = api('ascan', 'view', 'status', scanId=scan_id)['status']
            coverage['scan_progress'] = api('ascan', 'view', 'scanProgress', scanId=scan_id)
            wait(lambda: api('pscan', 'view', 'recordsToScan')['recordsToScan'] == '0', 180, 'passive scan queue')
            coverage['passive_remaining'] = int(api('pscan', 'view', 'recordsToScan')['recordsToScan'])
            message_ids = api('ascan', 'view', 'messagesIds', scanId=scan_id)['messagesIds']
            for message_id in message_ids:
                m = api('core', 'view', 'message', id=message_id)['message']
                line = m['requestHeader'].splitlines()[0].split(' ')
                status = m['responseHeader'].splitlines()[0].split(' ')[1] if m['responseHeader'] else '0'
                coverage['active_messages'].append({'id': str(message_id), 'method': line[0],
                                                    'path': urlsplit(line[1]).path, 'status': int(status)})
            alerts = api('core', 'view', 'alerts', baseurl=TARGET, start=0, count=10000)['alerts']
            count = int(api('core', 'view', 'numberOfAlerts', baseurl=TARGET)['numberOfAlerts'])
            assert len(alerts) == count, 'Truncated alert report'
            save('alerts.json', alerts)
            report = http.get(API + '/OTHER/core/other/htmlreport/', timeout=60)
            report.raise_for_status()
            (OUT / 'zap-report.html').write_bytes(report.content)
            coverage['completed'] = True
        finally:
            save('coverage.json', coverage)
            daemon.terminate()
            try:
                daemon.wait(timeout=20)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        traceback.print_exc()
        raise SystemExit(2)
