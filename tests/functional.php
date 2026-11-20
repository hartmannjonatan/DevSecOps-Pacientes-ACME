<?php
// Real HTTP contract tests, executed inside the app container, no test framework required.
declare(strict_types=1);

$base = 'http://127.0.0.1:8080';
$mode = $argv[1] ?? 'test';
if (!str_contains(getenv('DATABASE_URL') ?: '', '/acme_test?')) {
    fwrite(STDERR, "Refusing to mutate a database other than the disposable acme_test.\n");
    exit(2);
}
function check(bool $condition, string $message): void {
    if (!$condition) throw new RuntimeException($message);
}
function request(string $method, string $path, ?array $form = null, int $expected = 200, bool $json = true): mixed {
    global $base;
    $options = ['method' => $method, 'ignore_errors' => true, 'timeout' => 10];
    if ($form !== null) {
        $options['header'] = 'Content-Type: application/x-www-form-urlencoded';
        $options['content'] = http_build_query($form);
    }
    $body = file_get_contents($base.$path, false, stream_context_create(['http' => $options]));
    preg_match('/\s(\d{3})\s/', $http_response_header[0] ?? '', $matches);
    check((int) ($matches[1] ?? 0) === $expected, "$method $path: expected $expected, got ".($http_response_header[0] ?? 'no response')."; $body");
    return $json ? json_decode($body, true, 512, JSON_THROW_ON_ERROR) : $body;
}
function fixture(string $name = 'Paciente Fictício CI'): array {
    return ['nome' => $name, 'cpf' => (string) random_int(10000000000, 99999999999), 'sexo' => 'Outro', 'dataNasc' => '1995-05-20', 'endereco' => 'Rua de Teste, 123'];
}
$cleanup = [];
$exitCode = 0;
try {
    check(request('GET', '/health')['status'] === 'ok', 'health');
    $stateFile = dirname(__DIR__).'/var/test-persistence.json';
    if ($mode === 'persistence-create') {
        check(!file_exists($stateFile), 'Pending persistence fixture exists; verify it before creating another.');
        $p = request('POST', '/api/create', fixture('Persistência Fictícia CI'), 201);
        file_put_contents($stateFile, json_encode($p, JSON_THROW_ON_ERROR));
        echo "Persistence fixture created: {$p['id']}\n";
    } elseif ($mode === 'persistence-verify') {
        $p = json_decode(file_get_contents($stateFile), true, 512, JSON_THROW_ON_ERROR);
        check(request('GET', '/api/show/'.$p['id']) === $p, 'Record changed/lost after container restart');
        request('DELETE', '/api/delete/'.$p['id']);
        unlink($stateFile);
        echo "PASS: persistence after stopping/starting app and MySQL\n";
    } elseif ($mode === 'seed') {
        $fixtures = [];
        foreach (['consulta', 'edicao', 'exclusao'] as $purpose) {
            $fixtures[$purpose] = request('POST', '/api/create', fixture('DAST Fictício '.$purpose), 201);
        }
        echo json_encode($fixtures, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)."\n";
    } elseif ($mode === 'test') {
        $html = request('GET', '/', expected: 200, json: false);
        check(str_contains($html, 'id="app"'), 'Missing React root');
        preg_match_all('~(?:src|href)="(/build/[^"?]+)"~', $html, $matches);
        check(count($matches[1]) >= 3, 'Missing compiled CSS/JS assets');
        foreach ($matches[1] as $asset) check(strlen(request('GET', $asset, json: false)) > 0, 'Empty asset');
        foreach (['/create', '/edit/1'] as $page) check(str_contains(request('GET', $page, json: false), 'id="app"'), 'SPA deep link');
        $input = fixture();
        check(request('GET', '/api/validyCPF/'.$input['cpf']) === true, 'CPF availability');
        $p = request('POST', '/api/create', $input, 201);
        check(is_int($p['id']), 'Create must return usable ID');
        $id = $p['id']; $cleanup[] = $id;
        check(request('GET', '/api/show/'.$id) === $p, 'Readback differs');
        check(in_array($id, array_column(request('GET', '/api/'), 'id'), true), 'List missing record');
        check(request('GET', '/api/validyCPF/'.$input['cpf']) === false, 'Duplicate CPF availability');
        request('POST', '/api/create', $input, 409);
        $input['nome'] = 'Paciente Fictício Editado '.random_int(1000, 9999);
        request('POST', '/api/edit/'.$id, $input);
        check(request('GET', '/api/show/'.$id)['nome'] === $input['nome'], 'Edit not persisted');
        $results = request('POST', '/api/searchName/', ['input' => $input['nome']]);
        check(count($results) === 1 && $results[0]['id'] === $id && $results[0]['dataNasc'] === $input['dataNasc'], 'Search contract');
        check(request('POST', '/api/searchName/', ['input' => 'NoSuchPatient-'.bin2hex(random_bytes(8))]) === [], 'Empty search');
        request('POST', '/api/create', ['nome' => ''], 422);
        $bad = $input; $bad['dataNasc'] = '2023-02-30';
        request('POST', '/api/edit/'.$id, $bad, 422);
        $bad['dataNasc'] = '0004-01-01';
        request('POST', '/api/edit/'.$id, $bad, 422);
        check(request('GET', '/api/show/'.$id)['dataNasc'] === $input['dataNasc'], 'Invalid edit changed DB');
        request('POST', '/api/create', ['nome' => ['unexpected']], 422);
        request('GET', '/api/show/2147483647', expected: 404);
        request('POST', '/api/edit/2147483647', $input, 404);
        request('DELETE', '/api/delete/2147483647', expected: 404);
        request('GET', '/api/changeStatus/'.$id, expected: 405, json: false);
        check(request('POST', '/api/changeStatus/'.$id)['status'] === false, 'Deactivate');
        check(request('GET', '/api/show/'.$id)['status'] === false, 'Status not persisted');
        request('DELETE', '/api/delete/'.$id);
        $cleanup = [];
        request('GET', '/api/show/'.$id, expected: 404);
        echo "PASS: HTML/assets, SPA routes, create/read/list/edit/search/status/delete, invalid input, duplicates and missing records\n";
    } else {
        throw new RuntimeException('Unknown test mode');
    }
} catch (Throwable $error) {
    fwrite(STDERR, "FAIL: {$error->getMessage()}\n");
    $exitCode = 1;
} finally {
    foreach ($cleanup as $id) {
        try { request('DELETE', '/api/delete/'.$id); } catch (Throwable) { /* Original failure stays visible. */ }
    }
}

exit($exitCode);
