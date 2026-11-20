<?php
// Replace placeholder IDs with actual disposable fixtures for a later ZAP import.
$fixtures = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$spec = json_decode(file_get_contents(dirname(__DIR__).'/docs/openapi.json'), true, 512, JSON_THROW_ON_ERROR);
foreach (['show' => 'consulta', 'edit' => 'edicao', 'changeStatus' => 'edicao', 'delete' => 'exclusao'] as $operation => $purpose) {
    foreach ($spec['paths']['/api/'.$operation.'/{id}'] as &$definition) {
        $definition['parameters'][0]['example'] = $fixtures[$purpose]['id'];
    }
    unset($definition);
}
$spec['paths']['/api/validyCPF/{cpf}']['get']['parameters'][0]['example'] = $fixtures['consulta']['cpf'];
echo json_encode($spec, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)."\n";
