<?php
$body = @file_get_contents('http://127.0.0.1:8080/health', false, stream_context_create(['http' => ['timeout' => 2]]));
exit($body && (json_decode($body, true)['status'] ?? '') === 'ok' ? 0 : 1);
