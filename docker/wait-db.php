<?php
require dirname(__DIR__).'/vendor/autoload.php';
(new Symfony\Component\Dotenv\Dotenv())->bootEnv(dirname(__DIR__).'/.env');
$deadline = microtime(true) + 90;
do {
    try {
        $params = (new Doctrine\DBAL\Tools\DsnParser(['mysql' => 'pdo_mysql']))->parse($_ENV['DATABASE_URL'] ?? getenv('DATABASE_URL'));
        $db = Doctrine\DBAL\DriverManager::getConnection($params);
        $db->executeQuery('SELECT 1');
        exit(0);
    } catch (Throwable $e) {
        if (microtime(true) >= $deadline) {
            fwrite(STDERR, "Database did not become ready within 90 seconds. Check db logs and credentials.\n");
            exit(1);
        }
        usleep(500000);
    }
} while (true);
