<?php
namespace App\Controller;

use Doctrine\DBAL\Connection;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;

class HealthController
{
    #[Route('/health', methods: ['GET'])]
    public function __invoke(Connection $db): JsonResponse
    {
        try {
            $db->executeQuery('SELECT id FROM paciente LIMIT 1');
            return new JsonResponse(['status' => 'ok']);
        } catch (\Throwable) {
            return new JsonResponse(['status' => 'unavailable'], 503);
        }
    }
}
