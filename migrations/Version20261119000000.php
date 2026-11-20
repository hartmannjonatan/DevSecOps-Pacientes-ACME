<?php

declare(strict_types=1);
namespace DoctrineMigrations;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

final class Version20261119000000 extends AbstractMigration
{
    public function getDescription(): string { return 'Prevent duplicate CPF, including concurrent requests'; }
    public function isTransactional(): bool { return false; }
    public function up(Schema $schema): void
    {
        $duplicates = $this->connection->fetchOne('SELECT COUNT(*) FROM (SELECT cpf FROM paciente GROUP BY cpf HAVING COUNT(*) > 1) d');
        $this->abortIf((int) $duplicates > 0, 'Existing duplicate CPFs: review them manually; no records were removed.');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_CPF ON paciente (cpf)');
    }
    public function down(Schema $schema): void { $this->addSql('DROP INDEX UNIQ_CPF ON paciente'); }
}
