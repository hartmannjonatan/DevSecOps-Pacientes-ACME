<?php

declare(strict_types=1);
namespace DoctrineMigrations;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

// Historical duplicate of Version20221222030023; retained for existing histories.
final class Version20221226221206 extends AbstractMigration
{
    public function getDescription(): string { return 'Historical duplicate; no schema changes'; }
    public function up(Schema $schema): void {}
    public function down(Schema $schema): void {}
}
