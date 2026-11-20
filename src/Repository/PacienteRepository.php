<?php
namespace App\Repository;

use App\Entity\Paciente;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/** @extends ServiceEntityRepository<Paciente> */
class PacienteRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Paciente::class);
    }

    /** @return Paciente[] */
    public function findByNome(string $input): array
    {
        return $this->createQueryBuilder('p')->where('p.Nome LIKE :name')
            ->setParameter('name', '%'.$input.'%')->orderBy('p.id', 'ASC')->getQuery()->getResult();
    }
}
