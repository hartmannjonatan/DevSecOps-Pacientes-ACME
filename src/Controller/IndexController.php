<?php

namespace App\Controller;

use App\Entity\Paciente;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/api', name: 'api_')]
class IndexController extends AbstractController
{
    private function data(Paciente $p): array
    {
        return ['id' => $p->getId(), 'nome' => $p->getNome(),
            'dataNasc' => $p->getDataNascimento()->format('Y-m-d'),
            'cpf' => $p->getCPF(), 'sexo' => $p->getSexo(),
            'endereco' => $p->getEndereco(), 'status' => $p->isStatus()];
    }

    private function missing(): JsonResponse
    {
        return $this->json(['error' => 'Paciente não encontrado.'], 404);
    }

    #[Route('/', name: 'list', methods: ['GET'])]
    public function index(EntityManagerInterface $em): JsonResponse
    {
        return $this->json(array_map($this->data(...), $em->getRepository(Paciente::class)->findBy([], ['id' => 'ASC'])));
    }

    // Forms are the public contract used by React; JSON is deliberately rejected.
    private function save(Request $request, EntityManagerInterface $em, Paciente $p, bool $create): JsonResponse
    {
        if (!in_array($request->getContentTypeFormat(), ['form'], true)) {
            return $this->json(['error' => 'Envie campos de formulário (urlencoded ou multipart).'], 415);
        }
        $fields = $request->request->all();
        $errors = [];
        foreach (['nome' => 100, 'cpf' => 11, 'sexo' => 10, 'dataNasc' => 10, 'endereco' => 255] as $field => $max) {
            $value = $fields[$field] ?? '';
            if (!is_string($value) || mb_strlen(trim($value)) > $max || ($field !== 'endereco' && trim($value) === '')) {
                $errors[$field] = 'Campo obrigatório ou tamanho/formato inválido.';
            } else {
                $fields[$field] = trim($value);
            }
        }
        if ($errors) return $this->json(['errors' => $errors], 422);
        $date = \DateTimeImmutable::createFromFormat('!Y-m-d', $fields['dataNasc']);
        if (!$date || $date->format('Y-m-d') !== $fields['dataNasc'] || $date < new \DateTime('1000-01-01') || $date > new \DateTime('today')) {
            $errors['dataNasc'] = 'Use uma data entre 1000-01-01 e hoje, no formato AAAA-MM-DD.';
        }
        if (!preg_match('/^[0-9]{11}$/D', $fields['cpf'])) $errors['cpf'] = 'Use 11 dígitos.';
        if (!in_array($fields['sexo'], ['Masculino', 'Feminino', 'Outro'], true)) $errors['sexo'] = 'Valor inválido.';
        if ($errors) return $this->json(['errors' => $errors], 422);
        $existing = $em->getRepository(Paciente::class)->findOneBy(['CPF' => $fields['cpf']]);
        if ($existing && $existing->getId() !== $p->getId()) return $this->json(['error' => 'CPF já cadastrado.'], 409);
        $p->setNome($fields['nome'])->setCPF($fields['cpf'])->setSexo($fields['sexo'])
            ->setDataNascimento($date)->setEndereco($fields['endereco'] ?: null);
        try {
            $em->persist($p);
            $em->flush();
        } catch (UniqueConstraintViolationException) {
            return $this->json(['error' => 'CPF já cadastrado.'], 409);
        }
        return $this->json($this->data($p), $create ? 201 : 200);
    }

    #[Route('/create', name: 'create', methods: ['POST'])]
    public function create(Request $request, EntityManagerInterface $em): JsonResponse
    {
        return $this->save($request, $em, new Paciente(), true);
    }

    #[Route('/edit/{id}', name: 'edit', requirements: ['id' => '\d+'], methods: ['POST'])]
    public function edit(Request $request, EntityManagerInterface $em, int $id): JsonResponse
    {
        $p = $em->find(Paciente::class, $id);
        return $p ? $this->save($request, $em, $p, false) : $this->missing();
    }

    #[Route('/show/{id}', name: 'show', requirements: ['id' => '\d+'], methods: ['GET'])]
    public function show(EntityManagerInterface $em, int $id): JsonResponse
    {
        $p = $em->find(Paciente::class, $id);
        return $p ? $this->json($this->data($p)) : $this->missing();
    }

    #[Route('/delete/{id}', name: 'delete', requirements: ['id' => '\d+'], methods: ['DELETE'])]
    public function delete(EntityManagerInterface $em, int $id): JsonResponse
    {
        $p = $em->find(Paciente::class, $id);
        if (!$p) return $this->missing();
        $em->remove($p);
        $em->flush();
        return $this->json(['message' => 'Paciente excluído.']);
    }

    #[Route('/changeStatus/{id}', name: 'changeStatus', requirements: ['id' => '\d+'], methods: ['POST'])]
    public function changeStatus(EntityManagerInterface $em, int $id): JsonResponse
    {
        $p = $em->find(Paciente::class, $id);
        if (!$p) return $this->missing();
        $p->setStatus(!$p->isStatus());
        $em->flush();
        return $this->json($this->data($p));
    }

    #[Route('/validyCPF/{cpf}', name: 'validyCPF', methods: ['GET'])]
    public function validyCPF(EntityManagerInterface $em, string $cpf): JsonResponse
    {
        if (!preg_match('/^[0-9]{11}$/D', $cpf)) return $this->json(['error' => 'Use 11 dígitos.'], 422);
        // Availability only; does not validate Brazilian CPF check digits.
        return $this->json(!$em->getRepository(Paciente::class)->findOneBy(['CPF' => $cpf]));
    }

    #[Route('/searchName/', name: 'searchName', methods: ['POST'])]
    public function searchName(Request $request, EntityManagerInterface $em): JsonResponse
    {
        if ($request->getContentTypeFormat() !== 'form') return $this->json(['error' => 'Envie campos de formulário.'], 415);
        $input = $request->request->all()['input'] ?? null;
        if (!is_string($input) || mb_strlen($input) > 100) return $this->json(['errors' => ['input' => 'Informe até 100 caracteres.']], 422);
        $patients = $em->getRepository(Paciente::class)->findByNome(trim($input));
        return $this->json(array_map($this->data(...), $patients));
    }
}
