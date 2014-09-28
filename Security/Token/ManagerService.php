<?php
namespace AlyxGray\OathTokenBundle\Security\Token;

use Doctrine\ORM\EntityManager;
class ManagerService
{
    /**
     * Stores the Doctrine EntityManager for reuse
     * @var EntityManager
     */
    protected $entityManager;

    /**
     * @param EntityManager $entityManager
     */
    public function __construct (EntityManager $entityManager)
    {
        $this->entityManager = $entityManager;
    }
}

