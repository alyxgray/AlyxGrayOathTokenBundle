<?php
namespace AlyxGray\OathTokenBundle\Security\Token;

use Doctrine\ORM\EntityManager;
use AlyxGray\OathTokenBundle\Entity\DoctrineToken;

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

    /**
     * Instantiates a new token and persists it to the database
     * Returns the token object and the secret as an associative array with two keys
     *
     * @return array
     */
    public function createSoftwareToken () {

        // Create a new token object
        $oathToken = new DoctrineToken();

        // Initialize the token by generating a new secret
        $newSecret = $oathToken->generateSecret();

        // Persist the token using the entity manager
        $entityManager = $this->entityManager;
        $entityManager->persist($oathToken);

        // Flush the entity manager so the token is saved to the database
        $entityManager->flush($oathToken);

        return array (
            'token' => $oathToken,
            'secret' => $newSecret
        );
    }
}

