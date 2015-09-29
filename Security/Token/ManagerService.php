<?php
/**
 * This file is part of the Alyx Gray OATH token bundle.
 *
 * (c) Alyx Gray <opensource@alyxgray.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AlyxGray\OathTokenBundle\Security\Token;

use Doctrine\ORM\EntityManager;
use AlyxGray\OathTokenBundle\Entity\DoctrineToken;

/**
 * Token management service
 */
class ManagerService
{
    /**
     * Stores the Doctrine EntityManager for reuse
     * @var EntityManager
     */
    protected $entityManager;

    /**
     * Get the current entity manager
     * @todo Factor this into an interface
     * @return \Doctrine\ORM\EntityManager
     */
    public function getEntityManager() {
        return $this->entityManager;
    }

    /**
     * Set the current entity manager
     * @param EntityManager $entityManager
     */
    public function setEntityManager($entityManager = null)
    {
        if ($entityManager != null) {
            if ($entityManager instanceof EntityManager) {
                $this->entityManager = $entityManager;
            } else {
                throw new \InvalidArgumentException('Argument to setEntityManager must be an instance of Doctrine\ORM\EntityManager');
            }
        }
    }

    /**
     * Instantiates a new token and persists it to the database
     * Returns the token object and the secret as an associative array with two keys
     *
     * @return array
     */
    public function createSoftwareToken()
    {

        // Create a new token object
        $oathToken = new DoctrineToken();

        // Generate a new secret
        $newSecret = $oathToken->generateSecret();

        // Initialize the token using generated secret
        $oathToken->setSecret($newSecret);

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
