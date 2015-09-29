<?php
/**
 * This file is part of the Alyx Gray OATH token bundle.
 *
 * (c) Alyx Gray <opensource@alyxgray.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AlyxGray\OathTokenBundle\Tests;

use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Configuration;

/**
 * Tests whether or not the token manager service properly loads
 */
class ServiceTest extends \PHPUnit_Framework_TestCase
{
    private $container;

    protected function setUp()
    {
        $kernel = new \AppKernel('test', true);
        $kernel->boot();

        $this->container = $kernel->getContainer();
    }

    public function testServiceIsDefinedInContainer()
    {
        $service = $this->container->get('alyx_gray.oath_token.manager');

        $this->assertInstanceOf('AlyxGray\OathTokenBundle\Security\Token\ManagerService', $service, 'Improper class used for oath token manager service.');
    }

    public function testSetEntityManager()
    {
        $service = $this->container->get('alyx_gray.oath_token.manager');

        // Minimal doctrine setup
        $connectionOptions = array(
            'driver' => 'pdo_sqlite',
            'path' => 'database.sqlite'
        );

        // Set up a new Doctrine configuration
        $configuration = new Configuration();
        $driverImpl = $configuration->newDefaultAnnotationDriver();

        // Configure the metadate implementation
        $configuration->setMetadataDriverImpl($driverImpl);
        $configuration->setProxyDir('Test/tmp/Proxies');
        $configuration->setProxyNamespace('AlyxGray\OathTokenBundle\Proxies');

        // Create the entity manager
        $entityManager = EntityManager::create($connectionOptions, $configuration);

        $service->setEntityManager($entityManager);
        $this->assertSame($entityManager, $service->getEntityManager(), 'Incorrect entity manager returned.');

        // Ensure null is handled correctly
        $service->setEntityManager(null);
        $this->assertNull($service->getEntityManager, 'Failed to clear entity manager.');;

    }
}
