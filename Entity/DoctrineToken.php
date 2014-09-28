<?php
namespace AlyxGray\OathTokenBundle\Entity;

use AlyxGray\OathTokenBundle\OathToken;
use Doctrine\ORM\Mapping AS ORM;

/**
 * @ORM\Entity
 * @ORM\Table(name="ag_token")
 */
class DoctrineToken extends OathToken
{
    /**
     * Token counter
     *
     * @var integer
     */
    protected $counter = NULL;

    /**
     * @ORM\Id
     * @ORM\Column(name="id", type="integer")
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    protected $id;

    /**
     * Token mode (event or time)
     *
     * @var integer
     */
    protected $mode = NULL;

    /**
     * Client/Server shared secret
     *
     * @var string
     */
    protected $sharedSecret = NULL;

    /**
     * One time password size
     *
     * @var integer
     */
    protected $hotpSize = self::HOTP_DEFAULT_SIZE;

    /**
     * Optional manufacturer id for token
     * @ORM\serial
     * @ORM\Column(name="serial", type="string", length="64")
     * @ORM\GeneratedValue(strategy="AUTO")
     * @var string
     */
    protected $serial = NULL;
}