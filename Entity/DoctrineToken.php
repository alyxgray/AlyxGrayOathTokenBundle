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
     * @ORM\Column(name="counter", type="integer")
     * @var integer
     */
    protected $counter = NULL;

    /**
     * ID for token in database
     * @ORM\Id
     * @ORM\Column(name="id", type="integer")
     * @ORM\GeneratedValue(strategy="AUTO")
     * @var integer
     */
    protected $id;

    /**
     * Token mode (event or time)
     * @ORM\Column(name="mode", type="integer")
     * @var integer
     */
    protected $mode = NULL;

    /**
     * Client/Server shared secret
     * @ORM\Column(name="secret", type="string")
     * @var string
     */
    protected $sharedSecret = NULL;

    /**
     * One time password size
     * @ORM\Column(name="hotpsize", type="integer")
     * @var integer
     */
    protected $hotpSize = self::HOTP_DEFAULT_SIZE;

    /**
     * Optional manufacturer id for token
     * @ORM\Column(name="serial", type="string", length="64")
     * @var string
     */
    protected $serial = NULL;
}