<?php
/**
 * This file is part of the Alyx Gray OATH token bundle.
 *
 * (c) Alyx Gray <opensource@alyxgray.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AlyxGray\OathTokenBundle\Entity;

use AlyxGray\OathTokenBundle\OathToken;
use Doctrine\ORM\Mapping as ORM;

/**
 * Doctrine storage of an OATH token
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
    protected $counter = null;

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
    protected $mode = null;

    /**
     * Client/Server shared secret
     * @ORM\Column(name="secret", type="string")
     * @var string
     */
    protected $sharedSecret = null;

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
    protected $serial = null;
}
