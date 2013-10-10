<?php
namespace AlyxGray\OATHTokenBundle;

class OathToken
{

    /**
     *
     * @var integer The secret was too small
     */
    const ERROR_INSUFFICIENT_SECRET_SIZE = 1;

    /**
     *
     * @var integer An invalid value was specified for the counter
     */
    const ERROR_INVALID_COUNTER_VALUE = 2;

    /**
     *
     * @var integer An invalid HMAC was specified
     */
    const ERROR_INVALID_HMAC = 3;

    /**
     *
     * @var integer The HOTP size was invalid
     */
    const ERROR_INVALID_HOTP_SIZE = 4;

    /**
     *
     * @var integer HMAC-SHA-1 (required by RFC 4226) produces a 160 bit value
     */
    const HMAC_SIZE = 20;

    /**
     *
     * @var integer Default character length for one time password, chosen to be more secure than minimum length
     */
    const HOTP_DEFAULT_SIZE = 8;

    /**
     *
     * @var integer Minimum character length for one time password, per RFC 4226
     */
    const HOTP_MINIMUM_SIZE = 6;

    /**
     *
     * @var integer Maximum character length for one time password, largest size supported with a 31 dynamic binary code
     */
    const HOTP_MAXIMUM_SIZE = 9;

    /**
     *
     * @var integer Minimum number of bits, per RFC 4226 standards
     */
    const SECRET_MINIMUM_BITS = 128;

    /**
     *
     * @var integer Recommended number of bits, per RFC 4226 standards
     */
    const SECRET_RECOMMENDED_BITS = 160;

    const TOKEN_EVENT_MODE = 1;

    const TOKEN_TIME_MODE = 2;

    /**
     *
     * @var integer Token counter
     */
    protected $counter = NULL;

    /**
     *
     * @var string Client/Server shared secret
     */
    protected $sharedSecret = NULL;

    /**
     *
     * @var integer One time password size
     */
    protected $hotpSize = self::HOTP_DEFAULT_SIZE;

    /**
     * Set token shared secret
     *
     * @param string $sharedSecret
     *            Token shared secret
     * @param boolean $ignoreRecommendedLength
     *            If true, use the minimum required secret length, rather than the recommended length
     * @throws InvalidArgumentException
     * @return OathToken
     */
    public function setSecret($sharedSecret, $ignoreRecommendedLength = FALSE)
    {
        // Ensure that the shared secret meets complexity requirements
        $minLength = $ignoreRecommendedLength ? OathToken::SECRET_MINIMUM_BITS / 8 : OathToken::SECRET_RECOMMENDED_BITS / 8;
        if (strlen($sharedSecret) < $minLength) {
            throw new InvalidArgumentException(sprintf('Secret provided contains %d bits, minimum permitted is %d.', strlen($sharedSecret) * 8, $minLength * 8), self::ERROR_INSUFFICIENT_SECRET_SIZE);
        }
        
        // Store the shared secret in the object
        $this->sharedSecret = $sharedSecret;
        
        // Permits method chaining
        return $this;
    }

    /**
     * Set the token counter
     *
     * @param integer $counter
     *            New counter value
     * @throws InvalidArgumentException
     * @return OathToken
     */
    public function setCounter($counter)
    {
        // Ensures the counter is valid
        if (! is_integer($counter) || $counter < 0) {
            throw new InvalidArgumentException('Invalid counter value specified', self::ERROR_INVALID_COUNTER_VALUE);
        }
        
        // Stores counter in the object
        $this->counter = $counter;
        
        // Permits method chaining
        return $this;
    }

    /**
     * Set the one time password size
     *
     * @param integer $hotpSize
     *            Size of one time password
     * @throws InvalidArgumentException
     * @return OathToken
     */
    public function setHotpSize($hotpSize)
    {
        // Ensures the OTP size is valid
        if (! is_numeric($hotpSize) || ($hotpSize < self::HOTP_MINIMUM_SIZE) || ($hotpSize > self::HOTP_MAXIMUM_SIZE)) {
            throw new InvalidArgumentException('Invalid one time password size', self::ERROR_INVALID_HOTP_SIZE);
        }
        
        // Stores the OTP in the object
        $this->hotpSize = $hotpSize;
        
        // Permits method chaining
        return $this;
    }

     
    
    /**
     * Calculates HMAC
     * @param string $key Secret key
     * @param string $value Counter or time to use for HOTP calculation
     * @return string
     */
    public static function getHMAC($key, $value)
    {
    	 return hash_hmac('sha1', $value, $key);       
    }

    /**
     * Truncate an HMAC to a HOTP of desired size
     *
     * @param string $hotp
     *            Binary representation of the hmac
     * @param integer $hotpSize
     *            Size of one time password
     * @throws InvalidArgumentException
     * @return string One time password
     */
    public static function truncateHMAC($hmac, $hotpSize)
    {
        // Verify the OTP Size is valid
        if (! is_numeric($hotpSize) || ($hotpSize < self::HOTP_MINIMUM_SIZE) || ($hotpSize > self::HOTP_MAXIMUM_SIZE)) {
            throw new InvalidArgumentException('Invalid one time password size', self::ERROR_INVALID_HOTP_SIZE);
        }
        
        // Verify the HMAC is valid
        if (! is_string($hmac) || (strlen($hmac) != self::HMAC_SIZE)) {
            throw new InvalidArgumentException('Invalid HMAC specified', self::ERROR_INVALID_HMAC);
        }
        
        // Calculates offset by taking the 'binary and' of the last character of the hmac
        $offset = ord($hmac[19]) & 0x0F;
        
        // Extracts 4 bytes from the HOTP starting at the offset
        $dynamicBinaryCode = unpack('N', substr($hmac, $offset, 4));
        
        // Truncates to 31 bits
        $dynamicBinaryCode = $dynamicBinaryCode & 0x7FFFFFFF;
        
        // Divide the DBC by 10 ^ [OTP size] and take the remainder
        // This will generate a HOTP of the desired size
        $hotp = $dynamicBinaryCode % pow(10, $hotpSize);
        
        // Formats HOTP to the desired size
        $format = '%0' . $hotpSize . 'f';
        return sprintf($format, $hotp);
    }
    
    
    
    /**
     * Calculates one-time password
     * @param string $key Secret key
     * @param string $value Counter or time to use for HOTP calculation
     * @param integer $hotpSize
     */
    public static function getHOTP ($key, $value, $hotpSize)
    {
    	$hmac = self::getHMAC($key, $value);
    	
    	return self::truncateHMAC($hmac, $hotpSize);
    }
    
    
    
}


