<?php

namespace Juliano\Yii2EncryptorBehavior\classes;

use Exception;

/**
 * Class to encrypt/decrypt data.
 */
class EncryptDecrypt
{

    /**
     * @var string Cypher.
     */
    public string $cipher = 'AES-128-CBC';

    /**
     * @var array Allowed Ciphers.
     */
    public array $allowedCiphers = [
        'AES-128-CBC' => [
            16,
            16,
        ],
        'AES-192-CBC' => [
            16,
            24,
        ],
        'AES-256-CBC' => [
            16,
            32,
        ],
    ];

    /**
     * @var string Type of algorithm.
     */
    public string $kdfHash = 'sha256';

    /**
     * @var string Info key.
     */
    public string $authKeyInfo = 'AuthorizationKey';

    /**
     * @var string Type of MAC algorithm.
     */
    public string $macHash = 'sha256';


    /**
     * Encrypt method.
     *
     * @param mixed $data   The data to encrypt.
     * @param mixed $secret The encryption secret.
     *
     * @return string Output: [keySalt][MAC][IV][ciphertext]
     * - keySalt is KEY_SIZE bytes long
     * - MAC: message authentication code, length same as the output of MAC_HASH
     * - IV: initialization vector, length $blockSize
     *
     * @throws Exception
     */
    public function encrypt($data, $secret): string
    {
        if (extension_loaded('openssl') === false) {
            throw new Exception('Encryption requires the OpenSSL PHP extension');
        }

        if (isset($this->allowedCiphers[$this->cipher][0], $this->allowedCiphers[$this->cipher][1]) === false) {
            throw new Exception($this->cipher.' is not an allowed cipher');
        }

        list($blockSize, $keySize) = $this->allowedCiphers[$this->cipher];

        $keySalt = $this->generateRandomKey($keySize);
        $key = $this->hkdf($this->kdfHash, $secret, $keySalt, '', $keySize);

        $iv = $this->generateRandomKey($blockSize);

        $encrypted = openssl_encrypt($data, $this->cipher, $key, OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            throw new Exception('OpenSSL failure on encryption: '.openssl_error_string());
        }

        $authKey = $this->hkdf($this->kdfHash, $key, null, $this->authKeyInfo, $keySize);
        $hashed = $this->hashData($iv.$encrypted, $authKey);

        return $keySalt.$hashed;

    }


    /**
     * Decrypt method.
     *
     * @param mixed $data   The ecrypted data to decrypt.
     * @param mixed $secret The encryption secret.
     *
     * @return false|string
     *
     * @throws Exception
     */
    public function decrypt($data, $secret)
    {
        $info = '';
        if (extension_loaded('openssl') === false) {
            throw new Exception('Encryption requires the OpenSSL PHP extension');
        }

        if (isset($this->allowedCiphers[$this->cipher][0], $this->allowedCiphers[$this->cipher][1]) === false) {
            throw new Exception($this->cipher.' is not an allowed cipher');
        }

        list($blockSize, $keySize) = $this->allowedCiphers[$this->cipher];

        $keySalt = static::byteSubstr($data, 0, $keySize);
        $key = $this->hkdf($this->kdfHash, $secret, $keySalt, $info, $keySize);

        $authKey = $this->hkdf($this->kdfHash, $key, null, $this->authKeyInfo, $keySize);
        $data = $this->validateData(static::byteSubstr($data, $keySize, null), $authKey);
        if ($data === false) {
            return false;
        }

        $iv = static::byteSubstr($data, 0, $blockSize);
        $encrypted = static::byteSubstr($data, $blockSize, null);

        $decrypted = openssl_decrypt($encrypted, $this->cipher, $key, OPENSSL_RAW_DATA, $iv);
        if ($decrypted === false) {
            throw new Exception('OpenSSL failure on decryption: '.openssl_error_string());
        }

        return $decrypted;

    }


    /**
     * Key generation method.
     *
     * @param string  $algo     Name of selected hashing algorithm.
     * @param mixed   $inputKey Input keying material (raw binary).
     * @param null    $salt     Salt to use during derivation.
     * @param string  $info     Application/context-specific info string.
     * @param integer $length   Desired output length in bytes.
     *
     * @return string
     */
    public function hkdf($algo, $inputKey, $salt = null, string $info = '', int $length = 0): string
    {
        return hash_hkdf((string) $algo, (string) $inputKey, $length, $info, (string) $salt);

    }


    /**
     * Method to generate random key.
     *
     * @param integer $length The length of the random string.
     *
     * @return boolean|string
     *
     * @throws Exception
     */
    public function generateRandomKey(int $length = 32)
    {
        if (is_int($length) === false) {
            throw new Exception('First parameter ($length) must be an integer');
        }

        if ($length < 1) {
            throw new Exception('First parameter ($length) must be greater than 0');
        }

        return random_bytes($length);

    }


    /**
     * Method to generate the hash.
     *
     * @param mixed   $data    Message to be hashed.
     * @param mixed   $key     The secret key.
     * @param boolean $rawHash
     *
     * @return string
     *
     * @throws Exception
     */
    public function hashData($data, $key, bool $rawHash = false): string
    {
        $hash = hash_hmac($this->macHash, $data, $key, $rawHash);
        if ($hash === false) {
            throw new Exception('Failed to generate HMAC with hash algorithm: '.$this->macHash);
        }

        return $hash.$data;

    }


    /**
     * Get part of string.
     *
     * @param string       $string The string being checked.
     * @param integer      $start  The first position used in str.
     * @param null|integer $length The maximum length of the returned string.
     *
     * @return string
     */
    public static function byteSubstr($string, $start, $length = null): string
    {
        if ($length === null) {
            $length = static::byteLength($string);
        }

        return mb_substr($string, $start, $length, '8bit');

    }


    /**
     * Get string length.
     *
     * @param mixed $string The byte|string being checked for length.
     *
     * @return false|integer
     */
    public static function byteLength($string)
    {
        return mb_strlen((string) $string, '8bit');

    }


    /**
     * Method to validate the encrypted data.
     *
     * @param mixed   $data    The data to be validated.
     * @param mixed   $key     The kye secret.
     * @param boolean $rawHash When set to TRUE, outputs raw binary data, FALSE outputs lowercase hexits.
     *
     * @return false|string
     *
     * @throws Exception
     */
    public function validateData($data, $key, bool $rawHash = false)
    {
        $test = @hash_hmac($this->macHash, '', '', $rawHash);
        if ($test === false) {
            throw new Exception('Failed to generate HMAC with hash algorithm: '.$this->macHash);
        }

        $hashLength = static::byteLength($test);
        if (static::byteLength($data) >= $hashLength) {
            $hash = static::byteSubstr($data, 0, $hashLength);
            $pureData = static::byteSubstr($data, $hashLength, null);

            $calculatedHash = hash_hmac($this->macHash, $pureData, $key, $rawHash);

            if ($this->compareString($hash, $calculatedHash) === true) {
                return $pureData;
            }
        }

        return false;

    }


    /**
     * Method to compare two strings.
     *
     * @param string $expected Expected value.
     * @param string $actual   Actual value.
     *
     * @return boolean
     *
     * @throws Exception
     */
    public function compareString($expected, $actual): bool
    {
        if (is_string($expected) === false) {
            throw new Exception('Expected expected value to be a string, '.gettype($expected).' given.');
        }

        if (is_string($actual) === false) {
            throw new Exception('Expected actual value to be a string, '.gettype($actual).' given.');
        }

        if (function_exists('hash_equals') === true) {
            return hash_equals($expected, $actual);
        }

        $expected .= "\0";
        $actual .= "\0";
        $expectedLength = static::byteLength($expected);
        $actualLength = static::byteLength($actual);
        $diff = ($expectedLength - $actualLength);
        for ($i = 0; $i < $actualLength; $i++) {
            $diff |= (ord($actual[$i]) ^ ord($expected[($i % $expectedLength)]));
        }

        return $diff === 0;

    }


}
