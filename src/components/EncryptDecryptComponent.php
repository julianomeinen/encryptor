<?php

namespace  Juliano\Yii2EncryptorBehavior\components;

use Juliano\Yii2EncryptorBehavior\classes\AWSEncryptDecrypt;
use Juliano\Yii2EncryptorBehavior\classes\EncryptDecrypt;
use yii\base\Component;

/**
 * Class used to encrypt/decrypt values.
 */
class EncryptDecryptComponent extends Component
{

    /**
     * @var $key The key to encrypt/decrypt.
     */
    public $key;

    /**
     * @var $awsHashKey The hash key from AWS.
     */
    public $awsHashKey;

     /**
     * @var $s3Bucket The AWS S3 default bucket.
     */
    public $s3Bucket;


    /**
     * Encrypts the value.
     *
     * @param mixed   $value        The value to be encrypted.
     * @param boolean $base64Encode Base64 encoding? Default is true.
     *
     * @return string
     */
    public static function encrypt(mixed $value, bool $base64Encode = true): string
    {
        $encryptedData = (new EncryptDecrypt)->encrypt($value, self::getKey());
        return $base64Encode === true ? base64_encode($encryptedData) : $encryptedData;

    }


    /**
     * Decrypts the value.
     *
     * @param mixed   $value        The value to be decrypted.
     * @param boolean $base64Decode Base64 decoding? Default is true.
     *
     * @return mixed
     */
    public static function decrypt(mixed $value, bool $base64Decode = true): mixed
    {
        return (new EncryptDecrypt)->decrypt(
            ($base64Decode === true ? base64_decode($value) : $value),
            self::getKey()
        );

    }


    /**
     * Returns the secret key from the main config.
     *
     * @return mixed
     */
    public static function getKey(): mixed
    {
        $key = \Yii::$app->components['encryptor']['key'];

        if (substr($key, -17) === 'AWSEncryptDecrypt') {
            return AWSEncryptDecrypt::getKey(\Yii::$app->components['encryptor']['awsHashKey']);
        } else {
            return $key;
        }

    }


}
