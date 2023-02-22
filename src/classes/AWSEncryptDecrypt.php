<?php

namespace Juliano\Yii2EncryptorBehavior\classes;

use Aws\Kms\KmsClient;
use Exception;

/**
 * Class to encrypt/decrypt data with AWS KMS Key.
 */
class AWSEncryptDecrypt
{


    /**
     * Encrypt method.
     *
     * @param mixed $data  The data to encrypt.
     * @param mixed $KeyId The encryption KeyId.
     *
     * @return string Encrypted data.
     */
    public function encrypt(mixed $data, mixed $KeyId = null): string
    {
        $keyData = $this->getKmsClient()->describeKey(
            ['KeyId' => $KeyId]
        );

        $result = $this->getKmsClient()->encrypt(
            [
                'KeyId'     => $keyData['KeyMetadata']['Arn'],
                'Plaintext' => $data,
            ]
        );

        return $result['CiphertextBlob'];

    }


    /**
     * Decrypt method.
     *
     * @param mixed $data The ecrypted data to decrypt.
     *
     * @return false|string
     *
     * @throws Exception
     */
    public function decrypt($data): false|string
    {
        $result = $this->getKmsClient()->decrypt(
            ['CiphertextBlob' => $data]
        );

        if ($result instanceof \Aws\Result === false) {
            throw new Exception('Invalid AWS Decrypt Key.');
        }

        return $result['Plaintext'];

    }


    /**
     * Returns the AWS hash to be decrypted to get the real key.
     *
     * @param mixed   $hash         The ecrypted key hash to to be decrypted.
     * @param boolean $base64Decode Decode Decode with base64.
     *
     * @return mixed
     */
    public static function getKey(mixed $hash, $base64Decode = true): mixed
    {
        return (new AWSEncryptDecrypt)->decrypt($base64Decode === true ? base64_decode($hash) : $hash);

    }


    /**
     * Returns the KmsClient class to call the API.
     *
     * @return KmsClient
     */
    private function getKmsClient(): KmsClient
    {
        return new KmsClient(
            [
                'profile'     => 'default',
                'version'     => 'latest',
                'region'      => 'ca-central-1',
                'credentials' => false,
            ]
        );

    }


}
