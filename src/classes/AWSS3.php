<?php

namespace Juliano\Yii2EncryptorBehavior\classes;

use Aws\S3\S3Client;
use Juliano\Yii2encryptorbehavior\components\EncryptDecryptComponent;
use Exception;
use Iterator;
use GuzzleHttp\Psr7;

/**
 * Class to upload/download files from AWS S3.
 */
class AWSS3
{

    /**
     * @var $bucket S3 bucket.
     */
    public string $bucket;


    /**
     * Class construnctor.
     *
     * @param string|null $bucket The S3 bucket name.
     *
     * @return void
     */
    public function __construct(string $bucket = null)
    {
        $this->bucket = ($bucket ?? \Yii::$app->components['encryptor']['s3Bucket']);

    }


    /**
     * Return the list of S3 buckets.
     *
     * @return \Aws\Result Buckets.
     */
    public function listBuckets(): \Aws\Result
    {
        return $this->getS3Client()->listBuckets();

    }


    /**
     * Return the list of files in the bucket.
     *
     * @param string|null $bucket The S3 bucket name.
     *
     * @return Iterator Object files.
     */
    public function listFilesInBucket(string $bucket = null): Iterator
    {
        return $this->getS3Client()->getIterator(
            'ListObjects',
            ['Bucket' => ($bucket ?? $this->bucket)]
        );

    }


    /**
     * Return the file data from the bucket.
     *
     * @param string      $key    The file key.
     * @param string|null $bucket The S3 bucket name.
     *
     * @return \Aws\Result File data.
     */
    public function getFile(string $key, string $bucket = null): \Aws\Result
    {
        return $this->getS3Client()->getObject(
            [
                'Bucket' => ($bucket ?? $this->bucket),
                'Key'    => $key,
            ]
        );

    }


    /**
     * Copy the file from AWS S3 and save it in a directory.
     *
     * @param string      $key                  The file key.
     * @param string      $destinationDirectory The destination directory to save the copied file..
     * @param string|null $bucket               The S3 bucket name.
     *
     * @return boolean Return whether the file was copied or not.
     */
    public function copyFileFromAWS(string $key, string $destinationDirectory, string $bucket = null): bool
    {
        $file = $this->getFile($key, $bucket);

        if (substr($destinationDirectory, -1) !== '/') {
            $destinationDirectory .= '/';
        }

        return file_put_contents($destinationDirectory.$key, $file['Body']) === false ? false : true;

    }


    /**
     * Download the file from AWS S3 and save it in a directory.
     *
     * @param string      $key                  The file key.
     * @param string      $destinationDirectory The destination directory to save the copied file..
     * @param string|null $bucket               The S3 bucket name.
     *
     * @return boolean Return whether the file was saved or not.
     * @throws Exception Unable to read the file in the AWS S3 bucket.
     */
    public function downloadDecrypted(string $key, string $destinationDirectory, string $bucket = null): bool
    {
        $bucket = ($bucket ?? $this->bucket);
        $file = $this->getFile($key, $bucket);
        if ($file instanceof \Aws\Result === false) {
            return throw new Exception("Unable to find the file $key in the AWS S3 bucket $bucket.");
        }

        $decryptedData = (new EncryptDecryptComponent)->decrypt($file['Body'], false);
        return file_put_contents($destinationDirectory, $decryptedData) === false ? false : true;

    }


     /**
      * Download the file from AWS S3 and save it in a directory.
      *
      * @param string      $key                  The file key.
      * @param string      $destinationDirectory The destination directory to save the copied file..
      * @param string|null $bucket               The S3 bucket name.
      *
      * @return boolean Return whether the file was saved or not.
      */
    public function download(string $key, string $destinationDirectory, string $bucket = null): bool
    {
        return $this->copyFileFromAWS($key, $destinationDirectory, $bucket);

    }


    /**
     * Return the data bytes of the file decrypted.
     *
     * @param string      $key    The file key.
     * @param string|null $bucket The S3 bucket name.
     *
     * @return \Aws\Result The AWS file decrypted.
     */
    public function getDecryptedFile(string $key, string $bucket = null): \Aws\Result
    {
        $fileBytes = $this->getFile($key, $bucket);
        $decryptedData = (new EncryptDecryptComponent)->decrypt($fileBytes['Body'], false);
        $fileBytes['Encrypted_Body'] = $fileBytes['Body'];
        $fileBytes['Body'] = Psr7\Utils::streamFor($decryptedData);
        return $fileBytes;

    }


    /**
     * Copy the file from a local directory and save it in AWS S3.
     *
     * @param string      $key    The file key.
     * @param mixed       $data   The destination directory or data bytes to be saved.
     * @param string|null $bucket The S3 bucket name.
     *
     * @throws Exception Unable to read the file.
     * @return false|\Aws\Result Return file data from AWS.
     */
    public function upload(string $key, mixed $data, string $bucket = null): false|\Aws\Result
    {
        if (is_file($data) === true) {
            $fileBytes = file_get_contents($data);
            if ($fileBytes !== false) {
                $data = $fileBytes;
            } else {
                return throw new Exception('Unable to read the file '.$data);
            }
        }

        return $this->getS3Client()->putObject(
            [
                'Bucket' => ($bucket ?? $this->bucket),
                'Key'    => $key,
                'Body'   => $data,
            ]
        );

    }


    /**
     * Encryp the data file and save it in AWS S3.
     *
     * @param string      $key    The file key.
     * @param mixed       $data   The destination directory or data bytes to be saved.
     * @param string|null $bucket The S3 bucket name.
     *
     * @throws Exception Unable to read the file.
     * @return false|\Aws\Result Return file data from AWS.
     */
    public function uploadEncrypted(string $key, mixed $data, string $bucket = null): false|\Aws\Result
    {
        if (is_file($data) === true) {
            $fileBytes = file_get_contents($data);
            if ($fileBytes !== false) {
                $data = $fileBytes;
            } else {
                return throw new Exception('Unable to read the file '.$data);
            }
        }

        return $this->upload($key, (new EncryptDecryptComponent)->encrypt($data, false), $bucket);

    }


    /**
     * Returns the S3Client class to call the API.
     *
     * @return S3Client
     */
    private function getS3Client(): S3Client
    {
        return new S3Client(
            [
                'profile'     => 'default',
                'version'     => 'latest',
                'region'      => 'ca-central-1',
                'credentials' => false,
            ]
        );

    }


}
