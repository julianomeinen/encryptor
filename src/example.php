<?php

require_once '../vendor/autoload.php';

use Juliano\Yii2EncryptorBehavior\classes\EncryptDecrypt;
use Juliano\Yii2EncryptorBehavior\classes\AWSS3;

$key = 'key';
$text = 'text';
$encrypted = (new EncryptDecrypt)->encrypt($text, $key);
$decrypted = (new EncryptDecrypt)->decrypt($encrypted, $key);

echo $text . PHP_EOL;
echo $encrypted . PHP_EOL;
echo $decrypted . PHP_EOL;

// Set AWS S3 bucket at instance creation.
// You can also set the parameter 's3Bucket' in app's config.
$s3 = new AWSS3('s3-bucket-name');
        
// Download decrypted
$key = 'test-upload-encrypted';
$destination = 'uploads/test-download-decrypted.txt';
$s3->downloadDecrypted($key, $destination);

// Upload encrypted
$s3->uploadEncrypted('php7-text-test-upload-encrypted', 'uploads/php7-text-test-upload.txt');
