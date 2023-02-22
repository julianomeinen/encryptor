<?php

require_once '../vendor/autoload.php';

use Juliano\Yii2EncryptorBehavior\classes\EncryptDecrypt;

$key = 'key';
$text = 'text';
$encrypted = (new EncryptDecrypt)->encrypt($text, $key);
$decrypted = (new EncryptDecrypt)->decrypt($encrypted, $key);

echo $text . PHP_EOL;
echo $encrypted . PHP_EOL;
echo $decrypted . PHP_EOL;