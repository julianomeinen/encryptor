<?php declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Juliano\Yii2EncryptorBehavior\classes\EncryptDecrypt;

final class Example extends TestCase
{
    public function testEncryptDecryptMethods(): void
    {
        $key = 'key';
        $text = 'text';
        $encrypted = (new EncryptDecrypt)->encrypt($text, $key);
        $decrypted = (new EncryptDecrypt)->decrypt($encrypted, $key);
        
        $this->assertNotSame(false, $encrypted);
        $this->assertNotSame(false, $decrypted);
        $this->assertNotSame($text, $encrypted);
        $this->assertSame($text, $decrypted);

    }
}