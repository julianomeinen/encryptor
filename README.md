Yii2 Encrytor Behavior

## Configuration

Ensure the following params are present in the app's params config:

```
'components' => [
    ...
    'encryptor' => [
        'class' => 'Juliano\Yii2EncryptorBehavior\components\EncryptDecryptComponent',
            'key' => 'secret_key_to_encrypt_and_decrypt'
    ],
]
```

## How to use

1. Add the behavior to your model or base class as in the following example:
```
/**
 * {@inheritdoc}
 *
 * @return void
 */
public function init(): void
{
    $this->attachBehavior('encryptDecrypt', \Juliano\Yii2EncryptorBehavior\behaviors\EncryptDecryptBehavior::class);
    parent::init();

}
```
2. Add the arrays ```$encryptedAttributes``` and ```$decryptedAttributes``` as variables in your model, as in the following example:
```
 /**
 * @var array $encryptedAttributes The attributes that will be automatically encrypted before being
 * saved in the DB.
 */
public array $encryptedAttributes = ['column_note'];

/**
 * @var array $decryptedAttributes The attributes that will be automatically decrypted after being
 * retrieved from the database.
 */
public array $decryptedAttributes = ['column_note'];
```
3. Save your model like usual.
```
$note = new Note();
$note->column_note = 'This text will be encrypted and decrypted automatically.';
$note->save();
```

### Extra Info

The model's array ```$decryptedAttributes``` is optional. You can decrypt a value manually using the ```\Juliano\Yii2EncryptorBehavior\components\EncryptDecryptComponent::decrypt($encrypted_value)``` method.



## How to use AWS with the Component

It can be used with AWS PHP-SDK to retrieve the secret key with AWS KMS using a cryptographic hash. Environment variables can be used to increase security and avoid hard-coded secrets.

```
'components' => [
    ...
    'encryptor' => [
        'class' => 'Juliano\Yii2EncryptorBehavior\components\EncryptDecryptComponent',
            'key' => \Juliano\Yii2EncryptorBehavior\classes\AWSEncryptDecrypt::class,
            'awsHashKey' => getenv('AWS_HASH_KEY'),
    ],
],
```

### AWS Credentials

AWS credentials for PHP-SDK cannot be hard-coded and must be provided according to the official documentation available at https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_configuration.html#credentials.
The order for attempting to login will be:
1. Load credentials from environment variables.
2. Load credentials from a credentials .ini file.
3. Load credentials from an IAM role.

### How to Upload Encrypted files to AWS S3

The method ```uploadEncrypted(string $key, mixed $data, string $bucket = null)``` can be used to encrypt and upload files to AWS S3. The file path or the bytes of the file can be passed as data.
```
use Juliano\Yii2EncryptorBehavior\classes\AWSS3;
        
$s3 = new AWSS3();

// File's bytes.
$bytes = file_get_contents('file-to-upload.txt');
$s3->uploadEncrypted('file-key-in-s3-bucket', $bytes);

// File's path.
$path = 'file-to-upload.txt';
$s3->uploadEncrypted('file-key-in-s3-bucket', $path);
```
### How to Download Decrypted files from AWS S3
The method ```downloadDecrypted(string $key, string $destination, string $bucket = null)``` can be used to download and decrypt files from AWS S3. The destination file path must be passed in order to save the decrypted file.
```
use Juliano\Yii2EncryptorBehavior\classes\AWSS3;

$s3 = new AWSS3();
$s3FileID = 'encrypted-text';
$destination = '/uploads/decrypted-text.txt';
$s3->downloadDecrypted($s3FileID, $destination);
```
### How to get the Decrypted data bytes from AWS S3
If you don't want to donwnload and save the file, and just want to get the bytes, the ```getDecryptedFile(string $key, string $bucket = null)``` method can be used.
```
use Juliano\Yii2EncryptorBehavior\classes\AWSS3;

$s3 = new AWSS3();
$s3FileID = 'encrypted-text';
$s3->getDecryptedFile($s3FileID);
```

### Extra Info

You can use the ```download(string $key, string $destinationDirectory, string $bucket = null)``` and ```upload(string $key, mixed $data, string $bucket = null)``` methods to download and upload without encrypting and decrypting the data.
