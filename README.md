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

## Additional Options

It can be used with AWS PHP-SDK to retrieve the secret key with AWS KMS using a cryptographic hash:

```
'components' => [
    ...
    'encryptor' => [
        'class' => 'Juliano\Yii2EncryptorBehavior\components\EncryptDecryptComponent',
            'key' => AWSEncryptDecrypt::class,
            'awsHashKey' => getenv('AWS_HASH_KEY'),
    ],
],
```

AWS credentials for PHP-SDK cannot be hard-coded and must be provided according to the official documentation available at https://docs.aws.amazon.com/sdk-for-php/v3/developer-guide/guide_configuration.html#credentials.
The order for attempting to login will be:
1. Load credentials from environment variables.
2. Load credentials from a credentials .ini file.
3. Load credentials from an IAM role.