<?php

namespace tnm\soteria\behaviors;

use tnm\soteria\components\EncryptDecryptComponent;
use yii\base\Behavior;
use yii\base\Event;
use yii\base\InvalidConfigException;
use yii\db\BaseActiveRecord;

/**
 * Encrypts and decrypts the attributes when saving/updating an ActiveRecord.
 *
 * You can create an array called $encryptedAttributes in the model class to inform the attributes that will be
 * automatically encrypted.
 * You can also create an array called $decryptedAttributes in the model class to inform the attributes that will be
 * automatically decrypted. Or, you can use the EncryptDecrypt::decrypt method to decrypt the required attribute.
 */
class EncryptDecryptBehavior extends Behavior
{


    /**
     * {@inheritdoc}
     *
     * @return array
     */
    public function events(): array
    {
        return [
            BaseActiveRecord::EVENT_AFTER_FIND    => 'handleDecrypt',
            BaseActiveRecord::EVENT_BEFORE_INSERT => 'handleEncrypt',
            BaseActiveRecord::EVENT_BEFORE_UPDATE => 'handleEncrypt',
            BaseActiveRecord::EVENT_AFTER_INSERT  => 'handleDecrypt',
            BaseActiveRecord::EVENT_AFTER_UPDATE  => 'handleDecrypt',
        ];

    }


    /**
     * Decrypts all the listed attributes by the ActiveRecord in the behavior configuration.
     *
     * @param Event $event
     *
     * @return void
     */
    public function handleDecrypt(Event $event): void
    {
        foreach (($this->owner->encryptedAttributes ?? []) as $attribute) {
            if (in_array($attribute, ($this->owner->decryptedAttributes ?? [])) === true) {
                $this->decryptValue($attribute);
            }
        }

    }


    /**
     * Encrypts all the listed attributes by the ActiveRecord in the behavior configuration.
     *
     * @param Event $event
     *
     * @return void
     */
    public function handleEncrypt(Event $event): void
    {
        foreach (($this->owner->encryptedAttributes ?? []) as $attribute) {
            $this->encryptValue($attribute);
        }

    }


    /**
     * Decrypts the value of the given attribute.
     *
     * @param string $attribute The attribute name.
     *
     * @return void
     * @throws InvalidConfigException
     */
    private function decryptValue(string $attribute): void
    {
        $this->owner->$attribute = $this->getEncryptor()->decrypt($this->owner->$attribute);

    }


    /**
     * Encrypts the value of the given attribute.
     *
     * @param string $attribute The attribute name.
     *
     * @return void
     * @throws InvalidConfigException
     */
    private function encryptValue(string $attribute): void
    {
        $this->owner->$attribute = $this->getEncryptor()->encrypt($this->owner->$attribute);

    }


    /**
     * Returns the AWSEncryptDecrypt component used by the behavior.
     *
     * @return EncryptDecryptComponent
     * @throws InvalidConfigException
     */
    private function getEncryptor(): EncryptDecryptComponent
    {
        try {
            return \Yii::$app->encryptor;
        } catch (\Exception $exc) {
            throw new InvalidConfigException('EncryptDecrypt component not enabled. '.$exc->getMessage());
        }

    }


}
