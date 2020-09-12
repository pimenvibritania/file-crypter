<?php

namespace pimenvibritania\FileCrypter;

use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

class FileCrypter
{
    /**
     * The storage disk.
     *
     * @var string
     */
    protected $disk;

    /**
     * The encryption key.
     *
     * @var string
     */
    protected $key;
    protected $salt;

    /**
     * The algorithm used for encryption.
     *
     * @var string
     */
    protected $cipherAES;
    protected $chiperBF;

    /**
     * The storage adapter.
     *
     * @var string
     */
    protected $adapter;

    public function __construct()
    {
        $this->disk = config('file-crypter.disk');
        $this->key = config('file-crypter.key');
        $this->salt = config('file-crypter.salt');
        $this->cipherAES = config('file-crypter.cipher-aes');
        $this->cipherBF = config('file-crypter.cipher-bf');

    }



    /**
     * Set the disk where the files are located.
     *
     * @param  string  $disk
     * @return $this
     */
    public function disk($disk)
    {
        $this->disk = $disk;

        return $this;
    }

    /**
     * Set the encryption key.
     *
     * @param  string  $key
     * @return $this
     */
    public function key($key)
    {
        $this->key = $key;

        return $this;
    }

    /**
     * @return \Illuminate\Config\Repository|\Illuminate\Contracts\Foundation\Application|mixed
     */
    public function salt($salt)
    {
        $this->salt = $salt;

        return $this;
    }
    /**
     * Encrypt the passed file and saves the result in a new file with ".enc" as suffix.
     *
     * @param string $sourceFile Path to file that should be encrypted, relative to the storage disk specified
     * @param string $destFile   File name where the encryped file should be written to, relative to the storage disk specified
     * @return $this
     */
    public function encrypt($sourceFile, $destFile = null, $deleteSource = true)
    {
        $this->registerServices();

        if (is_null($destFile)) {
            $destFile = "{$sourceFile}.pimen";
        }

        $sourcePath = $this->getFilePath($sourceFile);
        $destPath = $this->getFilePath($destFile);

        // Create a new encrypter instance
        $encrypter = new FileEncrypter($this->key, $this->cipherAES, $this->cipherBF, $this->salt);

        // If encryption is successful, delete the source file
        if ($encrypter->encrypt($sourcePath, $destPath) && $deleteSource) {
            Storage::disk($this->disk)->delete($sourceFile);
        }

        return $this;
    }

    public function encryptCopy($sourceFile, $destFile = null)
    {
        return self::encrypt($sourceFile, $destFile, false);
    }

    /**
     * Dencrypt the passed file and saves the result in a new file, removing the
     * last 4 characters from file name.
     *
     * @param string $sourceFile Path to file that should be decrypted
     * @param string $destFile   File name where the decryped file should be written to.
     * @return $this
     */
    public function decrypt($sourceFile, $destFile = null, $deleteSource = true)
    {
        $this->registerServices();

        if (is_null($destFile)) {
            $destFile = Str::endsWith($sourceFile, '.pimen')
                        ? Str::replaceLast('.pimen', '', $sourceFile)
                        : $sourceFile.'.dec';
        }

        $sourcePath = $this->getFilePath($sourceFile);
        $destPath = $this->getFilePath($destFile);

        // Create a new encrypter instance
        $encrypter = new FileEncrypter($this->key, $this->cipherAES, $this->cipherBF, $this->salt);

        // If decryption is successful, delete the source file
        if ($encrypter->decrypt($sourcePath, $destPath) && $deleteSource) {
            Storage::disk($this->disk)->delete($sourceFile);
        }

        return $this;
    }

    public function decryptCopy($sourceFile, $destFile = null)
    {
        return self::decrypt($sourceFile, $destFile, false);
    }

    public function streamDecrypt($sourceFile)
    {
        $this->registerServices();

        $sourcePath = $this->getFilePath($sourceFile);

        // Create a new encrypter instance
        $encrypter = new FileEncrypter($this->key, $this->cipherAES, $this->cipherBF, $this->salt);

        return $encrypter->decrypt($sourcePath, 'php://output');
    }

    protected function getFilePath($file)
    {
        if ($this->isS3File()) {
            return "s3://{$this->adapter->getBucket()}/{$file}";
        }

        return Storage::disk($this->disk)->path($file);
    }

    protected function isS3File()
    {
        return $this->disk == 's3';
    }

    protected function setAdapter()
    {
        if ($this->adapter) {
            return;
        }

        $this->adapter = Storage::disk($this->disk)->getAdapter();
    }

    protected function registerServices()
    {
        $this->setAdapter();

        if ($this->isS3File()) {
            $client = $this->adapter->getClient();
            $client->registerStreamWrapper();
        }
    }
}
