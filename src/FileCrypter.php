<?php

namespace pimenvibritania\FileCrypter;

use Exception;
use Illuminate\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

/**
 * Class FileCrypter
 * @package pimenvibritania\FileCrypter
 */
class FileCrypter{
    protected const FILE_ENCRYPTION_BLOCKS = 255;
    /**
     * @var Repository|Application|mixed
     */
    private $key;

    public function __construct(){
        $this->key = config('file-encrypter.key');
    }

    protected function getFilePath($file)
    {
//        if ($this->isS3File()) {
//            return "s3://{$this->adapter->getBucket()}/{$file}";
//        }

        return Storage::disk('local')->path($file);
    }

    protected function openSourceFile($sourcePath)
    {
        $contextOpts = Str::startsWith($sourcePath, 's3://') ? ['s3' => ['seekable' => true]] : [];

        if (($fpIn = fopen($sourcePath, 'r', false, stream_context_create($contextOpts))) === false) {
            throw new Exception('Cannot open file for reading');
        }

        return $fpIn;
    }

    protected function openDestFile($destPath)
    {
        if (($fpOut = fopen($destPath, 'w')) === false) {
            throw new Exception('Cannot open file for writing');
        }

        return $fpOut;
    }

    public function encrypt($sourceFile, $destFile = null){

        $bf = new BlowfishEncrypter($this->key);

        if (is_null($destFile)) {
            $destFile = "{$sourceFile}.enc";
        }

        $sourcePath = $this->getFilePath($sourceFile);
        $destPath = $this->getFilePath($destFile);

        $fpIn = $this->openSourceFile($sourcePath);
        $fpOut = $this->openDestFile($destPath);

        $numberOfChunks = ceil(filesize($sourcePath) / (16 * self::FILE_ENCRYPTION_BLOCKS));

        $i = 0;

        while (! feof($fpIn)){
            $plaintext = fread($fpIn, 16 * self::FILE_ENCRYPTION_BLOCKS);

            $ciphertext = $bf->inputEncrypt($plaintext);

            if (strlen($plaintext) !== 16 * self::FILE_ENCRYPTION_BLOCKS
                && $i + 1 < $numberOfChunks
            ) {
                fseek($fpIn, 16 * self::FILE_ENCRYPTION_BLOCKS * $i);
                continue;
            }

            fwrite($fpOut, $ciphertext);

            $i++;
        }

        fclose($fpIn);
        fclose($fpOut);

        return true;
    }
}
