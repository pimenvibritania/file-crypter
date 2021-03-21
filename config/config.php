<?php

return [
    /*
     * The default key used for all file encryption / decryption
     * If no AES_KEY / SALT_KEY is found, then it will use your Laravel APP_KEY
     */
    'key' => env('AES_KEY', env('APP_KEY')),
    'salt' => env('SALT_KEY', env('APP_KEY')),

    /*
     * The cipher used for encryption.
     * Supported options are AES-128-CBC and AES-256-CBC and BF-EBC
     */
    'cipher-aes' => 'AES-256-CBC',
    /*
     * The Storage disk used by default to locate your files.
     */
    'disk' => 'local',


];
