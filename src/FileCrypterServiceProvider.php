<?php

namespace pimenvibritania\FileCrypter;

use Illuminate\Support\ServiceProvider;

class FileCrypterServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     */
    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/config.php' => config_path('file-crypter.php'),
            ], 'file-crypter-config');
        }
    }

    /**
     * Register the application services.
     */
    public function register()
    {
        // Automatically apply the package configuration
        $this->mergeConfigFrom(__DIR__.'/../config/config.php', 'file-crypter');

        // Register the main class to use with the facade
        $this->app->singleton('file-crypter', function () {
            return new FileCrypter;
        });
    }
}
