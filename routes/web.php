<?php

use App\Http\Controllers\AuthenticationController;
use App\Http\Controllers\ClientsController;
use App\Http\Controllers\RegistrationController;
use Illuminate\Support\Facades\Route;

Route::post('login', [AuthenticationController::class, 'login'])
    ->name('login');

Route::post('register', [RegistrationController::class, 'register'])
    ->name('register');

Route::get('clients/index', [ClientsController::class, 'index'])
    ->name('clients.index');

Route::delete('clients/{user}/destroy', [ClientsController::class, 'delete'])
    ->name('clients.destroy');

Route::get('/', function () {
    return view('welcome');
});
