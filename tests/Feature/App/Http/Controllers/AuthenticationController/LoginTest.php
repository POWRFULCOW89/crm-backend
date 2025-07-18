<?php

namespace Tests\Feature\App\Http\Controllers\AuthenticationController;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class LoginTest extends TestCase
{
    use RefreshDatabase;

    public function test_login_show_errors_when_data_is_wrong(): void
    {
        $this->post(route('login'))
            ->assertInvalid(['email', 'password']);
    }

    public function test_login_works(): void
    {
        User::factory()->create([
            'email' => 'test@example.com',
            'password' => 'password',
        ]);

        $this->post(route('login'), [
            'email' => 'test@example.com',
            'password' => 'password',
        ])->assertSuccessful();
    }

    public function test_unauthorized_when_error(): void
    {
        User::factory()->create([
            'email' => 'test@example.com',
            'password' => 'password',
        ]);

        $this->post(route('login'), [
            'email' => 'test@example.com',
            'password' => 'incorrect-password',
        ])->assertUnauthorized();
    }
}
