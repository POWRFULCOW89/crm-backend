<?php

namespace Tests\Feature\App\Http\Controllers\RegisterController;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class RegisterTest extends TestCase
{
    use RefreshDatabase;

    public function test_show_errors_when_data_is_wrong()
    {
        $this->post(route('register'))
            ->assertInvalid();
    }

    public function test_it_creates_a_model_and_return_success()
    {
        $this->post(route('register'), [
            'name' => 'John Doe',
            'email' => 'test@test.com',
            'password' => 'password',
        ])
        ->assertSuccessful();

        $this->assertDatabaseHas('users', [
            'email' => 'test@test.com',
        ]);
    }
}
