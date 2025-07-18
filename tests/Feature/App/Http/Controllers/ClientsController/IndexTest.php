<?php

namespace Tests\Feature\App\Http\Controllers\ClientsController;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\Fluent\AssertableJson;
use Tests\TestCase;

class IndexTest extends TestCase
{
    use RefreshDatabase;

    public function test_it_shows_all_clients()
    {
        User::factory()
            ->count(5)
            ->create();

        $response = $this->get(route('clients.index'));

        $response->assertStatus(200)
            ->assertJson(fn (AssertableJson $json) =>
                $json->has('data', 5)
            );
    }

    public function test_it_does_not_show_private_data()
    {
        User::factory()
            ->count(5)
            ->create();

        $response = $this->get(route('clients.index'));

        $response->assertJson(fn (AssertableJson $json) =>
            $json->has('data.0', fn (AssertableJson $json) =>
                $json->missing('password')
                    ->etc()
            )
        );
    }

    public function test_data_is_complete()
    {
        User::factory()
            ->count(5)
            ->create();

        $response = $this->get(route('clients.index'));

        $response->assertStatus(200)
            ->assertJson(fn (AssertableJson $json) =>
                $json->has('data.0', fn (AssertableJson $json) =>
                    $json->hasAll(['id', 'email', 'avatar', 'name', 'created_at', 'last_login_at'])
                        ->etc()
                )
            );
    }

}
