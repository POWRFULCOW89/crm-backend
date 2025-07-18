<?php

namespace Tests\Feature\App\Http\Controllers\ClientsController;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class DeleteTest extends TestCase
{
    use RefreshDatabase;

    public function test_it_show_404_if_not_found()
    {
        $this->delete(route('clients.destroy', ['user' => 1]))
            ->assertNotFound();
    }

    public function test_model_was_deleted()
    {
        $user = User::factory()->create();
        $this->delete(route('clients.destroy', $user));
        $this->assertModelMissing($user);
    }
}
