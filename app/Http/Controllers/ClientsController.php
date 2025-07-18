<?php

namespace App\Http\Controllers;

use App\Http\Resources\UserResource;
use App\Models\User;

class ClientsController extends Controller
{
    public function index()
    {
        return UserResource::collection(User::all());
    }

    public function delete(User $user)
    {
        $user->delete();
        return response(null, 204);
    }
}
