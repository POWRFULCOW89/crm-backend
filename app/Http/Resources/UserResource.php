<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class UserResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'email' => $this->email,
            'name' => $this->name,
            'avatar' => $this->avatar,
            'role' => 'Admin',
            'status' => 'Active',
            'created_at' => $this->created_at,
            'last_login_at' => now(),
        ];
    }
}
