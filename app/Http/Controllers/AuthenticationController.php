<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthenticationController extends Controller
{
    public function login(Request $request)
    {
        $data = $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string'
        ]);

        if(Auth::attempt($data)){
            return response('', 200);
        }

        return response([
            'message' => 'Invalid Credentials'
        ], 401);
    }
}
