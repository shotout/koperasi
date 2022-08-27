<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['register','login']]);
    }

    //register proccess
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password)
        ]);

        $token = auth('api')->attempt($request->only(['email', 'password']));
        
        $find = User::where('email', $request->email)->first();
        $find->email_verified_at = now();
        $find->save();


        return response()->json([
            'status' => 'Berhasil',
            'message' => 'Anggota Koperasi berhasil ditambahkan',
            'user' => $user,
            'authorisation' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);
    }

    //login proccess
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:6',
        ]);
        
        //check user
        $cek = User::where('email', $request->email)->first();
        if(!$cek){
            return response()->json([
                'status' => 'error',
                'message' => 'Anggota Tidak Terdaftar',
            ], 401);
        }


        $credentials = $request->only('email', 'password');
        $token = auth('api')->attempt($credentials);

        //token not found
        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'Unauthorized',
            ], 401);
        }


        $user = auth('api')->user();
        return response()->json([
            'status' => 'Login Anggota Koperasi Berhasil',
            'user' => $user,
            'authorisation' => [
                'token' => $token,
                'type' => 'bearer',
            ]
        ]);
    }


    public function logout()
    {
        auth('api')->logout();

        return response()->json([
            'message' => 'Berhasil Keluar'
        ]);
    }
}
