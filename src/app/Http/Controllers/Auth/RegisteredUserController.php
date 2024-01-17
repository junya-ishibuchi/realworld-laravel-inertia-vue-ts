<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Providers\RouteServiceProvider;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules;
use Inertia\Inertia;
use Inertia\Response;

class RegisteredUserController extends Controller
{
    /**
     * Display the registration view.
     */
    public function create(): Response
    {
        return Inertia::render('Auth/Register');
    }

    /**
     * Handle an incoming registration request.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(Request $request): RedirectResponse
    {
        $request->validate([
            'user.username' => 'required|string|max:255',
            'user.email' => 'required|string|lowercase|email|max:255|unique:users,email',
            'user.password' => ['required', Rules\Password::defaults()],
        ]);

        User::create([
            'name' => $request->input('user.username'),
            'email' => $request->input('user.email'),
            'password' => Hash::make($request->input('user.password')),
        ]);

        $token = auth()->attempt(['email' => $request->input('user.email'), 'password' => $request->input('user.password')]);

        return redirect(RouteServiceProvider::HOME)->withCookie(Cookie::make(
            'token',
            $token,
            config('jwt.refresh_ttl'),
            '/',
            null,
            request()->secure(),
            true));
    }
}
