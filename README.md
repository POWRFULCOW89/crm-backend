# Autenticación y autorización en Laravel y Vue.js con JWT

Esta guía te llevará paso a paso para implementar JSON Web Tokens en tu aplicación Laravel. 
Esto te permitirá autenticar usuarios en tu frontend web y mobile posteriormente.

## ¿Qué realizaremos?

Al completar esta guía tendrás:
- Un sistema de autenticación basado en tokens JWT
- Capacidad de manejar usuarios entre diferentes dominios
- Renovación automática de tokens
- Logout seguro con invalidación de tokens
- Protección de rutas automática

---

## Consideraciones
- Todas las fachadas principales de Laravel están disponibles como funciones globales, por ejemplo: `Auth::user()` es equivalente a `auth()->user()`.
- Si te encuentras con problemas, asegúrate que
  - Los namespaces estén correctos
  - No hayas importado una clase incorrecta con el mismo nombre
  - Tu archivo `.env` esté correctamente configurado
  - Tu base de datos esté migrada y funcionando
- En cada paso se encuentran los fragmentos de código para completar la tarea por si te atrasas, pero intenta programar la funcionalidad del paso por tu cuenta antes de ver el código completo.
  - Si requieres consultar los fragmentos de código completos, ¡no copies y pegues! Escríbelo a mano para entender mejor cómo funciona y terminar de conocer el lenguaje y el framework.
- En caso de cualquier duda, los mentores estamos para ti 
---

## Prerrequisitos

- [x] Proyecto Laravel funcionando con autenticación básica por sesiones de la clase anterior
- [x] Proyecto Vue.js funcionando del [CRM](https://github.com/alexisurquijo/crm-frontend)

---

# PARTE 1: BACKEND

## Paso 1: Instalar el paquete de JWT

**Qué necesitas hacer**: Instalar la librería que maneja JWT en Laravel.

Existen muchas librerías, pero la más popular y mantenida es `tymon/jwt-auth`.

**Comandos a ejecutar**:
```bash
composer require tymon/jwt-auth
composer install
```

- [ ] Paquete JWT instalado exitosamente

---

## Paso 2: Configurar la librería

**Qué necesitas hacer**: Crear el archivo de configuración JWT y generar una clave secreta.

Al instalar un paquete de Laravel, muchas veces cuentan con configuraciones por defecto que no se pueden modificar.
Para editarlas, debes _publicar_ el archivo de configuración del paquete. Esto creará un archivo en tu proyecto que podrás modificar.

De la misma forma que ejecutamos `php artisan key:generate` para crear la clave de aplicación,
ahora debemos generar una clave secreta para JWT, dado que los tokens son firmados con una clave secreta.

**¡Asegúrate de contar con tu archivo `.env`!**

**Comandos a ejecutar**:
```bash
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
php artisan jwt:secret
```

- [ ] Configuración publicada
- [ ] Clave JWT generada en el archivo `.env`

---

## Paso 3: Modificar el modelo User

**Qué necesitas hacer**: Hacer que tu modelo User pueda trabajar con JWT.

**Archivo a modificar**: `app/Models/User.php`

**Cambios mínimos**:
1. Importar la interfaz JWT: `use Tymon\JWTAuth\Contracts\JWTSubject;`
2. Implementar la interfaz: `class User extends Authenticatable implements JWTSubject`
3. Añadir dos métodos obligatorios que exige la interfaz

No es necesario crear otro modelo para comenzar a usar JWT, simplemente debes modificar el modelo User que ya tienes. 
La interfaz de JWT exige un método para obtener el ID del usuario y otro para añadir información extra al token.

Con el método `getKey()` de Eloquent puedes obtener el ID del usuario y retornarlo en el método que requiere la interfaz.
El método de claims puede retornar un array vacío por ahora, ya que no necesitas añadir información extra al token.

<details>
<summary>💡 Código completo del modelo User</summary>

```php
<?php
// app/Models/User.php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Authenticatable implements JWTSubject
{
    use HasFactory, Notifiable;

    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims()
    {
        return [];
    }
}
```
</details>

- [ ] Interfaz JWTSubject implementada
- [ ] Métodos `getJWTIdentifier()` y `getJWTCustomClaims()` añadidos

---

## Paso 4: Configurar el guard de autenticación

**Qué necesitas hacer**: Decirle a Laravel que use JWT en lugar de sesiones.

**Archivo a modificar**: `config/auth.php`

**Cambio específico**: En el guard `api`, cambiar `'driver' => 'token'` por `'driver' => 'jwt'`

En Laravel podemos tener distintos tipos de autenticación, llamados "guards". Por lo regular sólo se usan dos:
*`web`* para la autenticación por sesiones y *`api`* para la autenticación por tokens.

Podemos usar uno u otro explícitamente cuando interactuemos con la fachada **Auth**. Por ejemplo, `auth('api')->user()` para obtener el usuario autenticado con el guard `api`.

Por defecto el guard usado es `web`, si no le indicas otro.

<details>
<summary>💡 Configuración completa de config/auth.php</summary>

```php
<?php
// config/auth.php

return [
    'defaults' => [
        'guard' => 'web',
        'passwords' => 'users',
    ],

    'guards' => [
        'web' => [
            'driver' => 'session',
            'provider' => 'users',
        ],
        'api' => [
            'driver' => 'jwt',
            'provider' => 'users',
        ],
    ],

    'providers' => [
        'users' => [
            'driver' => 'eloquent',
            'model' => App\Models\User::class,
        ],
    ],

    'passwords' => [
        'users' => [
            'provider' => 'users',
            'table' => 'password_resets',
            'expire' => 60,
            'throttle' => 60,
        ],
    ],

    'password_timeout' => 10800,
];
```

**¿Por qué este cambio?**
- Antes Laravel usaba sesiones para autenticar usuarios
- Ahora usará JWT que son tokens auto-contenidos y no necesitan base de datos
- El guard 'api' es el que usaremos para todas rutas en `/api/*`
</details>

- [ ] Guard `api` configurado para usar `jwt`

---

## Paso 5: Crear el controlador de autenticación

**Qué necesitas hacer**: Crear un controlador específico para manejar login, logout, registro y renovación de tokens.

**Comando para crear el controlador**:
```
php artisan make:controller AuthController
```

**Ubicación**: `app/Http/Controllers/AuthController.php`

Este nuevo controlador se parecerá mucho al que trabajamos en la clase anterior, pero ahora usaremos JWT en lugar de sesiones. Puedes trabajar sobre el anterior si quieres.

Los snippets importantes para usar JWT en lugar de sesiones son:
```php
JWTAuth::fromUser($user); // Genera un token JWT para el usuario

auth('api')->attempt($credentials); // Intenta autenticar al usuario con JWT

auth('api')->logout(); // Cierra sesión invalidando el token

auth('api')->refresh(); // Renueva el token JWT

auth('api')->user(); // Obtiene el usuario autenticado con JWT
```

¿Cómo los usarías para implementar los endpoints de crear usuario, iniciar sesión, cerrar sesión y obtener el usuario autenticado?

---

### 5.1 Estructura inicial del controlador

Al iniciar, tu controlador debería tener esta estructura base:

```php
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{

}
```

---

### 5.2 Método `register()`

**Objetivo**: Registrar un nuevo usuario, guardarlo en la base de datos y generar un token JWT.

Debería ser similar a lo que ya trabajaste, siendo la única diferencia que

1. Creas un JWT para el usuario recién creado con `JWTAuth::fromUser($user)`
2. Devuelves el token junto con los datos del usuario en la respuesta

<details>
<summary>💡 Configuración completa del método register</summary>

```php
public function register(Request $request)
{
    $validated = $request->validate([
        'name' => 'required|string|max:255',
        'email' => 'required|string|email|max:255|unique:users',
        'password' => 'required|string|min:8|confirmed',
    ]);

    $user = User::create([
        'name' => $validated['name'],
        'email' => $validated['email'],
        'password' => $validated['password'],
    ]);

    $token = JWTAuth::fromUser($user);

    return response()->json([
        'message' => 'User registered successfully',
        'user' => $user,
        'token' => $token
    ], 201);
}
```

</details>

---

### 5.3 Método `login()`

**Objetivo**: Validar credenciales y devolver un token si son correctas.

Debería ser similar a lo que ya trabajaste, pero ahora usaremos `auth('api')->attempt($credentials)` para autenticar 
al usuario con el guard de API, y recuerda devolverle su token.

<details>
<summary>💡 Configuración completa del método login</summary>

```php
public function login(Request $request)
{
    $validated = $request->validate([
        'email' => 'required|email|exists:users,email',
        'password' => 'required|string',
    ]);

    if (!$token = auth('api')->attempt($validated)) {
        return response()->json([
            'message' => 'Invalid credentials'
        ], 401);
    }

    return $this->respondWithToken($token);
}
```
</details>

---

### 5.4 Método `logout()`

**Objetivo**: Cerrar la sesión del usuario actual invalidando su token.

En este endpoint lo único que hay por hacer es llamar a `auth('api')->logout()` para invalidar el token actual.

<details>
<summary>💡 Configuración completa del método logout</summary>

```php
public function logout()
{
    auth('api')->logout();

    return response()->json([
        'message' => 'Successfully logged out'
    ]);
}
```
</details>

---


### 5.5 Método `refresh()`

**Objetivo**: Generar un nuevo token antes de que expire el actual.

En realidad este método es opcional, pero te permitirá que tu usuario no tenga que volver a iniciar sesión si su token 
está a punto de expirar.

Sólo debes usar el método **refresh()** de un guard con JWT para refrescar el token.

<details>
<summary>💡 Configuración completa del método refresh</summary>

```php
public function refresh()
{
    return $this->respondWithToken(auth('api')->refresh());
}

```
</details>

---

### 5.6 Método `me()`

**Objetivo**: Obtener la información del usuario autenticado.

Sólo es necesario devolver un JSON con el usuario en alguna forma. 
Recuerda que puedes acceder al usuario autenticado con `auth('api')->user()`.

```php
public function me()
{
    return response()->json([
        'user' => auth('api')->user()
    ]);
}
```
---

### 5.7 Método `respondWithToken()`

**Objetivo**: Dar formato estándar a la respuesta que contiene el token.

Este método no es requerido para usar JWT, pero es una buena práctica para mantener consistencia en las respuestas de tu API que manejan JWT's.

Estaría bueno tener una función que reciba un token y te devuelva una respuesta JSON con el token, tipo de token, tiempo de expiración y el usuario autenticado.

Esta respuesta podría sería compartida por todos los métodos que devuelven un token, como `login()`, `refresh()` y `register()`.

```php
protected function respondWithToken($token)
{
    return response()->json([
        'access_token' => $token,
        'token_type' => 'bearer',
        'expires_in' => auth('api')->factory()->getTTL() * 60,
        'user' => auth('api')->user()
    ]);
}
```

---

- [ ] Controlador `AuthController` creado
- [ ] Métodos agregados paso a paso


## Paso 6: Configurar las rutas de autenticación

**Qué necesitas hacer**: Crear las rutas que tu frontend va a usar para autenticarse.

**Archivo a modificar**: `routes/api.php`

**Rutas a añadir**:
- POST `/api/auth/register` - Registrar usuario
- POST `/api/auth/login` - Iniciar sesión
- POST `/api/auth/logout` - Cerrar sesión
- POST `/api/auth/refresh` - Renovar token
- GET `/api/auth/me` - Obtener usuario actual

La ruta de `/api/auth/me` debe estar protegida por el middleware `auth:api`, para que sólo usuarios autenticados puedan acceder a ella. 
Puedes hacer que una ruta use uno o más middlewares usando el método `middleware()` de la fachada *Route*.

<details>
<summary>💡 Archivo routes/api.php completo</summary>

```php
<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

Route::group(['prefix' => 'auth'], function () {
    Route::post('register', [AuthController::class, 'register']);
    Route::post('login', [AuthController::class, 'login']);
    Route::post('logout', [AuthController::class, 'logout']);
    Route::post('refresh', [AuthController::class, 'refresh']);
    Route::middleware('auth:api')->get('me', [AuthController::class, 'me']);
});

Route::middleware('auth:api')->group(function () {
    // Rutas protegidas
});
```

</details>

- [ ] Rutas de autenticación añadidas
- [ ] Grupo de rutas protegidas configurado

---

## Paso 7: Configurar CORS

**Qué necesitas hacer**: Permitir que tu frontend (en otro dominio) pueda hacer peticiones a tu API.

El proyecto frontend de CRM ya cuenta con el archivo `config/cors.php` configurado, pero aquí te dejo un ejemplo 
de cómo debería quedar en general.

**Archivo a modificar**: `config/cors.php`

<details>
<summary>💡 Configuración completa de CORS</summary>

```php
<?php
// config/cors.php

return [
    'paths' => ['api/*'], // Sólo rutas API
    'allowed_methods' => ['*'], // GET, POST, PUT, DELETE, etc.
    'allowed_origins' => [
        'http://localhost:3000',    // Vue en desarrollo
        'https://tu-sitio.com' // Producción
    ],
    'allowed_origins_patterns' => [],
    'allowed_headers' => ['*'],
    'exposed_headers' => [],
    'max_age' => 0,
    'supports_credentials' => false, // false para JWT (no cookies)
];
```

**¿Por qué necesitas CORS?**
- Tu Vue (ej: localhost:3000) y Laravel (ej: localhost:8000) están en dominios diferentes
- Los navegadores bloquean por seguridad estas peticiones "cross-origin"
- CORS le dice al navegador que permita estas peticiones específicas
</details>

- [ ] CORS configurado para permitir tu dominio de Vue
- [ ] `supports_credentials` establecido en `false`

---

## Paso 8: Configurar variables de entorno

**Qué necesitas hacer**: Personalizar la configuración JWT en tu archivo `.env`.

**Variables a añadir/modificar en `.env`**:
```bash
JWT_TTL=60
JWT_REFRESH_TTL=20160
```

Puedes omitir este paso por ahora, pero cuando vayas a lanzar tu aplicación tal vez quieras regresar a ajustar 
la configuración de JWT para mejorar la seguridad y el rendimiento.

Un JWT que dure más implica menos consultas a la base de datos, pero también puede ser menos seguro.
Si el token dura mucho tiempo, un atacante podría usarlo si lo roba de alguna forma.

A los usuarios les encanta que no los molestes obligándolos a iniciar sesión cada hora, para lo cual JWT soporta "ventanas de refresco".
Esto les permitirá renovar su token sin tener que volver a iniciar sesión, siempre y cuando el token original siga siendo válido.

<details>
<summary>💡 Explicación completa de variables JWT</summary>

```bash
# Tiempo de vida del token en minutos (60 = 1 hora)
JWT_TTL=60

# Tiempo para poder renovar el token en minutos (20160 = 2 semanas)
JWT_REFRESH_TTL=20160

# Algoritmo de encriptación (recomendado: HS256)
JWT_ALGO=HS256

# Habilitar blacklist para invalidar tokens en logout
JWT_BLACKLIST_ENABLED=true

# Período de gracia para blacklist en segundos
JWT_BLACKLIST_GRACE_PERIOD=0

# Margen de tiempo para validar tokens (en segundos)
JWT_LEEWAY=0
```

**¿Qué tiempo de vida usar (TTL)?:**
- **Desarrollo**: TTL más largo (240 minutos) para facilidad
- **Producción**: TTL corto (30-60 minutos) para seguridad
</details>

- [ ] Variables JWT añadidas al `.env`
- [ ] TTL configurado según tu preferencia

---

## Paso 9: Probar el backend

**Qué necesitas hacer**: Verificar que tu implementación de JWT funciona correctamente.

**Herramientas que puedes usar**:
- Postman
- Insomnia
- Thunder Client (extensión de VS Code)

**Pruebas básicas**:

1. **Registrar usuario** - `POST /api/auth/register`
2. **Iniciar sesión** - `POST /api/auth/login`
3. **Obtener perfil** - `GET /api/auth/me` (con token)

Cuando tu archivo de rutas crece demasiado, conviene organizarlo en grupos o archivos separados.
Para incluir un archivo de API en tus rutas, debes declararlo en `boostrap/app.php` de la siguiente forma:

```php
return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
```

Este paso es opcional pero es conveniente separar las rutas de API de las rutas web.

<details>
<summary>💡 Ejemplos completos de pruebas de API</summary>

### 1. Registro de usuario
**POST** `http://tu-sitio.com/api/auth/register`

**Headers:**
```
Content-Type: application/json
Accept: application/json
```

**Body (JSON):**
```json
{
    "name": "Juan Pérez",
    "email": "juan@ejemplo.com",
    "password": "password123",
    "password_confirmation": "password123"
}
```

**Respuesta esperada (201):**
```json
{
    "message": "User registered successfully",
    "user": {
        "id": 1,
        "name": "Juan Pérez",
        "email": "juan@ejemplo.com"
    },
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### 2. Iniciar sesión
**POST** `http://tu-sitio.com/api/auth/login`

**Body (JSON):**
```json
{
    "email": "juan@ejemplo.com",
    "password": "password123"
}
```

**Respuesta esperada (200):**
```json
{
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "token_type": "bearer",
    "expires_in": 3600,
    "user": {
        "id": 1,
        "name": "Juan Pérez",
        "email": "juan@ejemplo.com"
    }
}
```

### 3. Obtener perfil (autenticado)
**GET** `http://tu-sitio.com/api/auth/me`

**Headers:**
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Accept: application/json
```

**Respuesta esperada (200):**
```json
{
    "user": {
        "id": 1,
        "name": "Juan Pérez",
        "email": "juan@ejemplo.com",
        "email_verified_at": null,
        "created_at": "2024-01-15T10:30:00.000000Z",
        "updated_at": "2024-01-15T10:30:00.000000Z"
    }
}
```

**Si el token es inválido o no se envía:**
```json
{
    "message": "Unauthenticated."
}
```
</details>

- [ ] Registro funcionando correctamente
- [ ] Login devuelve token válido
- [ ] Ruta protegida funciona con token
- [ ] Ruta protegida bloquea sin token

---

## 💡 Importante

> - **Nunca commitees tus llaves secretas del entorno** (.env)
> - **Usa el middleware** `auth:api` en lugar de solo `auth`
> - **Los tokens no se invalidan** automáticamente al cerrar el navegador
> - **Siempre valida** los datos de entrada en tus controllers, NUNCA CONFÍES EN EL USUARIO

> **Comandos útiles:**
> ```bash
> # Limpiar cache de rutas después de cambios
> php artisan route:clear
> # Ver todas las rutas disponibles que la aplicación reconoce
> php artisan route:list
> ```

---

# PARTE 2: FRONTEND (Vue.js)

Estamos listos para hacer la conexión final al proyecto frontend de CRM. Ya están creadas las vistas 
respectivas de inicio de sesión, registro y dashboard.

En otra ventana de tu IDE, abre el proyecto `crm-frontend` e inícialo con:

```bash
npm i
npm run dev
```

El único cambio requerido en el lado del front es colocar la URL de tu backend en `LoginView.vue:25` y en
`RegisterView.vue:28`. Cuando inicies sesión o te registres, deberías ser redirigido a la vista principal del dashboard,
donde podrás ver una tabla con todos los usuarios registrados en tu base de datos.

¡Felicidades! Has implementado autenticación JWT en tu aplicación Laravel y 
ahora puedes autenticar usuarios desde tu frontend Vue.js.

Pero esto no se acaba aquí, aún hay mejoras que puedes implementar para hacer tu sistema más robusto y seguro.
Te planteo algunos retos para que sigas mejorando tu implementación:

## Líneas de mejora

### Complementar el modelo de usuario

**Qué necesitas hacer**: Añadir más campos al modelo de usuario para mejorar la experiencia.

**Archivo a modificar**: `app/Models/User.php`

El proyecto de frontend espera que el modelo ``User`` tenga algunas cosas más, como un _role_, un  _status_
o un _avatar_. ¿Cómo podrías añadir estos campos al modelo de usuario y a la base de datos?

<details>
<summary>💡 Ejemplo de campos adicionales</summary>

```php
// app/Models/User.php
class User extends Authenticatable implements JWTSubject
{
    // ...

    protected $fillable = [
        'name', 'email', 'password', 'role', 'status', 'avatar'
    ];

    // ...
}
```

No olvides crear las migraciones respectivas:
```bash
php artisan make:migration add_fields_to_users_table
```

y configurarlas:
```php
// database/migrations/xxxx_xx_xx_xxxxxx_add_fields_to_users_table.php
public function up()
{
    Schema::table('users', function (Blueprint $table) {
        $table->string('role')->default('user'); // Ejemplo: user, admin
        $table->string('status')->default('active'); // Ejemplo: active, inactive
        $table->string('avatar')->nullable(); // URL del avatar del usuario
    });
}

public function down()
{
    Schema::table('users', function (Blueprint $table) {
        $table->dropColumn(['role', 'status', 'avatar']);
    });
}
```

</details>

- [ ] Campos adicionales añadidos al modelo User
- [ ] Campos se muestran correctamente en el frontend


### Configurar Axios con interceptors

**Qué necesitas hacer**: Crear una configuración de Axios que añada automáticamente el token a todas las peticiones.

**Archivo a crear**: `src/services/api.js`

Axios es una librería para hacer peticiones HTTP que se integra fácilmente con Vue.js. `fetch` es fácil de usar
pero puede llegar a ser tedioso manejar los headers y errores de forma manual. Axios simplifica esto y permite configurar ``interceptors``.
Los interceptors se ejecutan automáticamente antes de cada petición (para añadir el token de acceso) 
y después de cada respuesta (para manejar errores).

<details>
<summary>💡 Código completo de api.js</summary>

```javascript
// src/services/api.js
import axios from 'axios'

// Crear instancia compartida de axios
const api = axios.create({
  baseURL: process.env.VUE_APP_API_URL || 'http://localhost:8000/api',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }
})

// Nos interesa añadir el token de acceso guardado en memoria automáticamente
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('jwt_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Si el token está vencido, intenta renovarlo. De lo contrario, vuelve a iniciar sesión
api.interceptors.response.use(
  (response) => {
    return response
  },
  async (error) => {
    const originalRequest = error.config

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      try {
        // Intentar renovar el token
        const response = await axios.post(`${api.defaults.baseURL}/auth/refresh`, {}, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('jwt_token')}`
          }
        })

        const newToken = response.data.access_token
        localStorage.setItem('jwt_token', newToken)
        
        // Reintentar la request original con el nuevo token
        originalRequest.headers.Authorization = `Bearer ${newToken}`
        return api(originalRequest)
      } catch (refreshError) {
        // Si falla el refresh, cerrar sesión
        localStorage.removeItem('jwt_token')
        localStorage.removeItem('user_data')
        
        // Redirigir al login
        window.location.href = '/login'
      }
    }

    return Promise.reject(error)
  }
)

export default api
```

**¿Qué hace este archivo?**
- **Interceptor de request**: Añade automáticamente `Authorization: Bearer TOKEN` a todas las peticiones
- **Interceptor de response**: Si recibe error 401 (no autorizado), intenta renovar el token automáticamente
- **Renovación automática**: Si el refresh funciona, reintenta la petición original
- **Logout automático**: Si el refresh falla, elimina tokens y redirige al login
</details>

- [ ] Archivo `src/services/api.js` creado
- [ ] Interceptors configurados para token automático

---

### Crear servicio de autenticación

**Qué necesitas hacer**: Crear una clase que maneje todas las operaciones de autenticación (login, logout, registro, etc.).

**Archivo a crear**: `src/services/auth.js`

**Funciones principales**: login, logout, register, getCurrentUser, isAuthenticated

Manejar la autenticación en el frontend puede ser tedioso si no se organiza bien. Si pudieras centralizar la funcionalidad de 
autenticación en un sólo archivo puede ser extremadamente fácil de refactorizar si algún día necesitas usar otro método de autenticación (hacer un inicio de sesión social, por ejemplo.)

<details>
<summary>💡 Código completo de auth.js</summary>

```javascript
// src/services/auth.js
import api from './api'
import router from '@/router'

class AuthService {
  constructor() {
    this.token = localStorage.getItem('jwt_token')
    this.user = JSON.parse(localStorage.getItem('user_data') || 'null')
  }

  async login(credentials) {
    try {
      const response = await api.post('/auth/login', credentials)
      const { access_token, user, expires_in } = response.data

      // Guardar token y datos del usuario
      localStorage.setItem('jwt_token', access_token)
      localStorage.setItem('user_data', JSON.stringify(user))
      
      // Calcular y guardar tiempo de expiración
      const expiresAt = Date.now() + (expires_in * 1000)
      localStorage.setItem('token_expires_at', expiresAt.toString())

      this.token = access_token
      this.user = user

      return { success: true, user, token: access_token }
    } catch (error) {
      console.error('Login error:', error.response?.data?.message)
      return { 
        success: false, 
        message: error.response?.data?.message || 'Error en el login'
      }
    }
  }

  async register(userData) {
    try {
      const response = await api.post('/auth/register', userData)
      const { token, user } = response.data

      localStorage.setItem('jwt_token', token)
      localStorage.setItem('user_data', JSON.stringify(user))

      this.token = token
      this.user = user

      return { success: true, user, token }
    } catch (error) {
      return { 
        success: false, 
        message: error.response?.data?.message || 'Error en el registro',
        errors: error.response?.data?.errors
      }
    }
  }

  async logout() {
    try {
      await api.post('/auth/logout')
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      localStorage.removeItem('jwt_token')
      localStorage.removeItem('user_data')
      localStorage.removeItem('token_expires_at')
      
      this.token = null
      this.user = null
      
      router.push('/login')
    }
  }

  async getCurrentUser() {
    try {
      const response = await api.get('/auth/me')
      const user = response.data.user
      
      localStorage.setItem('user_data', JSON.stringify(user))
      this.user = user
      
      return user
    } catch (error) {
      console.error('Get current user error:', error)
      this.logout()
      return null
    }
  }

  async refreshToken() {
    try {
      const response = await api.post('/auth/refresh')
      const { access_token, expires_in } = response.data

      localStorage.setItem('jwt_token', access_token)
      const expiresAt = Date.now() + (expires_in * 1000)
      localStorage.setItem('token_expires_at', expiresAt.toString())

      this.token = access_token
      return access_token
    } catch (error) {
      console.error('Refresh token error:', error)
      this.logout()
      throw error
    }
  }

  isAuthenticated() {
    return !!this.token && !!this.user
  }

  isTokenExpiringSoon() {
    const expiresAt = localStorage.getItem('token_expires_at')
    if (!expiresAt) return false
    
    const fiveMinutes = 5 * 60 * 1000 // 5 minutos en milisegundos
    return Date.now() + fiveMinutes > parseInt(expiresAt)
  }

  getUser() {
    return this.user
  }

  getToken() {
    return this.token
  }
}

export default new AuthService()
```

</details>

- [ ] Archivo `src/services/auth.js` creado
- [ ] Métodos de autenticación implementados

---

##
