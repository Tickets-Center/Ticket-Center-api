<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Broadcast;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\NotificationController;
use App\Http\Controllers\{
    AccessController,
    AssignmentController,
    AuthController,
    InterventionController,
    MessageController,
    TicketController,
    UserController,
};

/*
|--------------------------------------------------------------------------
| Public
|--------------------------------------------------------------------------
*/

Route::get('/health', function (\Illuminate\Http\Request $request) {
    \Log::info('health hit', [
        'ip' => $request->ip(),
        'ua' => $request->userAgent(),
        'host' => $request->getHost(),
        'referer' => $request->headers->get('referer'),
    ]);
    return response()->json(['status' => 'ok']);
});

Route::post('/register',            [AuthController::class, 'register']);
Route::post('/verify-email',        [AuthController::class, 'verifyEmail']);
Route::post('/resend-verification', [AuthController::class, 'resendVerification']);
Route::post('/login',               [AuthController::class, 'login']);
Route::post('/forgot-password',     [AuthController::class, 'forgotPassword']);
Route::post('/reset-password',      [AuthController::class, 'resetPassword']);

Route::get('/login', fn() => response()->json(['message' => 'unauthenticated']))->name('login');

/*
|--------------------------------------------------------------------------
| Protected — all authenticated users
|--------------------------------------------------------------------------
*/
Route::middleware('auth:sanctum')->group(function () {

    Route::get('/me',      [AuthController::class, 'me']);
    Route::post('/logout', [AuthController::class, 'logout']);

    Route::get('/ticket',     [TicketController::class, 'index']);
    Route::post('/ticket',    [TicketController::class, 'create']);
    Route::get('/my-tickets', [TicketController::class, 'myTickets']);

    Route::get('/messages/{ticketId}',  [MessageController::class, 'index']);
    Route::post('/messages/{ticketId}', [MessageController::class, 'store']);

    Route::post('/broadcasting/auth', fn(Request $r) => Broadcast::auth($r));
});

/*
|--------------------------------------------------------------------------
| dispatcher / Admin
|--------------------------------------------------------------------------
*/
Route::middleware(['auth:sanctum', 'role:dispatcher|admin'])
    ->prefix('manager')
    ->group(function () {
        Route::get('/ticket',               [TicketController::class, 'all']);
        Route::get('/ticket/{id}',          [TicketController::class, 'show']);
        Route::put('/ticket/{id}',          [TicketController::class, 'update']);
        Route::put('/assignments/{id}',          [AssignmentController::class, 'update']);

        Route::get('/technicians',          [UserController::class, 'technicians']);
        Route::post('/ticket/{id}/assign',  [AssignmentController::class, 'assign']);
        Route::get('/ticket/{id}/progress', [TicketController::class, 'progress']);
    });

/*
|--------------------------------------------------------------------------
| Technician / Admin
|--------------------------------------------------------------------------
*/
Route::middleware(['auth:sanctum', 'role:technician|admin'])
    ->prefix('technician')
    ->group(function () {
        Route::get('/assignments',                 [AssignmentController::class, 'assigments']);
        Route::get('/assignment/{id}',             [AssignmentController::class, 'assigment']);
        Route::post('/appointment',                [InterventionController::class, 'makeAppointment']);
        Route::post('/{id}/intervention/complete', [InterventionController::class, 'complete']);
        Route::post('/{id}/intervention/update',   [InterventionController::class, 'update']);
    });

/*
|--------------------------------------------------------------------------
| notifications 
|--------------------------------------------------------------------------
*/

    

Route::middleware('auth:sanctum')->group(function () {
    Route::get('/notifications',              [NotificationController::class, 'index']);
    Route::get('/notifications/unread-count', [NotificationController::class, 'unreadCount']);
    Route::patch('/notifications/read-all',   [NotificationController::class, 'markAllRead']);
    Route::patch('/notifications/{id}/read',  [NotificationController::class, 'markRead']);
    Route::delete('/notifications',           [NotificationController::class, 'clearAll']);
});
/*
|--------------------------------------------------------------------------
| Admin only — user management
|--------------------------------------------------------------------------
*/

Route::middleware(['auth:sanctum', 'role:admin'])
    ->prefix('admin')
    ->group(function () {
        Route::get('/users',               [UserController::class, 'index']);
        Route::post('/users',              [UserController::class, 'store']);
        Route::delete('/users/{id}',       [UserController::class, 'destroy']);
        Route::patch('/users/{id}/role',   [UserController::class, 'assignRole']);

        // Roles -------------------------------------------------------------
        Route::get('/roles',               [UserController::class, 'roles']);
        Route::get('/roles/manage',        [AccessController::class, 'roleIndex']);
        Route::post('/roles',              [AccessController::class, 'roleStore']);
        Route::patch('/roles/{role}',      [AccessController::class, 'roleUpdate'])
            ->whereNumber('role');
        Route::delete('/roles/{role}',     [AccessController::class, 'roleDestroy'])
            ->whereNumber('role');

        // Permissions -------------------------------------------------------
        Route::get('/permissions',             [AccessController::class, 'permissionIndex']);
        Route::post('/permissions',            [AccessController::class, 'permissionStore']);
        Route::patch('/permissions/{permission}', [AccessController::class, 'permissionUpdate'])
            ->whereNumber('permission');
        Route::delete('/permissions/{permission}', [AccessController::class, 'permissionDestroy'])
            ->whereNumber('permission');
    });

