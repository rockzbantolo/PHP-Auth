<?php
namespace Mws\Core;

use Mws\Controllers\AuthController;


class Routes
{
    public static function initRoutes($router)
    {
        //  Authentication
        Routing::map($router, '/Auth', AuthController::class, function($r) {

            // Authentication
          $r->post('/Login', 'login')
            ->post('/Logout', 'logout')
            ->post('/Register', 'registerUser')
            ->post('/RefreshToken', 'refreshToken')

            // Users
            ->get('/Users', 'getAllUsers')
            ->get('/Users/{id}', 'getUserById')
            ->put('/Users/{id}', 'updateUserById')
            ->delete('/Users/{id}', 'deleteUserById')

            // Batch
            ->post('/Batch/Create', 'batchCreateUsers')
            ->put('/Batch/Update', 'batchUpdateUsers')
            ->delete('/Batch/Delete', 'batchDeleteUsers');
        });

    }
}
