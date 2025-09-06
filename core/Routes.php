<?php
namespace Mws\Core;

use Mws\Controllers\AuthController;


class Routes
{
    public static function initRoutes($router)
    {
        //  Authentication
        Routing::map($router, '/Auth', AuthController::class, function($r) {

          $r->post('/Login', 'login')
            ->post('/Logout', 'logout')
            ->post('/Register', 'registerUser')
            ->post('/RefreshToken', 'refreshToken');

        });

        //  Users
        Routing::map($router, '/User', AuthController::class, function($r) {

          $r->get('', 'getAllUsers')
            ->get('/{id}', 'getUserById')
            ->put('/{id}', 'updateUserById')
            ->delete('/{id}', 'deleteUserById')

            // Batch
            ->post('/Batch/Create', 'batchCreateUsers')
            ->put('/Batch/Update', 'batchUpdateUsers')
            ->delete('/Batch/Delete', 'batchDeleteUsers');
        });

    }
}
