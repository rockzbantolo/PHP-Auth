<?php
namespace Svm\Core;

use Svm\Controllers\AuthCtrl;

class Routes
{
    public static function initRoutes($router)
    {
        //  Authentication
        Routing::map($router, '/Auth', AuthCtrl::class, function($r) {

          $r->post('/Login', 'login')
            ->post('/Logout', 'logout')
            ->post('/Register', 'registerUser')
            ->post('/Token/Refresh', 'refreshToken')
            ->post('/Otp/Request', 'requestOTP')
            ->post('/Otp/Verify', 'verifyOTP');

        });

        //  Users
        Routing::map($router, '/User', AuthCtrl::class, function($r) {

          $r->get('', 'getAllUsers')
            ->get('/{id}', 'getUserDetails')
            ->put('/{id}', 'updateUserDetails')
            ->delete('/{id}', 'deleteUserDetails');
        });

    }
}
